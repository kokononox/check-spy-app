"""Offline global candidate/transport plan. No network, installer or CASC writer."""
import json,os,re,shutil,sqlite3,hashlib
from pathlib import Path
from datetime import datetime,timezone
import common,indexes,metadata,manifest,staging
from encoding import EncodingTable,EncodingError,MAX_BYTES
from payload import MAX_ENCODED,MAX_DECODED
from cdn_catalog import matches,CatalogError
class FullPlanError(Exception):pass
INDEX_MAX=8*1024*1024
GROUP_MAX=128*1024*1024
LOOSE_MAX=128*1024*1024

def read_report(path):
 if not path.is_file() or path.stat().st_size>65536:raise FullPlanError('report_missing_or_oversized')
 return json.loads(path.read_text(encoding='utf-8-sig'))
def cached_spec(fields,name):
 keys=fields.get(name,[]);sizes=fields.get(name+'-size',[])
 if len(keys)!=2 or len(sizes)!=2 or not all(common.HEX.fullmatch(k) for k in keys):raise FullPlanError('unsupported_'+name+'_metadata_configuration')
 decoded,encoded=map(int,sizes)
 if not all(0<n<=MAX_BYTES for n in (decoded,encoded)):raise FullPlanError('metadata_size_limit')
 return {'ckey':keys[0].lower(),'ekey':keys[1].lower(),'decoded':decoded,'encoded':encoded}
def cached_metadata(stage,spec,label,out,cancel,notify,snapshots):
 cache=stage/'cache/tpr/wow/data'
 for path in [cache/(spec['ekey']+'.decoded'),cache/spec['ekey']]:
  if path.is_file():snapshots[path]=indexes.fingerprint(path)
 path,origin=metadata.metadata(stage,spec,label,out,cancel,notify)
 snapshots[path]=indexes.fingerprint(path);return path,origin

def create_candidates(db):
 db.execute('CREATE TABLE candidate(ekey BLOB PRIMARY KEY,bytes INTEGER NOT NULL,priority INTEGER NOT NULL,inventory_reason TEXT NOT NULL,ckey BLOB,decoded_size INTEGER,metadata_status TEXT NOT NULL DEFAULT "not_checked",transport_class TEXT) WITHOUT ROWID')
 db.execute('INSERT INTO candidate(ekey,bytes,priority,inventory_reason) SELECT t.ekey,t.bytes,t.priority,CASE WHEN EXISTS(SELECT 1 FROM local l WHERE l.prefix=substr(t.ekey,1,9)) THEN "prefix_size_mismatch" ELSE "no_observed_prefix" END FROM target t WHERE NOT EXISTS(SELECT 1 FROM local l WHERE l.prefix=substr(t.ekey,1,9) AND l.bytes=t.bytes)')
 db.execute('CREATE TABLE location(ekey BLOB,route TEXT,archive TEXT,offset INTEGER,bytes INTEGER,PRIMARY KEY(ekey,route,archive,offset)) WITHOUT ROWID')
 db.execute('CREATE TABLE staged_exact(ekey BLOB PRIMARY KEY,path TEXT,bytes INTEGER,verification_status TEXT,decoded_ckey_verified INTEGER) WITHOUT ROWID')
 db.execute('CREATE TABLE staged_decoded(ekey BLOB,path TEXT,decoded_bytes INTEGER,PRIMARY KEY(ekey,path)) WITHOUT ROWID');db.commit()

def map_candidates(db,encoding_path,cancel,notify):
 wanted={ek:n for ek,n in db.execute('SELECT ekey,bytes FROM candidate')};found={}
 if not wanted:return wanted
 with EncodingTable(encoding_path) as table:
  for ck,size,eks in table.c_records(cancel,notify):
   for ek in eks:
    if ek in wanted:
     if ek in found and found[ek]!=(ck,size):raise FullPlanError('ambiguous_target_content_mapping')
     found[ek]=(ck,size)
  sizes=table.e_sizes(set(wanted),cancel,notify)
 updates=[]
 for ek,n in wanted.items():
  ck,size=found.get(ek,(None,None));status='mapped' if ck is not None and sizes.get(ek)==n else ('target_encoding_size_conflict' if ck is not None else 'target_encoding_unmapped')
  updates.append((ck,size,status,ek))
 db.executemany('UPDATE candidate SET ckey=?,decoded_size=?,metadata_status=? WHERE ekey=?',updates);db.execute('CREATE INDEX candidate_ckey ON candidate(ckey)');db.commit();return wanted

def cached_catalog(db,stage,prior,wanted,cancel,notify,snapshots):
 stats={'network_access_attempted':False,'configured_archives':0,'valid_normal_indexes':0,'missing_normal_indexes':0,'invalid_normal_indexes':0,'oversized_normal_indexes':0,'group_index_present':False,'group_index_used':False,'group_index_validation_problem':None,'archive_catalog_complete':False,'loose_index_configured':False,'loose_index_valid':False,'loose_index_problem':None,'validated_index_records':0,'target_size_conflicts':0,'coverage_scope':'ONLY fresh prefix/size-unmatched candidates; target catalog is NOT online availability'}
 cache=stage/'cache/tpr/wow';key=prior.get('target_cdn_config','').lower()
 if not common.HEX.fullmatch(key):raise FullPlanError('invalid_pinned_cdn_config_key')
 cfg=cache/'config'/key
 # The v0.2 cache is authoritative; use no unverified or guessed config/network fallback.
 if not cfg.is_file():stats['catalog_configuration_problem']='pinned_cdn_config_not_cached';return stats,[]
 before=indexes.fingerprint(cfg)
 if before[0]>4*1024*1024:raise FullPlanError('cdn_config_oversized')
 raw=cfg.read_bytes()
 if hashlib.md5(raw).hexdigest()!=key:raise FullPlanError('pinned_cdn_config_checksum_mismatch')
 if indexes.fingerprint(cfg)!=before:raise FullPlanError('source_changed')
 snapshots[cfg]=before;fields=metadata.fields(raw)
 if 'builds' in fields and prior['target_build_config'] not in fields['builds']:raise FullPlanError('cdn_config_target_build_conflict')
 archives=fields.get('archives',[])
 if not 0<len(archives)<=10000 or len(set(archives))!=len(archives) or not all(common.HEX.fullmatch(a) and a==a.lower() for a in archives):raise FullPlanError('invalid_cdn_archive_list')
 stats['configured_archives']=len(archives);expected_paths=[cache/'data'/(a+'.index') for a in archives]
 initial_presence=[p.is_file() for p in expected_paths]
 def consume(path,key,kind,limit,archive_list=None):
  old=indexes.fingerprint(path)
  if old[0]>limit:raise CatalogError('index_file_size_limit')
  data=path.read_bytes();records,proof=matches(data,key,wanted,kind,archive_list,cancel)
  if indexes.fingerprint(path)!=old:raise FullPlanError('cached_index_changed')
  snapshots[path]=old
  db.executemany('INSERT OR IGNORE INTO location VALUES (?,?,?,?,?)',records);db.commit()
  stats['validated_index_records']+=proof['index_records'];stats['target_size_conflicts']+=proof['target_size_conflicts']
 group=fields.get('archive-group',[])
 if len(group)==1 and common.HEX.fullmatch(group[0]):
  gp=cache/'data'/(group[0]+'.index');stats['group_index_present']=gp.is_file()
  if gp.is_file():
   notify('Verifying existing target group index locally…')
   try:consume(gp,group[0],'group',GROUP_MAX,archives);stats['group_index_used']=True;stats['archive_catalog_complete']=True
   except CatalogError as exc:
    if str(exc)=='cancelled':raise FullPlanError('cancelled')
    stats['group_index_validation_problem']=str(exc)
   except OSError:stats['group_index_validation_problem']='index_io_error'
 if not stats['group_index_used']:
  for i,(archive,path) in enumerate(zip(archives,expected_paths)):
   if cancel.is_set():raise FullPlanError('cancelled')
   notify('Verifying cached archive index '+str(i+1)+' / '+str(len(archives)))
   if not path.is_file():stats['missing_normal_indexes']+=1;continue
   try:consume(path,archive,'archive',INDEX_MAX);stats['valid_normal_indexes']+=1
   except CatalogError as exc:
    if str(exc)=='cancelled':raise FullPlanError('cancelled')
    if str(exc)=='index_file_size_limit':stats['oversized_normal_indexes']+=1
    else:stats['invalid_normal_indexes']+=1
   except OSError:stats['invalid_normal_indexes']+=1
  stats['archive_catalog_complete']=stats['valid_normal_indexes']==len(archives)
 loose=fields.get('file-index',[])
 if len(loose)==1 and common.HEX.fullmatch(loose[0]):
  stats['loose_index_configured']=True;lp=cache/'data'/(loose[0]+'.index');expected_paths.append(lp);initial_presence.append(lp.is_file())
  if not lp.is_file():stats['loose_index_problem']='loose_index_not_cached'
  else:
   try:consume(lp,loose[0],'loose',LOOSE_MAX);stats['loose_index_valid']=True
   except CatalogError as exc:
    if str(exc)=='cancelled':raise FullPlanError('cancelled')
    stats['loose_index_problem']=str(exc)
   except OSError:stats['loose_index_problem']='index_io_error'
 if stats['group_index_present']:
  expected_paths.append(gp);initial_presence.append(True)
 presence=list(zip(expected_paths,initial_presence))
 return stats,presence

def classify(db):
 db.execute('UPDATE candidate SET transport_class=CASE WHEN metadata_status!="mapped" THEN "metadata_unresolved" WHEN EXISTS(SELECT 1 FROM staged_exact s WHERE s.ekey=candidate.ekey) THEN "exact_encoded_copy_verified_in_staging" WHEN EXISTS(SELECT 1 FROM location l WHERE l.ekey=candidate.ekey AND l.route="archive_range") THEN "archive_range_location_known" WHEN EXISTS(SELECT 1 FROM location l WHERE l.ekey=candidate.ekey AND l.route="advertised_direct") THEN "advertised_direct_only" ELSE "transport_location_unresolved" END');db.commit()
 summary={k:{'target_objects':n,'whole_encoded_bytes':b} for k,n,b in db.execute('SELECT transport_class,count(*),coalesce(sum(bytes),0) FROM candidate GROUP BY transport_class')}
 for name in ['metadata_unresolved','exact_encoded_copy_verified_in_staging','archive_range_location_known','advertised_direct_only','transport_location_unresolved']:summary.setdefault(name,{'target_objects':0,'whole_encoded_bytes':0})
 count,total=db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM candidate').fetchone()
 if sum(v['target_objects'] for v in summary.values())!=count or sum(v['whole_encoded_bytes'] for v in summary.values())!=total:raise FullPlanError('class_totals_do_not_reconcile')
 # Independent joins verify each retained exact encoded staged representation.
 verified=db.execute('SELECT count(*),coalesce(sum(c.bytes),0) FROM candidate c INNER JOIN staged_exact s ON s.ekey=c.ekey WHERE c.metadata_status="mapped"').fetchone()
 if tuple(verified)!=(summary['exact_encoded_copy_verified_in_staging']['target_objects'],summary['exact_encoded_copy_verified_in_staging']['whole_encoded_bytes']):raise FullPlanError('staged_independent_join_mismatch')
 remaining_count=count-verified[0];remaining_bytes=total-verified[1]
 full,opaque=db.execute('SELECT coalesce(sum(decoded_ckey_verified),0),coalesce(sum(CASE WHEN decoded_ckey_verified=0 THEN 1 ELSE 0 END),0) FROM staged_exact').fetchone()
 decoded_only=db.execute('SELECT count(DISTINCT ekey) FROM staged_decoded').fetchone()[0]
 limits=db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM candidate WHERE metadata_status="mapped" AND (bytes>? OR decoded_size>?)',(MAX_ENCODED,MAX_DECODED)).fetchone()
 # Independent priority aggregation has same candidate totals; priorities are not playable stages.
 priorities=[{'manifest_priority':p,'target_objects':n,'whole_encoded_bytes':b} for p,n,b in db.execute('SELECT priority,count(*),sum(bytes) FROM candidate GROUP BY priority ORDER BY priority')]
 if sum(r['target_objects'] for r in priorities)!=count or sum(r['whole_encoded_bytes'] for r in priorities)!=total:raise FullPlanError('priority_totals_do_not_reconcile')
 return {'candidate_objects_before_staging':count,'candidate_whole_encoded_bytes_before_staging':total,'transport_classes':summary,'candidate_objects_without_verified_exact_staged_copy':remaining_count,'candidate_whole_encoded_bytes_without_verified_exact_staged_copy':remaining_bytes,'staged_exact_copies_with_decoded_ckey_verified':full,'staged_exact_copies_encoded_integrity_only':opaque,'decoded_only_staging_matches_not_subtracted':decoded_only,'objects_exceeding_current_payload_verifier_limits':limits[0],'associated_bytes_exceeding_verifier_limits':limits[1],'priority_breakdown_of_candidates':priorities,'independent_class_and_priority_reconciliation_passed':True}

def run(report_path,build_info,cancel,notify):
 rp=Path(report_path).resolve();report=read_report(rp)
 if report.get('tool')!='WoW Retail EU Small Archive Batch 0.9' or report.get('product')!='wow' or report.get('region')!='eu' or report.get('status') not in ('batch_completed','batch_completed_with_unresolved_locations','batch_stopped_after_sample_failure','batch_stopped','batch_cancelled','batch_download_declined','batch_prepared_not_downloaded','no_located_samples_within_lookup_budget','preparation_stopped','cancelled'):raise FullPlanError('select_original_v09_batch_report')
 stage=rp.parent.parent;prior_path=stage/'Retail-Staging-to-share.json';prior=read_report(prior_path);local=common.local_info(build_info);installation=local['installation']
 if local['version']!=report.get('local_version'):raise FullPlanError('installed_version_changed_refresh_sources')
 if prior.get('status')!='sample_downloaded_and_content_verified' or prior.get('target_version')!=report.get('target_version'):raise FullPlanError('pinned_reports_disagree')
 if stage==installation or stage.is_relative_to(installation) or installation.is_relative_to(stage):raise FullPlanError('staging_must_be_outside_game')
 if shutil.disk_usage(stage).free<2*1024**3:raise FullPlanError('at_least_2GiB_free_staging_required')
 cfg=stage/'build.config';snapshots={p:indexes.fingerprint(p) for p in [rp,prior_path,Path(build_info).resolve(),cfg]}
 raw=cfg.read_bytes()
 if len(raw)>4*1024**2 or common.md5(raw)!=prior['target_build_config'].lower():raise FullPlanError('target_build_config_hash_mismatch')
 fields=metadata.fields(raw)
 if fields.get('build-uid')!=['wow'] or not fields.get('build-name',[''])[0].startswith('WOW-'+report['target_version'].split('.')[-1]):raise FullPlanError('target_build_identity_mismatch')
 rows=common.rows(Path(build_info).read_text(encoding='utf-8-sig'));tags=common.one([r for r in rows if r.get('Product')=='wow' and r.get('Active')=='1' and r.get('Branch')=='eu'])['Tags'];known=['deDE','enUS','esES','esMX','frFR','itIT','koKR','ptBR','ruRU','zhCN','zhTW'];locales=[l for l in known if re.search(r'(?<![A-Za-z])'+l+r'(?![A-Za-z])',tags)]
 if not locales:raise FullPlanError('installed_locale_unknown_no_default_guessed')
 out=stage/('Full-Plan-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir()
 notify('Verifying cached target download manifest; OFFLINE.')
 dl,dl_origin=cached_metadata(stage,cached_spec(fields,'download'),'download',out,cancel,notify,snapshots)
 notify('Verifying cached target Encoding metadata; OFFLINE.')
 ep,ep_origin=cached_metadata(stage,cached_spec(fields,'encoding'),'target',out,cancel,notify,snapshots)
 data=dl.read_bytes();layout=manifest.manifest_layout(data,locales);db=indexes.open_db(out/'full-plan-private.sqlite');db.set_progress_handler(lambda:1 if cancel.is_set() else 0,10000)
 try:
  filtered=manifest.import_target(db,data,layout,cancel,notify);del data
  notify('Scanning fresh local journal references; payloads are NOT validated by a prefix match.')
  coverage,local_snaps,local_archives,files,folder=indexes.import_local(db,installation,cancel,notify)
  inventory=manifest.aggregate(db);create_candidates(db)
  notify('Binding candidate target EKeys to verified target Encoding metadata…')
  wanted=map_candidates(db,ep,cancel,notify)
  notify('Reading and validating cached CDN indexes; NO network.')
  catalog,presence=cached_catalog(db,stage,prior,wanted,cancel,notify,snapshots)
  notify('Reverifying existing target representations in staging; NO new game assets saved.')
  staged_stats,stage_snaps,stage_files=staging.scan(db,stage,cancel,notify);snapshots.update(stage_snaps)
  summary=classify(db)
  if summary['candidate_objects_before_staging']!=inventory['no_observed_prefix_match']+inventory['prefix_with_size_mismatch']:raise FullPlanError('global_candidate_count_mismatch')
  if summary['candidate_whole_encoded_bytes_before_staging']!=inventory['no_prefix_match_encoded_bytes']+inventory['size_mismatch_encoded_bytes']:raise FullPlanError('global_candidate_bytes_mismatch')
  indexes.stable(local_snaps,local_archives,files,folder)
  if any(indexes.fingerprint(p)!=old for p,old in snapshots.items()):raise FullPlanError('source_changed_during_plan')
  if any(p.is_file()!=existed for p,existed in presence):raise FullPlanError('cached_index_set_changed')
  if staging.discover(stage)!=stage_files:raise FullPlanError('staged_asset_set_changed')
  if cancel.is_set():raise FullPlanError('cancelled')
  local_partial=bool(coverage['uncovered_buckets'] or coverage['journal_problems'] or coverage['invalid_or_unavailable_archive_references'])
  staged_partial=bool(staged_stats['scan_limit_reached'] or staged_stats['oversized_files_not_checked'] or staged_stats['unreadable_files'] or staged_stats['outside_stage_files_skipped'])
  unresolved=summary['transport_classes']['metadata_unresolved']['target_objects']+summary['transport_classes']['transport_location_unresolved']['target_objects']
  partial=local_partial or not catalog['archive_catalog_complete'] or (catalog['loose_index_configured'] and not catalog['loose_index_valid']) or staged_partial or bool(unresolved) or bool(catalog['target_size_conflicts'])
  result={'tool':'WoW Retail EU Offline Global Candidate Plan 0.10','status':'global_candidate_plan_partial_coverage' if partial else 'global_candidate_plan_completed','checked_at_utc':datetime.now(timezone.utc).isoformat(),'product':'wow','region':'eu','platform':'Windows x64','local_version':local['version'],'target_version':report['target_version'],'target_pinned_latest_online_not_checked':True,'locales':locales,'optional_tags_included':layout['optional_tags_included'],'all_manifest_priorities_included':True,'manifest_all_records':layout['count'],'filtered_manifest_records':filtered,'target_download_manifest_hash_verified':True,'target_encoding_metadata_hash_verified':True,'download_manifest_origin':dl_origin,'target_encoding_origin':ep_origin,'inventory':inventory,'fresh_local_index_coverage':coverage,'catalog_coverage':catalog,'staging_scan':staged_stats,'plan':summary,'local_payloads_for_prefix_size_matches_verified':False,'active_journals_resolved':False,'local_journal_checksums_validated':False,'network_access_attempted':False,'game_downloads_attempted':False,'installed_files_changed':False,'decoded_game_assets_saved':False,'game_assets_executed':False,'binary_patch_size_computed':False,'minimal_playable_selection_computed':False,'full_update_engine_implemented':False,'limitations':['All selected target objects are counted, but detailed transport/staging analysis is ONLY fresh prefix+size-unmatched objects; local candidates remain payload-unverified.','A prefix+size journal candidate is NOT proof of complete/safe content, and no observed prefix is NOT proof of absence. Historical journal generations, not shmem-resolved active generation, are considered.','All byte totals are whole encoded OBJECT sums; not a required download, binary patch, compressed bundle, minimal playable size or guaranteed saved bandwidth.','Only fully EKey/chunk-verified exact TARGET encoded copies already in staging are subtracted from the transfer-candidate sum. Opaque target content may remain decoded-CKey unknown.','Decoded-only staged content is observed separately and NOT subtracted: exact target re-encoding/compatibility is not implemented.','Cached archive indexes validate locations, not current HTTP availability. A validated loose-file entry advertises a direct object but HTTP access is untested; no index download/online fallback.','Missing/invalid/unsupported cache indexes, metadata mappings and staging size/scan limits create coverage gaps, not proof of global absence/corruption.','No new game data files, installation/CASC writer, patch chains or rollback. Pinned target is NOT checked for latest version online.','Private SQLite contains identifiers/paths; keep it LOCAL. The share JSON contains no private paths, accounts, tokens or captured payloads.'],'sources':['https://wowdev.wiki/TACT','https://wowdev.wiki/CASC','https://wowdev.wiki/BLTE']}
  (out/'Retail-Full-Plan-to-share.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8');return result,out
 except sqlite3.OperationalError:
  if cancel.is_set():raise FullPlanError('cancelled')
  raise
 finally:db.close()
