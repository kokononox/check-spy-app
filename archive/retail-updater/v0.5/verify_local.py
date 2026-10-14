import json,os,re,shutil,sqlite3
from datetime import datetime,timezone
from pathlib import Path
import common as c,indexes as ix,metadata as meta
from encoding import EncodingTable,EncodingError
from payload import verify,PayloadError,MAX_ENCODED,MAX_DECODED
class VerifyError(Exception):pass

def read_json(path):
 if path.stat().st_size>65536:raise VerifyError('Report exceeds size limit')
 return json.loads(path.read_text(encoding='utf-8-sig'))

def source_candidates(path,report):
 if not path.is_file():raise VerifyError('Keep content-private.sqlite beside the ORIGINAL v0.4 report; do not upload it')
 before=ix.fingerprint(path);db=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True);db.execute('PRAGMA query_only=ON')
 try:
  expected=['target_ekey','ckey','alternate_ekey','status','target_encoded_bytes']
  if [r[1] for r in db.execute('PRAGMA table_info(content_comparison)')]!=expected:raise VerifyError('Unexpected content database schema')
  rows=db.execute('SELECT target_ekey,ckey,alternate_ekey,target_encoded_bytes FROM content_comparison WHERE status=?',('alternate_encoding_same_content_candidate',)).fetchall()
  summary=report['summary']['alternate_encoding_same_content_candidate']
  if len(rows)!=summary['target_objects'] or sum(r[3] for r in rows)!=summary['target_whole_encoded_bytes']:raise VerifyError('Report/private database do not reconcile')
  if any(not all(isinstance(k,bytes) and len(k)==16 for k in row[:3]) or row[3]<=0 for row in rows):raise VerifyError('Invalid candidate identifiers')
  return rows,before
 finally:db.close()

def scan_locations(installation,prefixes,cancel,notify):
 folder=installation/'Data/data';files=sorted(folder.glob('*.idx'))
 if not files or len(files)>1024:raise VerifyError('Unsupported local journal layout')
 snapshots={};archives={};locations={};buckets=set();problems=[];records=0;invalid=0
 for i,path in enumerate(files):
  if cancel.is_set():raise VerifyError('Cancelled')
  notify('Reading local journal '+str(i+1)+' / '+str(len(files)))
  m=re.fullmatch(r'([0-9a-fA-F]{2})[0-9a-fA-F]{8}\.idx',path.name,re.I)
  if not m or int(m[1],16)>15:problems.append('unsupported_filename');continue
  before=ix.fingerprint(path)
  if before[0]>128*1024*1024:problems.append('oversized_journal');continue
  data=path.read_bytes()
  if before!=ix.fingerprint(path):raise VerifyError('Local journal changed during read')
  snapshots[path]=before
  try:
   for key,archive,offset,total in ix.parse_idx(data,int(m[1],16)):
    records+=1
    if records%50000==0 and cancel.is_set():raise VerifyError('Cancelled')
    if key not in prefixes:continue
    if archive not in archives:
     ap=folder/('data.'+str(archive).zfill(3))
     try:archives[archive]=(ap,ix.fingerprint(ap))
     except OSError:archives[archive]=(ap,None)
    ap,af=archives[archive]
    if total<30 or af is None or offset+total>af[0]:invalid+=1;continue
    value=(ap,offset+30,total-30)
    pool=locations.setdefault(key,[])
    if value not in pool:
     if len(pool)>=64:problems.append('too_many_ambiguous_locations');continue
     pool.append(value)
   buckets.add(int(m[1],16))
  except ix.PlanError:problems.append('unsupported_or_malformed_journal')
 coverage={'files':len(files),'valid_buckets':sorted(buckets),'uncovered_buckets':[i for i in range(16) if i not in buckets],
 'journal_problems':problems,'index_records_examined':records,'invalid_needed_archive_references':invalid,
 'bounds_check_scope':'candidate alternative encodings only, not all archive records'}
 return locations,coverage,snapshots,archives,files,folder

def maps(rows,target_path,local_path,cancel,notify):
 wanted={r[0] for r in rows};needed={r[1] for r in rows};alts={r[2] for r in rows};target_map={};local_map={}
 with EncodingTable(target_path) as table:
  for ck,size,eks in table.c_records(cancel,notify):
   for ek in eks:
    if ek in wanted:
     if ek in target_map and target_map[ek][:2]!=(ck,size):raise VerifyError('Ambiguous target content mapping')
     target_map[ek]=(ck,size,set(eks))
  target_sizes=table.e_sizes(wanted,cancel,notify)
 with EncodingTable(local_path) as table:
  for ck,size,eks in table.c_records(cancel,notify):
   if ck in needed:local_map[ck]=(size,set(eks))
  alternate_sizes=table.e_sizes(alts,cancel,notify)
 result={}
 for ek,ck,alt,size in rows:
  t=target_map.get(ek);l=local_map.get(ck);es=alternate_sizes.get(alt)
  if t is None or l is None or t[0]!=ck or t[1]!=l[0] or alt not in l[1] or es is None or target_sizes.get(ek)!=size:
   result[ek]=None
  else:result[ek]={'ckey':ck,'alternate':alt,'decoded_size':t[1],'encoded_size':es,'target_advertises_alternate':alt in t[2]}
 return result

def check_one(spec,locations,cancel):
 if not 0<=spec['encoded_size']<=MAX_ENCODED or not 0<=spec['decoded_size']<=MAX_DECODED:return {'status':'not_checked_size_limit','reason':'size_limit','encoded_integrity_verified':False,'decoded_ckey_verified':False}
 candidates=[(p,off,size) for p,off,size in locations.get(spec['alternate'][:9],[]) if size==spec['encoded_size']]
 if not candidates:return {'status':'location_not_found','reason':'no_current_bounded_index_location','encoded_integrity_verified':False,'decoded_ckey_verified':False}
 best=None;last_reason='no_valid_payload';io_errors=0
 for path,offset,size in candidates:
  if cancel.is_set():raise VerifyError('Cancelled')
  try:
   before=ix.fingerprint(path)
   with path.open('rb') as src:
    src.seek(offset);result=verify(src,size,spec['decoded_size'],spec['ckey'],spec['alternate'],cancel)
   if ix.fingerprint(path)!=before:raise VerifyError('Archive changed during payload validation')
   if result['status']=='content_verified':return result
   best=result
  except PayloadError as exc:
   if exc.kind=='cancelled':raise VerifyError('Cancelled')
   last_reason=exc.reason
  except OSError:io_errors+=1;last_reason='archive_io_error'
 if best is not None:return best
 return {'status':'read_failed' if io_errors==len(candidates) else 'validation_failed','reason':last_reason,'encoded_integrity_verified':False,'decoded_ckey_verified':False}

def run(report_path,build_info,cancel,notify):
 report_path=Path(report_path).resolve();content=report_path.parent;stage=content.parent;report=read_json(report_path)
 if report.get('product')!='wow' or report.get('region')!='eu' or report.get('status') not in ('candidate_content_comparison_completed','candidate_content_comparison_partial'):raise VerifyError('Select the ORIGINAL v0.4 content report')
 previous_path=stage/'Retail-Staging-to-share.json';previous=read_json(previous_path)
 if previous.get('target_version')!=report['target_version'] or previous.get('status')!='sample_downloaded_and_content_verified':raise VerifyError('Pinned target reports disagree')
 local=c.local_info(build_info);installation=local['installation'];bi=Path(build_info)
 if local['version']!=report['local_version']:raise VerifyError('Installed build changed; previous candidates need refreshing')
 if not c.HEX.fullmatch(local['build']):raise VerifyError('Invalid installed build key')
 if stage==installation or stage.is_relative_to(installation) or installation.is_relative_to(stage):raise VerifyError('Staging must remain outside the installed game')
 if shutil.disk_usage(stage).free<1024**3:raise VerifyError('At least 1 GiB free staging space required')
 tcfg=stage/'build.config';lkey=local['build'];lcfg=installation/'Data/config'/lkey[:2]/lkey[2:4]/lkey
 if not lcfg.is_file():lcfg=stage/'cache/tpr/wow/config'/lkey
 ts=meta.config(tcfg,previous['target_build_config']);ls=meta.config(lcfg,lkey)
 source_path=content/'content-private.sqlite';rows,source_fp=source_candidates(source_path,report)
 if not rows:raise VerifyError('No alternate candidates to validate in this report')
 source_fps={p:ix.fingerprint(p) for p in [report_path,previous_path,bi,tcfg,lcfg]}
 output=stage/('Payload-Verify-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());output.mkdir()
 locations,coverage,snapshots,archives,files,folder=scan_locations(installation,{r[2][:9] for r in rows},cancel,notify)
 target_path,target_origin=meta.metadata(stage,ts,'target',output,cancel,notify)
 target_fp=ix.fingerprint(target_path)
 old_path=content/'local-encoding.decoded'
 try:
  if not old_path.is_file():raise EncodingError('Previous local Encoding absent')
  local_path=meta.valid_decoded(old_path,ls,cancel);local_origin='verified_previous_content_metadata'
 except EncodingError:
  if cancel.is_set():raise VerifyError('Cancelled')
  local_path,local_origin=meta.metadata(stage,ls,'local',output,cancel,notify,installation,snapshots)
 local_fp=ix.fingerprint(local_path)
 specs=maps(rows,target_path,local_path,cancel,notify);results={};seen={};detail=[]
 statuses=['content_verified','encoded_integrity_only','validation_failed','location_not_found','read_failed','metadata_unresolved','not_checked_size_limit']
 summary={s:{'target_objects':0,'associated_target_encoded_bytes':0} for s in statuses};advertised_count=0;not_advertised_count=0
 for i,(target,ck,alt,size) in enumerate(rows):
  if cancel.is_set():raise VerifyError('Cancelled')
  notify('Hash-only payload check '+str(i+1)+' / '+str(len(rows)))
  spec=specs[target]
  if spec is None:r={'status':'metadata_unresolved','reason':'metadata_mapping_does_not_reconcile','encoded_integrity_verified':False,'decoded_ckey_verified':False};ad=False
  else:
   identity=(spec['alternate'],spec['ckey'],spec['encoded_size'],spec['decoded_size']);ad=spec['target_advertises_alternate']
   if identity not in seen:seen[identity]=check_one(spec,locations,cancel)
   r=seen[identity]
  summary[r['status']]['target_objects']+=1;summary[r['status']]['associated_target_encoded_bytes']+=size
  if r['status']=='content_verified':
   if ad:advertised_count+=1
   else:not_advertised_count+=1
  results[target]=r;detail.append((target,ck,alt,r['status'],r['reason'],size,int(ad)))
 assert sum(x['target_objects'] for x in summary.values())==len(rows)
 assert sum(x['associated_target_encoded_bytes'] for x in summary.values())==sum(r[3] for r in rows)
 db=sqlite3.connect(output/'payload-verify-private.sqlite')
 try:
  db.execute('CREATE TABLE checks(target_ekey BLOB PRIMARY KEY,ckey BLOB,alternate_ekey BLOB,status TEXT,reason TEXT,target_encoded_bytes INTEGER,target_advertises_alternate INTEGER) WITHOUT ROWID')
  db.executemany('INSERT INTO checks VALUES (?,?,?,?,?,?,?)',detail);db.commit()
  independent={s:(n,b) for s,n,b in db.execute('SELECT status,count(*),sum(target_encoded_bytes) FROM checks GROUP BY status')}
  for name,val in summary.items():
   if independent.get(name,(0,0))!=(val['target_objects'],val['associated_target_encoded_bytes']):raise VerifyError('Independent result reconciliation failed')
 finally:db.close()
 ix.stable(snapshots,archives,files,folder)
 if ix.fingerprint(source_path)!=source_fp or any(ix.fingerprint(p)!=fp for p,fp in source_fps.items()):raise VerifyError('Source metadata/inventory changed during validation')
 if ix.fingerprint(target_path)!=target_fp or ix.fingerprint(local_path)!=local_fp:raise VerifyError('Encoding metadata changed during validation')
 if cancel.is_set():raise VerifyError('Cancelled')
 partial=bool(coverage['uncovered_buckets'] or coverage['journal_problems'] or coverage['invalid_needed_archive_references'])
 result={'tool':'WoW Retail EU Local Payload Verification 0.5','status':'payload_verification_completed_with_coverage_gaps' if partial else 'payload_verification_completed',
 'checked_at_utc':datetime.now(timezone.utc).isoformat(),'population':'ONLY alternate-encoding candidates from the selected v0.4 report; NOT the whole game',
 'local_version':local['version'],'target_version':report['target_version'],'product':'wow','region':'eu','input_target_candidates':len(rows),'unique_local_alternatives_evaluated':len(seen),
 'summary':summary,'verified_content_target_metadata_advertises_alternate':advertised_count,'verified_content_target_metadata_does_not_advertise_alternate':not_advertised_count,
 'target_encoding_origin':target_origin,'installed_encoding_origin':local_origin,'encoding_metadata_content_hashes_verified':True,'used_encoding_pages_checked':True,'local_index_coverage':coverage,
 'independent_class_totals_reconciled':True,'installed_files_changed':False,'network_downloads_attempted':False,'decoded_game_assets_saved':False,'game_assets_executed':False,
 'active_journals_resolved':False,'index_checksums_validated':False,'not_confirmed_saved_bandwidth':True,'full_update_engine_implemented':False,
 'limits':{'max_encoded_bytes_per_asset':MAX_ENCODED,'max_decoded_bytes_per_asset':MAX_DECODED},
 'limitations':['content_verified means full decoded size/CKey matched expected target content AND full alternate EKey/chunk integrity checked for this candidate.',
 'encoded_integrity_only means the encoded representation was checked but decoded CKey could not be computed (encrypted/unsupported mode); NOT fully verified content.',
 'A failed indexed location is NOT proof that all copies of the content on disk are corrupt or absent. Multiple locations are tried; locations outside readable journals/loose files are not searched.',
 'All readable historical journal generations are considered; active journals are unresolved. Valid payload checks are separate from journal-checksum validation.',
 'Associated target byte sums are NOT guaranteed saved bandwidth or final patch size. Even validated old content may require re-encoding, target-manifest compatibility handling or another strategy before installation.',
 'Target-advertised alternate is an Encoding metadata observation, NOT a tested promise that the current/new game will select it.',
 'No asset contents saved, no game downloads, no CASC writing or installation. The target is pinned to the previous report; latest online version is not checked.'],
 'sources':['https://wowdev.wiki/TACT','https://wowdev.wiki/BLTE','https://wowdev.wiki/CASC']}
 (output/'Retail-Payload-Verify-to-share.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
 return result,output
