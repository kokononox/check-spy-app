import hashlib,json,os,re,shutil,sqlite3
from datetime import datetime,timezone
from pathlib import Path
import common as c
import indexes as ix
from encoding import EncodingTable,EncodingError,decode_stream,digest_file,MAX_BYTES
class ContentError(Exception):pass

def fields(data):
 out={}
 for line in data.decode('utf-8-sig').splitlines():
  if '=' in line and not line.lstrip().startswith('#'):
   k,v=line.split('=',1);out[k.strip()]=v.split()
 return out

def config(path,key):
 if not path.is_file() or path.stat().st_size>4*1024*1024:raise ContentError('Required build configuration missing/oversized; no download was attempted')
 b=path.read_bytes()
 if c.md5(b)!=key.lower():raise ContentError('Build configuration content hash mismatch')
 result=fields(b)
 if result.get('build-uid')!=['wow']:raise ContentError('Not a Retail WoW build configuration')
 keys=result.get('encoding',[]);sizes=result.get('encoding-size',[])
 if len(keys)!=2 or len(sizes)!=2 or not all(c.HEX.fullmatch(k) for k in keys):raise ContentError('Unsupported Encoding configuration')
 sizes=list(map(int,sizes))
 if not all(0<x<=MAX_BYTES for x in sizes):raise ContentError('Encoding metadata exceeds supported size')
 return {'ckey':keys[0].lower(),'ekey':keys[1].lower(),'decoded':sizes[0],'encoded':sizes[1]}

def valid_decoded(path,spec,cancel):
 if path.stat().st_size!=spec['decoded']:raise EncodingError('Cached Encoding size mismatch')
 before=ix.fingerprint(path)
 if digest_file(path,cancel)!=spec['ckey']:raise EncodingError('Cached Encoding CKey mismatch')
 if ix.fingerprint(path)!=before:raise EncodingError('Encoding file changed during hash verification')
 return path

def metadata(stage,spec,label,output,cancel,notify,installation=None,journal_snapshots=None):
 cache=stage/'cache/tpr/wow/data';decoded=cache/(spec['ekey']+'.decoded');encoded=cache/spec['ekey'];failures=0
 if decoded.is_file():
  try:return valid_decoded(decoded,spec,cancel),'verified_existing_decoded_cache'
  except EncodingError:
   if cancel.is_set():raise
   failures+=1
 if encoded.is_file() and encoded.stat().st_size==spec['encoded']:
  try:
   before=ix.fingerprint(encoded)
   with encoded.open('rb') as src:
    dest=decode_stream(src,spec['encoded'],spec['decoded'],spec['ckey'],spec['ekey'],output/(label+'-encoding.decoded'),cancel,notify)
   if ix.fingerprint(encoded)!=before:raise EncodingError('Encoded metadata cache changed during read')
   return dest,'verified_existing_encoded_cache'
  except EncodingError:
   if cancel.is_set():raise
   failures+=1
 if installation is None:
  raise ContentError('Verified target Encoding metadata is unavailable in the v0.2 cache. No network download was attempted.')
 key=bytes.fromhex(spec['ekey'])[:9];attempts=0
 notify('Locating installed Encoding metadata in local CASC archives…')
 for path,before in journal_snapshots.items():
  if cancel.is_set():raise ContentError('Cancelled')
  bucket=int(path.name[:2],16)
  try:records=ix.parse_idx(path.read_bytes(),bucket)
  except ix.PlanError:continue
  for prefix,archive,offset,total in records:
   if prefix!=key or total-30!=spec['encoded']:continue
   attempts+=1
   if attempts>64:raise ContentError('Too many ambiguous Encoding metadata locations')
   archive_path=installation/'Data/data'/('data.'+str(archive).zfill(3))
   try:
    old=ix.fingerprint(archive_path)
    if offset+total>old[0]:continue
    with archive_path.open('rb') as src:
     src.seek(offset+30)
     dest=decode_stream(src,spec['encoded'],spec['decoded'],spec['ckey'],spec['ekey'],output/(label+'-encoding.decoded'),cancel,notify)
    if ix.fingerprint(archive_path)!=old:raise EncodingError('Local metadata archive changed during read')
    if ix.fingerprint(path)!=before:raise EncodingError('Local journal changed during metadata lookup')
    return dest,'verified_local_archive_metadata'
   except (OSError,EncodingError):
    if cancel.is_set():raise ContentError('Cancelled')
    failures+=1
 raise ContentError('Installed Encoding metadata could not be located and fully hash-verified. No game data was downloaded.')

def original_unmatched(source_path,report):
 if not source_path.is_file():raise ContentError('Original inventory-private.sqlite is missing; do not upload it, keep it beside the v0.3 report')
 before=ix.fingerprint(source_path)
 db=sqlite3.connect(source_path.resolve().as_uri()+'?mode=ro',uri=True);db.execute('PRAGMA query_only=ON')
 try:
  for name,expected in [('target',['ekey','bytes','priority']),('local',['prefix','bytes'])]:
   schema=[r[1] for r in db.execute('PRAGMA table_info('+name+')')]
   if schema!=expected:raise ContentError('Unexpected v0.3 inventory database schema')
  total=db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM target').fetchone()
  if total!=(report['summary']['unique_target_ekeys'],report['summary']['target_encoded_bytes']):raise ContentError('Inventory report/database disagree; rerun v0.3')
  rows=db.execute('SELECT t.ekey,t.bytes FROM target t WHERE NOT EXISTS(SELECT 1 FROM local l WHERE l.prefix=substr(t.ekey,1,9) AND l.bytes=t.bytes)').fetchall()
  expected=report['summary']['no_observed_prefix_match']+report['summary']['prefix_with_size_mismatch'];expected_bytes=report['summary']['no_prefix_match_encoded_bytes']+report['summary']['size_mismatch_encoded_bytes']
  if len(rows)!=expected or sum(r[1] for r in rows)!=expected_bytes:raise ContentError('Original unmatched population does not reconcile')
  if any(not isinstance(key,bytes) or len(key)!=16 or size<=0 for key,size in rows):raise ContentError('Invalid target records')
  return dict(rows),before
 finally:db.close()

def compare_maps(missing,current_db,target_path,local_path,cancel,notify):
 exact={};remaining={}
 for key,size in missing.items():
  if current_db.execute('SELECT 1 FROM local WHERE prefix=? AND bytes=? LIMIT 1',(key[:9],size)).fetchone():exact[key]=size
  else:remaining[key]=size
 mapped={};wanted=set(remaining)
 with EncodingTable(target_path) as target:
  for ck,ds,keys in target.c_records(cancel,notify):
   for ek in keys:
    if ek in wanted:
     if ek in mapped and mapped[ek]!=(ck,ds):raise ContentError('Ambiguous target EKey-to-CKey mapping')
     mapped[ek]=(ck,ds)
 needed={x[0] for x in mapped.values()};local_map={};all_alternates=set()
 with EncodingTable(local_path) as local:
  for ck,ds,keys in local.c_records(cancel,notify):
   if ck in needed:local_map[ck]=(ds,keys);all_alternates.update(keys)
  sizes=local.e_sizes(all_alternates,cancel,notify)
 categories={'exact_index_candidate_now':dict(exact),'alternate_encoding_same_content_candidate':{},'same_content_metadata_no_local_index_candidate':{},'content_key_not_in_installed_build_metadata':{},'target_ekey_unmapped':{},'metadata_decoded_size_conflict':{}}
 private=[]
 for key,encoded_size in remaining.items():
  if cancel.is_set():raise ContentError('Cancelled')
  ck=None;alt=None
  if key not in mapped:status='target_ekey_unmapped'
  else:
   ck,decoded_size=mapped[key]
   if ck not in local_map:status='content_key_not_in_installed_build_metadata'
   elif local_map[ck][0]!=decoded_size:status='metadata_decoded_size_conflict'
   else:
    status='same_content_metadata_no_local_index_candidate'
    for candidate in local_map[ck][1]:
     if candidate==key:continue
     size=sizes.get(candidate)
     if size is not None and current_db.execute('SELECT 1 FROM local WHERE prefix=? AND bytes=? LIMIT 1',(candidate[:9],size)).fetchone():
      alt=candidate;status='alternate_encoding_same_content_candidate';break
  categories[status][key]=encoded_size;private.append((key,ck,alt,status,encoded_size))
 summary={name:{'target_objects':len(values),'target_whole_encoded_bytes':sum(values.values())} for name,values in categories.items()}
 assert sum(v['target_objects'] for v in summary.values())==len(missing)
 assert sum(v['target_whole_encoded_bytes'] for v in summary.values())==sum(missing.values())
 return summary,private

def run(report_path,build_info,cancel,notify):
 report_path=Path(report_path).resolve();inventory=report_path.parent;stage=inventory.parent
 if report_path.stat().st_size>65536:raise ContentError('Inventory report too large')
 report=json.loads(report_path.read_text(encoding='utf-8-sig'))
 if report.get('product')!='wow' or report.get('region')!='eu' or report.get('status') not in ('candidate_inventory_completed','candidate_inventory_partial'):raise ContentError('Select the ORIGINAL v0.3 inventory report')
 previous_path=stage/'Retail-Staging-to-share.json'
 if previous_path.stat().st_size>65536:raise ContentError('Prior staging report too large')
 previous=json.loads(previous_path.read_text(encoding='utf-8-sig'))
 if previous.get('status')!='sample_downloaded_and_content_verified' or previous.get('target_version')!=report['target_version']:raise ContentError('Staging target and inventory target disagree')
 local=c.local_info(build_info);installation=local['installation'];bi=Path(build_info);bi_before=ix.fingerprint(bi)
 if local['version']!=report['local_version']:raise ContentError('Installed build changed; rerun v0.3 before comparing content')
 if stage==installation or stage.is_relative_to(installation) or installation.is_relative_to(stage):raise ContentError('Staging must remain separate from installed game')
 if shutil.disk_usage(stage).free<1024**3:raise ContentError('At least 1 GiB free staging space required')
 target_spec=config(stage/'build.config',previous['target_build_config'])
 local_key=local['build']
 if not c.HEX.fullmatch(local_key):raise ContentError('Invalid installed build hash')
 local_config=installation/'Data/config'/local_key[:2]/local_key[2:4]/local_key
 if not local_config.is_file():local_config=stage/'cache/tpr/wow/config'/local_key
 local_spec=config(local_config,local_key)
 bound_inputs={path:ix.fingerprint(path) for path in [report_path,previous_path,stage/'build.config',local_config]}
 missing,source_before=original_unmatched(inventory/'inventory-private.sqlite',report)
 output=stage/('Content-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());output.mkdir()
 db=ix.open_db(output/'content-private.sqlite');db.set_progress_handler(lambda:1 if cancel.is_set() else 0,10000)
 try:
  coverage,snapshots,archives,files,folder=ix.import_local(db,installation,cancel,notify)
  target_path,target_origin=metadata(stage,target_spec,'target',output,cancel,notify)
  target_fp=ix.fingerprint(target_path)
  local_path,local_origin=metadata(stage,local_spec,'local',output,cancel,notify,installation,snapshots)
  meta_fps={target_path:target_fp,local_path:ix.fingerprint(local_path)}
  summary,details=compare_maps(missing,db,target_path,local_path,cancel,notify)
  db.execute('CREATE TABLE content_comparison(target_ekey BLOB PRIMARY KEY, ckey BLOB, alternate_ekey BLOB,status TEXT, target_encoded_bytes INTEGER) WITHOUT ROWID')
  db.executemany('INSERT INTO content_comparison VALUES (?,?,?,?,?)',details)
  detail_keys={x[0] for x in details}
  db.executemany('INSERT INTO content_comparison VALUES (?,NULL,NULL,?,?)',[(k,'exact_index_candidate_now',v) for k,v in missing.items() if k not in detail_keys]);db.commit()
  # Independent SQL reconciliation of every reported class, using persisted detail rows.
  actual={s:(n,b) for s,n,b in db.execute('SELECT status,count(*),sum(target_encoded_bytes) FROM content_comparison GROUP BY status')}
  for name,value in summary.items():
   if actual.get(name,(0,0))!=(value['target_objects'],value['target_whole_encoded_bytes']):raise ContentError('Independent class reconciliation failed')
  ix.stable(snapshots,archives,files,folder)
  if ix.fingerprint(bi)!=bi_before or ix.fingerprint(inventory/'inventory-private.sqlite')!=source_before:raise ContentError('Source installation/inventory changed during comparison')
  if any(ix.fingerprint(path)!=old for path,old in meta_fps.items()):raise ContentError('Verified Encoding metadata changed during comparison')
  if any(ix.fingerprint(path)!=old for path,old in bound_inputs.items()):raise ContentError('Build configuration or source report changed during comparison')
  if cancel.is_set():raise ContentError('Cancelled')
  partial=bool(coverage['uncovered_buckets'] or coverage['journal_problems'] or coverage['invalid_or_unavailable_archive_references'])
  result={'tool':'WoW Retail EU Content Comparison 0.4','status':'candidate_content_comparison_partial' if partial else 'candidate_content_comparison_completed','checked_at_utc':datetime.now(timezone.utc).isoformat(),
   'mode':'offline_ckey_candidate_comparison_no_game_update','local_version':local['version'],'target_version':report['target_version'],'product':'wow','region':'eu',
   'population':'ONLY v0.3 target EKeys without a prefix+size candidate; not the entire installation',
   'original_unmatched_target_objects':len(missing),'original_unmatched_whole_encoded_bytes':sum(missing.values()),'summary':summary,
   'target_encoding_content_hash_verified':True,'installed_encoding_content_hash_verified':True,'target_encoding_origin':target_origin,'installed_encoding_origin':local_origin,
   'used_encoding_page_checksums_verified':True,'fresh_index_coverage':coverage,'comparison_has_index_coverage_gaps':partial,'prior_inventory_was_partial':bool(report.get('comparison_has_index_coverage_gaps',False)),'class_totals_independently_reconciled':True,'installed_files_changed':False,'network_downloads_attempted':False,
   'game_asset_payloads_verified':False,'active_journals_resolved':False,'index_checksums_validated':False,
   'limitations':['Encoding metadata content hashes/pages are verified; OTHER game asset contents are NOT verified.',
    'Alternate candidates require matching CKey and decoded size plus an alternate EKey prefix/encoded-size match in current local indexes; actual alternate asset payload is NOT validated.',
    'No content key in the installed build metadata is NOT proof of absence from disk. Loose files and other installed builds are not searched.',
    'Whole-object byte sums are NOT confirmed saved bandwidth or patch/download sizes. Binary patch chains and minimal playable/optional content selection are not implemented.',
    'All readable historical journal generations are considered, not resolved active journals. Coverage warnings remain relevant.',
    'No game files downloaded, no CASC writes, installation or rollback engine. Target is pinned to the prior inventory, not checked for latest version online.'],
   'sources':['https://wowdev.wiki/TACT','https://wowdev.wiki/CASC','https://github.com/wowdev/TACTSharp']}
  (output/'Retail-Content-to-share.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
  return result,output
 except sqlite3.OperationalError:
  if cancel.is_set():raise ContentError('Cancelled')
  raise
 finally:db.close()
