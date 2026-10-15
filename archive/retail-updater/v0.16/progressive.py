"""Progressive bounded queue; state IDs are hints, fresh metadata + hashes are truth."""
import json,sqlite3,hashlib,os
from pathlib import Path
from datetime import datetime,timezone
import queue_engine as q,full_plan,common
MAX_CACHE_FILES=4096
class ProgressError(q.SampleError):pass

def item_from_db(db,key):
 row=db.execute('SELECT bytes,ckey,decoded_size,transport_class FROM candidate WHERE ekey=? AND metadata_status="mapped"',(key,)).fetchone()
 if row is None:raise ProgressError('previous_queue_candidate_scope_changed')
 n,ck,ds,kind=row
 if kind not in ('archive_range_location_known','advertised_direct_only') or not 0<n<=q.MAX_OBJECT or not 0<=ds<=q.MAX_DECODE:raise ProgressError('previous_queue_candidate_no_longer_eligible')
 item={'ekey':key,'bytes':n,'ckey':ck,'decoded_size':ds,'route':'archive' if kind=='archive_range_location_known' else 'direct'}
 if item['route']=='archive':
  loc=db.execute('SELECT archive,offset,bytes FROM location WHERE ekey=? AND route="archive_range" ORDER BY archive,offset LIMIT 1',(key,)).fetchone()
  if loc is None or loc[2]!=n or not common.HEX.fullmatch(loc[0]) or not 0<=loc[1]<=2**32-n:raise ProgressError('invalid_archive_location')
  item.update(archive=loc[0],offset=loc[1])
 return item

def verified_cache(db,stage,folders,cancel,notify,snapshots=None):
 seen=set();paths=[];stats={'files_examined':0,'duplicate_representations_not_counted_twice':0,'outside_current_candidate_scope':0,'known_verified_objects':0,'known_decoded_ckey_verified_objects':0,'known_verified_encoded_bytes':0,'scan_file_cap':MAX_CACHE_FILES}
 for folder in folders:
  if folder.exists() and not folder.resolve().is_relative_to(stage):raise ProgressError('cache_folder_outside_stage')
  if folder.is_dir():
   for p in sorted(folder.glob('*.blte')):
    paths.append(p)
    if len(paths)>MAX_CACHE_FILES:raise ProgressError('cache_scan_limit_no_network_started')
 for i,p in enumerate(paths):
  if cancel.is_set():raise ProgressError('cancelled')
  if not p.resolve().is_relative_to(stage):raise ProgressError('cache_file_outside_stage')
  key=p.stem
  if not common.HEX.fullmatch(key):raise ProgressError('unexpected_cache_filename_preserved')
  key=bytes.fromhex(key);stats['files_examined']+=1
  row=db.execute('SELECT bytes,ckey,decoded_size,metadata_status FROM candidate WHERE ekey=?',(key,)).fetchone()
  if row is None:stats['outside_current_candidate_scope']+=1;continue
  n,ck,ds,status=row
  if status!='mapped' or not 0<n<=q.MAX_OBJECT or not 0<=ds<=q.MAX_DECODE:raise ProgressError('cached_candidate_metadata_or_caps_changed')
  notify('Reverifying queue/pilot cache '+str(i+1)+' / '+str(len(paths)))
  proof=q.check(p,{'bytes':n,'ckey':ck,'decoded_size':ds,'ekey':key},cancel)
  if snapshots is not None:snapshots[p]=(p.stat().st_size,p.stat().st_mtime_ns)
  if key in seen:stats['duplicate_representations_not_counted_twice']+=1;continue
  seen.add(key);stats['known_decoded_ckey_verified_objects']+=int(proof['decoded_ckey_verified']);stats['known_verified_encoded_bytes']+=n
 stats['known_verified_objects']=len(seen);return seen,stats

def read_state(path,build):
 if not path.exists():return []
 if not path.resolve().is_relative_to(path.parent.resolve()):raise ProgressError('progress_state_outside_queue_preserved')
 if path.stat().st_size>65536:raise ProgressError('oversized_progress_state_preserved')
 try:data=json.loads(path.read_text(encoding='utf-8-sig'))
 except (ValueError,OSError):raise ProgressError('invalid_progress_state_preserved')
 if not isinstance(data,dict):raise ProgressError('invalid_progress_state_preserved')
 keys=data.get('active_queue_keys')
 if data.get('tool_version')!='0.16' or data.get('target_build_key')!=build or not isinstance(keys,list) or len(keys)>q.MAX_ITEMS or not all(isinstance(k,str) and common.HEX.fullmatch(k) for k in keys):raise ProgressError('invalid_progress_state_preserved')
 decoded=[bytes.fromhex(k) for k in keys]
 if len(set(decoded))!=len(decoded):raise ProgressError('duplicate_progress_keys_preserved')
 return decoded

def choose(db,known,previous):
 if previous:
  # Never use stored sizes, routes or stored "completed" claims.
  prior_items=[item_from_db(db,k) for k in previous];pending=[i for i in prior_items if i['ekey'] not in known]
  if pending:
   if sum(i['bytes']+1 for i in pending)>q.CAP:raise ProgressError('previous_queue_budget_changed')
   return pending,previous,'resume_previous_incomplete_batch'
 # A temporary read-only selection view in memory excludes hash-verified complete objects.
 mem=sqlite3.connect(':memory:');mem.execute('CREATE TABLE candidate(ekey BLOB,bytes INTEGER,ckey BLOB,decoded_size INTEGER,transport_class TEXT,metadata_status TEXT)');mem.execute('CREATE TABLE location(ekey BLOB,route TEXT,archive TEXT,offset INTEGER,bytes INTEGER)')
 try:
  mem.executemany('INSERT INTO candidate VALUES (?,?,?,?,?,?)',(r for r in db.execute('SELECT ekey,bytes,ckey,decoded_size,transport_class,metadata_status FROM candidate') if r[0] not in known))
  mem.executemany('INSERT INTO location VALUES (?,?,?,?,?)',db.execute('SELECT ekey,route,archive,offset,bytes FROM location'));mem.commit();items,_=q.select(mem)
 finally:mem.close()
 return items,[i['ekey'] for i in items],'next_bounded_batch'

def run(rp,bi,cancel,notify):
 notify('Fresh OFFLINE metadata plan; verifying earlier cache before advancing.')
 plan,planout=full_plan.run(rp,bi,cancel,notify)
 if plan['status']!='global_candidate_plan_completed':raise ProgressError('fresh_plan_partial_no_progressive_download')
 stage=Path(rp).resolve().parent.parent;prior=full_plan.read_report(stage/'Retail-Staging-to-share.json');build=prior['target_build_config'];root=stage/'Queue-v016'/build;store=root/'objects';store.mkdir(parents=True,exist_ok=True)
 if not store.resolve().is_relative_to(stage):raise ProgressError('queue_cache_outside_stage')
 out=root/('Run-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir();state_path=root/'progress-private.json';lock=root/'queue.lock';owned=False;token=os.urandom(16).hex()
 report={'tool':'WoW Retail EU Progressive Bounded Queue 0.16','status':'preparing','product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'selected_queue_objects':0,'planned_encoded_bytes':0,'max_queue_objects':q.MAX_ITEMS,'asset_response_read_cap_bytes':q.CAP,'max_encoded_bytes_per_object':q.MAX_OBJECT,'max_decoded_bytes_per_object':q.MAX_DECODE,'asset_requests_attempted':0,'asset_response_bytes_read':0,'verified_queue_cache_reused':0,'verified_previous_files_imported':0,'new_verified_objects_saved':0,'items':[],'metadata':{'requests_attempted':0,'response_bytes_read':0,'network_access_attempted':False},'automatic_retries':0,'complete_verified_file_resume_supported':True,'partial_byte_resume_supported':False,'installed_files_changed':False,'decoded_game_assets_saved':False,'assets_executed':False,'decryption_attempted':False,'full_update_engine_implemented':False,'limitations':['Progress advances only among fresh unmatched mapped candidates under object caps; NOT full update or playable installation.','Previously complete encoded files are reverified; stored state IDs are hints only, stored sizes/status never trusted.','Incomplete prior batch resumed before next batch. No partial byte resume or automatic retry.','At most eight objects and 16 MiB asset response read including probes; two <256 KiB EU metadata responses and HTTP/TLS/network buffering additional.','Cache scan capped at4096 files; exceeding cap stops without download rather than claiming complete coverage.','Encoded integrity does not always prove decoded CKey for opaque content.','Private state/manifest/SQLite contain identifiers; keep LOCAL.','Crash/power loss may leave queue.lock; report blocker, no automatic lock deletion or blind overwrite.','No CASC writer, patch chain, rollback, game execution or decryption.']}
 db=None;items=[];active=[];known=set();selection_ready=False
 def save_public():
  tmp=out/'report.tmp';tmp.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');tmp.replace(out/'Retail-Progressive-Queue-to-share.json')
 def persist():
  save_public()
  if selection_ready:
   completed=known|{i['ekey'] for i,row in zip(items,report['items']) if row['encoded_integrity_verified']}
   state={'tool_version':'0.16','target_build_key':build,'active_queue_keys':[k.hex() for k in active],'active_queue_complete_by_current_hash_checks':all(k in completed for k in active)}
   tmp=out/'state.tmp';tmp.write_text(json.dumps(state,indent=2)+'\n',encoding='utf-8');tmp.replace(state_path)
   private={'state':state,'selected_specs':[dict(ekey=i['ekey'].hex(),ckey=i['ckey'].hex(),encoded_bytes=i['bytes'],decoded_bytes=i['decoded_size'],route=i['route'],archive=i.get('archive'),offset=i.get('offset')) for i in items]};(out/'queue-private.json').write_text(json.dumps(private,indent=2)+'\n',encoding='utf-8')
 try:
  try:
   with lock.open('x',encoding='utf-8') as f:f.write(token)
   owned=True
  except FileExistsError:raise ProgressError('another_run_or_stale_lock_preserved')
  db=sqlite3.connect((planout/'full-plan-private.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
  folders=[store,stage/'Queue-v015'/build/'objects',stage/'Route-Samples-v012'/build/'objects',stage/'Direct-Sample-v014'/build/'objects']
  sources=[Path(rp).resolve(),Path(bi).resolve(),stage/'Retail-Staging-to-share.json',stage/'build.config'];snaps={p:hashlib.sha256(p.read_bytes()).digest() for p in sources};cache_snaps={}
  known,stats=verified_cache(db,stage,folders,cancel,notify,cache_snaps);report['prior_cache_verification']=stats
  previous=read_state(state_path,build);items,active,mode=choose(db,known,previous);selection_ready=True
  report.update(selection_mode=mode,selected_queue_objects=len(items),planned_encoded_bytes=sum(i['bytes'] for i in items),previous_active_queue_objects=len(previous),previous_active_objects_already_verified=sum(k in known for k in previous))
  count=db.execute('SELECT count(*),coalesce(sum(bytes),0) FROM candidate').fetchone();report['fresh_candidate_objects_before_queue_cache']=count[0];report['fresh_candidate_whole_encoded_bytes_before_queue_cache']=count[1];report['candidate_objects_not_in_reverified_queue_cache']=count[0]-len(known)
  report['items']=[q.public_item(i,item) for i,item in enumerate(items)];persist()
  def stable():
   if any(hashlib.sha256(p.read_bytes()).digest()!=h for p,h in snaps.items()):raise ProgressError('source_changed')
   if any(not p.exists() or (p.stat().st_size,p.stat().st_mtime_ns)!=fp for p,fp in cache_snaps.items()):raise ProgressError('verified_prior_cache_changed')
  def before_network():
   report['current_online_version']=q.net.online(report['metadata'],cancel,q.net.fetch);report['pinned_target_matches_current_online']=report['current_online_version']==plan['target_version'];stable()
  if not items:stable();report['status']='no_remaining_eligible_objects_under_current_caps'
  else:q.execute(items,store,report,cancel,notify,stable=stable,before_network=before_network,seed_dirs=folders[1:],persist=persist)
 except Exception as e:
  report.update(status='progressive_queue_cancelled' if cancel.is_set() else 'progressive_queue_stopped',failure_reason=str(e) if isinstance(e,(ProgressError,q.SampleError,q.net.CompletionError,q.PayloadError)) else type(e).__name__)
 finally:
  if db is not None:db.close()
  report['checked_at_utc']=datetime.now(timezone.utc).isoformat();report['network_access_attempted']=bool(report['asset_requests_attempted'] or report['metadata']['network_access_attempted'])
  try:persist()
  finally:
   if owned and lock.exists() and lock.read_text(encoding='utf-8')==token:lock.unlink()
 return report,out
