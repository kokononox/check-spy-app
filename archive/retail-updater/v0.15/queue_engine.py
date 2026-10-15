"""Bounded two-route queue; verified-file resume; STAGING ONLY."""
import json,sqlite3,re,time,urllib.request,urllib.error,hashlib,os,io
from pathlib import Path
from datetime import datetime,timezone
import full_plan,complete_catalog as net,common
from payload import verify,PayloadError
CAP=16*1024*1024;MAX_OBJECT=4*1024*1024-1;MAX_DECODE=16*1024*1024;PER_ROUTE=4;MAX_ITEMS=8
class SampleError(Exception):pass

def transfer(item,stats,cancel,open_fn=None):
 if cancel.is_set():raise SampleError('cancelled')
 size=item['bytes'];key=item['archive'] if item['route']=='archive' else item['ekey'].hex()
 if not common.HEX.fullmatch(key) or not 0<size<=MAX_OBJECT:raise SampleError('invalid_object_plan')
 req=net.urllib.request.Request(net.CDN+'/tpr/wow/data/'+key[:2]+'/'+key[2:4]+'/'+key,headers={'User-Agent':'WoW-Retail-Bounded-Queue/0.15','Accept-Encoding':'identity'})
 if item['route']=='archive':req.add_header('Range','bytes='+str(item['offset'])+'-'+str(item['offset']+size-1))
 if stats['asset_requests_attempted']>=MAX_ITEMS or CAP-stats['asset_response_bytes_read']<size+1:raise SampleError('asset_budget_reached')
 stats['asset_requests_attempted']+=1
 opener=open_fn or net.urllib.request.build_opener(net.NoRedirect()).open
 with opener(req,timeout=30) as r:
  stats['last_http_status']=r.status
  if item['route']=='archive':
   if r.status!=206:raise SampleError('range_not_206_body_not_read')
   m=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',r.headers.get('Content-Range',''))
   if not m or (int(m[1]),int(m[2]))!=(item['offset'],item['offset']+size-1) or int(m[3])<=int(m[2]):raise SampleError('content_range_mismatch_body_not_read')
  elif r.status!=200:raise SampleError('direct_not_200_body_not_read')
  if r.headers.get('Content-Encoding','identity').lower() not in ('identity',''):raise SampleError('http_compression_rejected')
  length=r.headers.get('Content-Length')
  if length is not None and (not length.isdigit() or int(length)!=size):raise SampleError('content_length_mismatch_body_not_read')
  data=bytearray();deadline=time.monotonic()+90
  while True:
   if cancel.is_set():raise SampleError('cancelled')
   if time.monotonic()>deadline:raise SampleError('response_time_limit')
   b=r.read(min(65536,size+1-len(data)));stats['asset_response_bytes_read']+=len(b);data.extend(b)
   if len(data)>size:raise SampleError('response_size_overrun')
   if not b:break
  if len(data)!=size:raise SampleError('truncated_response')
  return bytes(data)

def check(path,item,cancel):
 before=(path.stat().st_size,path.stat().st_mtime_ns)
 if before[0]!=item['bytes']:raise SampleError('cached_sample_size_mismatch')
 with path.open('rb') as f:proof=verify(f,item['bytes'],item['decoded_size'],item['ckey'],item['ekey'],cancel)
 if (path.stat().st_size,path.stat().st_mtime_ns)!=before:raise SampleError('cached_sample_changed')
 return proof

def select(db):
 byroute={};eligible={}
 for route,kind in [('archive','archive_range_location_known'),('direct','advertised_direct_only')]:
  params=(kind,MAX_OBJECT,MAX_DECODE)
  eligible[route]=db.execute('SELECT count(*) FROM candidate WHERE transport_class=? AND metadata_status="mapped" AND bytes>0 AND bytes<=? AND decoded_size>=0 AND decoded_size<=?',params).fetchone()[0]
  rows=db.execute('SELECT ekey,bytes,ckey,decoded_size FROM candidate WHERE transport_class=? AND metadata_status="mapped" AND bytes>0 AND bytes<=? AND decoded_size>=0 AND decoded_size<=? ORDER BY bytes,ekey LIMIT 4',params).fetchall();byroute[route]=[]
  for ek,n,ck,ds in rows:
   if not isinstance(ek,bytes) or len(ek)!=16 or not isinstance(ck,bytes) or len(ck)!=16:raise SampleError('invalid_metadata_key')
   item={'ekey':ek,'bytes':n,'ckey':ck,'decoded_size':ds,'route':route}
   if route=='archive':
    loc=db.execute('SELECT archive,offset,bytes FROM location WHERE ekey=? AND route="archive_range" ORDER BY archive,offset LIMIT 1',(ek,)).fetchone()
    if loc is None or loc[2]!=n or not common.HEX.fullmatch(loc[0]) or not 0<=loc[1]<=2**32-n:raise SampleError('invalid_archive_location')
    item.update(archive=loc[0],offset=loc[1])
   byroute[route].append(item)
 selected=[];used=0
 # Round-robin budget allocation avoids consuming all quota on the first route.
 for i in range(PER_ROUTE):
  for route in ('archive','direct'):
   if i>=len(byroute[route]):continue
   item=byroute[route][i]
   if used+item['bytes']+1<=CAP:selected.append(item);used+=item['bytes']+1
 selected.sort(key=lambda i:(i['route']!='archive',i['bytes'],i['ekey']))
 return selected,eligible

def public_item(i,item):
 return {'item_number':i+1,'route':item['route'],'expected_encoded_bytes':item['bytes'],'status':'pending','http_status':None,'failure_reason':None,'encoded_integrity_verified':False,'decoded_ckey_verified':False}
def exclusive_save(path,data):
 created=False
 try:
  with path.open('xb') as f:created=True;f.write(data)
 except FileExistsError:raise SampleError('concurrent_cache_file_preserved')
 except OSError:
  if created and path.exists():path.unlink()
  raise

def execute(items,store,report,cancel,notify,opener=None,stable=lambda:None,before_network=lambda:None,seed_dirs=(),persist=lambda:None):
 if len(items)>MAX_ITEMS or sum(i['bytes']+1 for i in items)>CAP or any(i['route'] not in ('archive','direct') or not 0<i['bytes']<=MAX_OBJECT or not 0<=i['decoded_size']<=MAX_DECODE for i in items):raise SampleError('invalid_queue_limits')
 report['items']=[public_item(i,item) for i,item in enumerate(items)];persist();network_ready=False
 for item,row in zip(items,report['items']):
  report['last_http_status']=None
  if cancel.is_set():row.update(status='cancelled',failure_reason='cancelled');persist();break
  path=store/(item['ekey'].hex()+'.blte')
  try:
   stable();notify('Checking queue item '+str(row['item_number'])+' / '+str(len(items)))
   if path.exists():
    if not path.resolve().is_relative_to(store.resolve()):raise SampleError('cache_file_outside_store')
    proof=check(path,item,cancel);stable();row['status']='verified_queue_cache_reused';report['verified_queue_cache_reused']+=1
   else:
    seed=next((folder/path.name for folder in seed_dirs if (folder/path.name).exists()),None)
    if seed is not None:
     if not seed.resolve().is_relative_to(seed.parent.resolve()):raise SampleError('seed_outside_stage')
     before=(seed.stat().st_size,seed.stat().st_mtime_ns)
     if before[0]!=item['bytes']:raise SampleError('seed_size_mismatch')
     data=seed.read_bytes()
     if len(data)!=item['bytes']:raise SampleError('seed_size_mismatch')
     proof=verify(io.BytesIO(data),item['bytes'],item['decoded_size'],item['ckey'],item['ekey'],cancel)
     if (seed.stat().st_size,seed.stat().st_mtime_ns)!=before:raise SampleError('seed_changed')
     stable();exclusive_save(path,data);row['status']='previous_pilot_file_verified_and_imported';report['verified_previous_files_imported']+=1
    else:
     if not network_ready:before_network();network_ready=True
     stable();notify('Downloading small '+item['route']+' queue item '+str(row['item_number']))
     data=transfer(item,report,cancel,opener);row['http_status']=report['last_http_status'];proof=verify(io.BytesIO(data),item['bytes'],item['decoded_size'],item['ckey'],item['ekey'],cancel);stable()
     if cancel.is_set():raise SampleError('cancelled')
     exclusive_save(path,data);row['status']='new_object_downloaded_and_verified';report['new_verified_objects_saved']+=1
   row.update(encoded_integrity_verified=proof['encoded_integrity_verified'],decoded_ckey_verified=proof['decoded_ckey_verified'],unsupported_modes_hex=proof.get('unsupported_modes_hex',[]));persist()
  except Exception as e:
   row['http_status']=e.code if isinstance(e,urllib.error.HTTPError) else report.get('last_http_status')
   row.update(status='cancelled' if cancel.is_set() else 'failed',failure_reason='http_'+str(e.code) if isinstance(e,urllib.error.HTTPError) else str(e) if isinstance(e,(SampleError,net.CompletionError,PayloadError)) else type(e).__name__)
   for later in report['items']:
    if later['status']=='pending':later['status']='not_attempted_after_stop'
   persist();break
 if cancel.is_set():
  for later in report['items']:
   if later['status']=='pending':later['status']='not_attempted_after_stop'
 report['encoded_verified_objects']=sum(i['encoded_integrity_verified'] for i in report['items']);report['decoded_ckey_verified_objects']=sum(i['decoded_ckey_verified'] for i in report['items'])
 if report['encoded_verified_objects']!=report['new_verified_objects_saved']+report['verified_queue_cache_reused']+report['verified_previous_files_imported']:raise SampleError('independent_progress_count_mismatch')
 report['encoded_verified_bytes']=sum(i['expected_encoded_bytes'] for i in report['items'] if i['encoded_integrity_verified'])
 report['verified_new_download_bytes']=sum(i['expected_encoded_bytes'] for i in report['items'] if i['status']=='new_object_downloaded_and_verified' and i['encoded_integrity_verified'])
 report['verified_imported_bytes']=sum(i['expected_encoded_bytes'] for i in report['items'] if i['status']=='previous_pilot_file_verified_and_imported' and i['encoded_integrity_verified'])
 report['verified_reused_queue_bytes']=sum(i['expected_encoded_bytes'] for i in report['items'] if i['status']=='verified_queue_cache_reused' and i['encoded_integrity_verified'])
 report['verified_byte_categories_reconcile']=report['encoded_verified_bytes']==report['verified_new_download_bytes']+report['verified_imported_bytes']+report['verified_reused_queue_bytes']
 if not report['verified_byte_categories_reconcile']:raise SampleError('verified_byte_totals_mismatch')
 report['status']='queue_cancelled_with_progress_preserved' if cancel.is_set() else 'bounded_queue_completed' if all(i['encoded_integrity_verified'] and i['status'] in ('verified_queue_cache_reused','previous_pilot_file_verified_and_imported','new_object_downloaded_and_verified') for i in report['items']) else 'queue_stopped_with_progress_preserved'
 report.pop('last_http_status',None);persist()

def run(rp,bi,cancel,notify):
 notify('Preparing fresh OFFLINE plan. No imported private database trusted.')
 plan,planout=full_plan.run(rp,bi,cancel,notify)
 if plan['status']!='global_candidate_plan_completed':raise SampleError('fresh_plan_partial_no_queue_started')
 stage=Path(rp).resolve().parent.parent;db=sqlite3.connect((planout/'full-plan-private.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
 try:items,eligible=select(db)
 finally:db.close()
 prior=full_plan.read_report(stage/'Retail-Staging-to-share.json');build=prior['target_build_config'];root=stage/'Queue-v015'/build;store=root/'objects';store.mkdir(parents=True,exist_ok=True)
 if not store.resolve().is_relative_to(stage):raise SampleError('queue_cache_outside_stage')
 out=root/('Run-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir()
 report={'tool':'WoW Retail EU Bounded Resumable Queue 0.15','status':'queue_prepared','product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'eligible_candidates_under_per_object_caps':eligible,'selected_queue_objects':len(items),'planned_encoded_bytes':sum(i['bytes'] for i in items),'max_queue_objects':MAX_ITEMS,'max_objects_per_route':PER_ROUTE,'asset_response_read_cap_bytes':CAP,'max_encoded_bytes_per_object':MAX_OBJECT,'max_decoded_bytes_per_object':MAX_DECODE,'asset_requests_attempted':0,'asset_response_bytes_read':0,'verified_queue_cache_reused':0,'verified_previous_files_imported':0,'new_verified_objects_saved':0,'items':[],'metadata':{'requests_attempted':0,'response_bytes_read':0,'network_access_attempted':False},'automatic_retries':0,'complete_verified_file_resume_supported':True,'partial_byte_resume_supported':False,'installed_files_changed':False,'decoded_game_assets_saved':False,'assets_executed':False,'decryption_attempted':False,'full_update_engine_implemented':False,'limitations':['Bounded test queue of at most eight smallest eligible objects, NOT whole-update download, playable installer or patch-size estimate.','16 MiB asset response-read cap includes oversize probes; two <256 KiB EU metadata responses, network buffering and HTTP/TLS overhead additional.','First error stops queue; completed verified files retained. Resume revalidates complete files, not partial response bytes.','Previous v0.12/v0.14 exact encoded files reverified before local copy; originals preserved.','Current sources reconstruct selection; unchanged sources reproduce same bounded queue, not automatic next batch.','Separate queue/pilot caches not subtracted by inherited global planner.','Encoded integrity may be verified while opaque decoded CKey remains unknown; decoded bytes never saved/executed.','Private queue manifest and SQLite stay LOCAL.']}
 sources=[Path(rp).resolve(),Path(bi).resolve(),stage/'Retail-Staging-to-share.json',stage/'build.config'];snapshot={p:hashlib.sha256(p.read_bytes()).digest() for p in sources}
 def stable():
  if any(hashlib.sha256(p.read_bytes()).digest()!=h for p,h in snapshot.items()):raise SampleError('source_changed')
 def before_network():
  report['current_online_version']=net.online(report['metadata'],cancel,net.fetch);report['pinned_target_matches_current_online']=report['current_online_version']==plan['target_version'];stable()
 def persist():
  private={'target_build_key':build,'selection':[dict(ekey=i['ekey'].hex(),ckey=i['ckey'].hex(),encoded_bytes=i['bytes'],decoded_bytes=i['decoded_size'],route=i['route'],archive=i.get('archive'),offset=i.get('offset')) for i in items],'current_run_report':report}
  tmp=out/'queue-private.tmp';tmp.write_text(json.dumps(private,indent=2)+'\n',encoding='utf-8');tmp.replace(out/'queue-private.json')
  tmp=out/'report.tmp';tmp.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');tmp.replace(out/'Retail-Queue-to-share.json')
 seed_dirs=[stage/'Route-Samples-v012'/build/'objects',stage/'Direct-Sample-v014'/build/'objects']
 if any(d.exists() and not d.resolve().is_relative_to(stage) for d in seed_dirs):raise SampleError('seed_folder_outside_stage')
 try:
  if not items:report['status']='no_eligible_bounded_queue_objects'
  else:execute(items,store,report,cancel,notify,stable=stable,before_network=before_network,seed_dirs=seed_dirs,persist=persist)
 except Exception as e:report.update(status='queue_stopped_with_progress_preserved',failure_reason=str(e) if isinstance(e,(SampleError,net.CompletionError,PayloadError)) else type(e).__name__)
 finally:
  report['checked_at_utc']=datetime.now(timezone.utc).isoformat();report['network_access_attempted']=bool(report['asset_requests_attempted'] or report['metadata']['network_access_attempted']);persist()
 return report,out
