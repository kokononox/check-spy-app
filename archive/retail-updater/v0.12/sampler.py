"""At most three small samples per route; complete verified-file resume only."""
import json,sqlite3,re,time,urllib.request,urllib.error,hashlib,os
from pathlib import Path
from datetime import datetime,timezone
import full_plan,complete_catalog as net,common
from payload import verify,PayloadError
CAP=8*1024*1024;MAX_OBJECT=1024*1024;MAX_DECODE=16*1024*1024;PER_ROUTE=3
class SampleError(Exception):pass
def select(db):
 result=[]
 for route in ['archive_range_location_known','advertised_direct_only']:
  rows=db.execute('SELECT ekey,bytes,ckey,decoded_size FROM candidate WHERE transport_class=? AND metadata_status="mapped" AND bytes>0 AND bytes<=? AND decoded_size<=? ORDER BY bytes,ekey LIMIT ?', (route,MAX_OBJECT,MAX_DECODE,PER_ROUTE)).fetchall()
  for ek,n,ck,ds in rows:
   item={'ekey':ek,'bytes':n,'ckey':ck,'decoded_size':ds,'route':'archive' if route.startswith('archive') else 'direct'}
   if item['route']=='archive':
    loc=db.execute('SELECT archive,offset,bytes FROM location WHERE ekey=? AND route="archive_range" ORDER BY archive,offset LIMIT 1',(ek,)).fetchone()
    if loc is None or loc[2]!=n or not common.HEX.fullmatch(loc[0]) or not 0<=loc[1]<=2**32-n:raise SampleError('invalid_archive_location')
    item.update(archive=loc[0],offset=loc[1])
   result.append(item)
 if sum(i['bytes']+1 for i in result)>CAP:raise SampleError('selection_budget')
 return result

def transfer(item,stats,cancel,open_fn=None):
 if cancel.is_set():raise SampleError('cancelled')
 size=item['bytes'];key=item['archive'] if item['route']=='archive' else item['ekey'].hex()
 if not common.HEX.fullmatch(key) or not 0<size<=MAX_OBJECT:raise SampleError('invalid_object_plan')
 req=net.urllib.request.Request(net.CDN+'/tpr/wow/data/'+key[:2]+'/'+key[2:4]+'/'+key,headers={'User-Agent':'WoW-Retail-Small-Route-Sampler/0.12','Accept-Encoding':'identity'})
 if item['route']=='archive':req.add_header('Range','bytes='+str(item['offset'])+'-'+str(item['offset']+size-1))
 if stats['asset_requests_attempted']>=2*PER_ROUTE or CAP-stats['asset_response_bytes_read']<size+1:raise SampleError('asset_budget_reached')
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
 if path.stat().st_size!=item['bytes']:raise SampleError('cached_sample_size_mismatch')
 with path.open('rb') as f:return verify(f,item['bytes'],item['decoded_size'],item['ckey'],item['ekey'],cancel)

def execute(items,store,report,cancel,notify,opener=None,stable=lambda:None):
 import io
 blocked=set()
 for i,item in enumerate(items):
  report['last_http_status']=None;route=item['route'];row={'sample_number':i+1,'route':route,'expected_encoded_bytes':item['bytes'],'status':'not_attempted','encoded_integrity_verified':False,'decoded_ckey_verified':False,'http_status':None,'failure_reason':None};report['samples'].append(row)
  if cancel.is_set():row.update(status='cancelled',failure_reason='cancelled');break
  if route in blocked:row['status']='skipped_after_route_failure';continue
  path=store/(item['ekey'].hex()+'.blte')
  try:
   stable()
   if path.exists():
    if not path.resolve().is_relative_to(store.resolve()):raise SampleError('cached_sample_outside_store')
    proof=check(path,item,cancel);row['status']='verified_cached_sample_reused';report['verified_cached_samples_reused']+=1
   else:
    notify('Small '+route+' sample '+str(i+1)+' / '+str(len(items)))
    report['last_http_status']=None;data=transfer(item,report,cancel,opener);row['http_status']=report['last_http_status']
    proof=verify(io.BytesIO(data),item['bytes'],item['decoded_size'],item['ckey'],item['ekey'],cancel);stable()
    created=False
    try:
     with path.open('xb') as f:created=True;f.write(data)
    except FileExistsError:raise SampleError('concurrent_sample_preserved')
    except OSError:
     if created and path.exists():path.unlink()
     raise
    row['status']='sample_downloaded_and_verified';report['new_verified_samples_saved']+=1
   row.update(encoded_integrity_verified=proof['encoded_integrity_verified'],decoded_ckey_verified=proof['decoded_ckey_verified'],unsupported_modes_hex=proof.get('unsupported_modes_hex',[]))
  except Exception as e:
   row['http_status']=report.get('last_http_status')
   if isinstance(e,urllib.error.HTTPError):row['http_status']=e.code
   row.update(status='cancelled' if cancel.is_set() else 'sample_failed',failure_reason='http_'+str(e.code) if isinstance(e,urllib.error.HTTPError) else str(e) if isinstance(e,(SampleError,net.CompletionError,PayloadError)) else type(e).__name__)
   blocked.add(route)
   if cancel.is_set():break
 report['encoded_verified_samples']=sum(s['encoded_integrity_verified'] for s in report['samples']);report['decoded_ckey_verified_samples']=sum(s['decoded_ckey_verified'] for s in report['samples'])
 report['status']='cancelled' if cancel.is_set() else 'samples_completed' if len(report['samples'])==len(items) and all(s['encoded_integrity_verified'] for s in report['samples']) else 'samples_partial_with_route_failure'
 report.pop('last_http_status',None)

def run(rp,bi,cancel,notify):
 # Rebuild from checksum-verified metadata, not an untrusted imported SQLite.
 notify('Building fresh OFFLINE plan from existing cache before sampling…')
 plan,planout=full_plan.run(rp,bi,cancel,notify)
 if plan['status']!='global_candidate_plan_completed':raise SampleError('fresh_plan_partial_no_sampling_started')
 stage=Path(rp).resolve().parent.parent;db=sqlite3.connect((planout/'full-plan-private.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
 try:items=select(db)
 finally:db.close()
 prior=full_plan.read_report(stage/'Retail-Staging-to-share.json');root=stage/'Route-Samples-v012'/prior['target_build_config'];store=root/'objects';store.mkdir(parents=True,exist_ok=True)
 if not store.resolve().is_relative_to(stage):raise SampleError('sample_store_outside_stage')
 out=root/('Run-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir()
 report={'tool':'WoW Retail EU Small Resumable Route Samples 0.12','status':'prepared','product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'selected_samples':len(items),'planned_encoded_bytes':sum(i['bytes'] for i in items),'asset_requests_attempted':0,'asset_response_bytes_read':0,'asset_response_read_cap_bytes':CAP,'max_samples_per_route':PER_ROUTE,'max_encoded_bytes_per_sample':MAX_OBJECT,'max_decoded_bytes_per_sample':MAX_DECODE,'new_verified_samples_saved':0,'verified_cached_samples_reused':0,'samples':[],'automatic_retries':0,'partial_response_resume_supported':False,'complete_verified_sample_reuse_supported':True,'installed_files_changed':False,'decoded_game_assets_saved':False,'assets_executed':False,'decryption_attempted':False,'full_update_engine_implemented':False,'limitations':['Smallest eligible samples per route only; no full updater, patch-size or all-object availability claim.','At most six asset requests and 8 MiB response bytes including overrun probes; two <=256 KiB EU metadata responses and HTTP/TLS overhead are additional.','Stop remaining samples only in the route that fails; other route can still be tested. No alternate host, access bypass or retry.','Completed encoded samples reverified on rerun; interrupted response discarded, no partial byte resume.','Opaque encrypted content may have encoded integrity only; decoded bytes are never saved.','Existing invalid sample preserved, not overwritten. Sample cache is separate and not subtracted from the inherited global plan.']}
 sources=[Path(rp).resolve(),Path(bi).resolve(),stage/'Retail-Staging-to-share.json',stage/'build.config'];snapshot={p:hashlib.sha256(p.read_bytes()).digest() for p in sources}
 def stable():
  if any(hashlib.sha256(p.read_bytes()).digest()!=h for p,h in snapshot.items()):raise SampleError('source_changed')
 try:
  if not items:report['status']='no_small_eligible_samples'
  else:
   meta={'requests_attempted':0,'response_bytes_read':0,'network_access_attempted':False};report['metadata']=meta
   report['current_online_version']=net.online(meta,cancel,net.fetch);report['pinned_target_matches_current_online']=report['current_online_version']==plan['target_version'];stable()
   execute(items,store,report,cancel,notify,stable=stable)
 except Exception as e:report.update(status='cancelled' if cancel.is_set() else 'sampling_stopped',failure_reason='http_'+str(e.code) if isinstance(e,urllib.error.HTTPError) else str(e) if isinstance(e,(SampleError,net.CompletionError,PayloadError)) else type(e).__name__)
 finally:
  report['checked_at_utc']=datetime.now(timezone.utc).isoformat();(out/'Retail-Route-Samples-to-share.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 return report,out
