"""Bounded staged batch; exact target objects, no installation or decryption."""
import json,os,shutil
from pathlib import Path
from datetime import datetime,timezone
import pilot,range_pilot as ranges
MAX_OBJECTS=8
CAP=pilot.CAP
class BatchError(Exception):pass
def stats_new():return {'cached_index_files_checked':0,'remote_index_requests':0,'index_response_bytes_read':0,'index_validation_problems':0,'index_network_problems':0,'generated_group_index_used':False,'index_search_complete':False,'cdn_config_downloaded':False,'cdn_config_requests':0}
def clean_stats(stats):return {k:v for k,v in stats.items() if not k.startswith('_')}
def public_item(item):
 keys=['sample_number','expected_encoded_bytes','lookup_status','lookup_failure_reason','lookup_search_complete','download_status','range_http_status','range_response_bytes_read','encoded_integrity_verified','decoded_ckey_verified','downloaded_asset_kept','unsupported_modes_hex']
 return {k:item.get(k) for k in keys}
def make_report(plan,status,reason=None):
 items=plan['items'];verified=[i for i in items if i.get('encoded_integrity_verified')];ready=[i for i in items if i['lookup_status']=='located']
 received=sum(i.get('range_response_bytes_read',0) for i in items)
 assert len(items)<=MAX_OBJECTS and sum(i['expected_encoded_bytes'] for i in items)<CAP and received<=CAP
 counts={}
 for i in items:counts[i.get('download_status','pending')]=counts.get(i.get('download_status','pending'),0)+1
 assert sum(counts.values())==len(items)
 return {'tool':'WoW Retail EU Small Archive Batch 0.9','status':status,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'current_online_version':plan['current_online_version'],'pinned_target_matches_current_online_version':plan['target_version']==plan['current_online_version'],'selected_target_objects':len(items),'located_target_objects':len(ready),'planned_range_bytes':sum(i['expected_encoded_bytes'] for i in ready),'selected_target_bytes':sum(i['expected_encoded_bytes'] for i in items),'range_requests_attempted':sum(bool(i.get('range_request_attempted')) for i in items),'range_response_bytes_read':received,'encoded_verified_objects':len(verified),'decoded_ckey_verified_objects':sum(bool(i.get('decoded_ckey_verified')) for i in verified),'encoded_verified_bytes':sum(i['expected_encoded_bytes'] for i in verified),'counts_by_download_status':counts,'objects':list(map(public_item,items)),'lookup':clean_stats(plan['shared_stats']),'failure_reason':reason,'installed_files_changed':False,'decoded_game_assets_saved':False,'assets_executed':False,'decryption_attempted':False,'automatic_range_retries':0,'max_selected_objects':MAX_OBJECTS,'batch_asset_response_read_limit_bytes':CAP,'remote_index_response_read_budget_bytes':ranges.INDEX_BUDGET,'remote_index_request_limit':ranges.MAX_REMOTE_INDEXES,'per_object_hash_results_reconciled':True,'full_update_engine_implemented':False,'limitations':['Only up to eight small candidates from original v0.6; NOT the full game/update or saved bandwidth estimate.','Index budget of 16 requests / 32 MiB response read is SHARED across the entire batch, not per object. Cached-index check counts are validation operations and may include repeated checks of the same file.','Two small EU metadata requests plus at most one CDN config response, network buffering/HTTP/TLS overhead are additional to stated response-read limits.','Total planned object bytes are strictly below 8 MiB, reserving one overrun-detection byte; stop at the first download/verification failure.','Missing index or partial lookup is not evidence of globally absent content. Unlocated selected objects are reported and not requested.','No automatic retries/resume in this pilot. Completed verified objects survive a later failure; new runs use a new output directory, so do not repeatedly run it blindly.','Range requires 206 and exact Content-Range; full archive 200 rejected before body read.','Encoded integrity only does not prove decoded CKey for encrypted/unsupported chunks; no keys or decryption.','Pinned target is never silently changed; no CASC writer/installation/rollback or updated-game compatibility test.'],'sources':['https://wowdev.wiki/TACT','https://wowdev.wiki/BLTE']}
def save(plan,status,reason=None):
 r=make_report(plan,status,reason);dest=plan['output']/'Retail-Archive-Batch-to-share.json';temp=plan['output']/'batch-report.tmp';temp.write_text(json.dumps(r,indent=2),encoding='utf-8');temp.replace(dest);return r

def prepare(report_path,build_info,cancel,notify):
 plan=pilot.prepare(report_path,build_info,cancel,notify,batch_size=MAX_OBJECTS)
 if shutil.disk_usage(plan['stage']).free<ranges.INDEX_BUDGET+CAP+1024**2:raise BatchError('insufficient_staging_space')
 out=plan['stage']/('CDN-Batch-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir();plan['output']=out;plan['shared_stats']=stats_new();plan['items']=[]
 for n,c in enumerate(plan['candidates'],1):
  item={'sample_number':n,'expected_encoded_bytes':c['encoded_size'],'lookup_status':'pending','lookup_failure_reason':None,'lookup_search_complete':False,'download_status':'not_started','range_response_bytes_read':0,'encoded_integrity_verified':False,'decoded_ckey_verified':False,'downloaded_asset_kept':False,'plan':{**plan,**c}}
  # Per-object plans share source fingerprints and metadata/index budget.
  item['plan'].pop('items',None);item['plan'].pop('candidates',None);plan['items'].append(item)
 try:
  for item in plan['items']:
   if cancel.is_set():raise BatchError('cancelled')
   n=item['sample_number'];notify('Locating batch sample '+str(n)+' / '+str(len(plan['items']))+' in target indexes…')
   try:
    location,proof=ranges.lookup(item['plan'],out,cancel,lambda s:notify('Sample '+str(n)+': '+s),plan['shared_stats'])
    item['lookup_status']='located';item['lookup_search_complete']=plan['shared_stats']['index_search_complete'];item['plan']['location']=location;item['plan']['index_verification']=proof
   except Exception as exc:
    why,code=ranges.reason(exc)
    if why in ('cancelled','cached_index_changed','source_changed_retry_after_refresh'):raise BatchError(why)
    item['lookup_status']='unresolved';item['lookup_failure_reason']=why;item['lookup_search_complete']=plan['shared_stats']['index_search_complete'];item['download_status']='not_requested_unresolved_location'
   pilot.ensure_stable(plan['snapshots'])
  if not any(i['lookup_status']=='located' for i in plan['items']):
   return {'failed_report':save(plan,'no_located_samples_within_lookup_budget'),'output':out}
  save(plan,'batch_prepared_not_downloaded');return plan
 except Exception as exc:
  why=str(exc) if isinstance(exc,BatchError) else ranges.reason(exc)[0]
  return {'failed_report':save(plan,'cancelled' if why=='cancelled' else 'preparation_stopped',why),'output':out}

def run(plan,cancel,notify):
 items=plan['items'];status='batch_completed';failure=None
 try:
  pilot.ensure_stable(plan['snapshots'])
  if not 0<sum(i['expected_encoded_bytes'] for i in items)<CAP or len(items)>MAX_OBJECTS:raise BatchError('invalid_batch_budget')
  if any(i['plan']['encoded_size']!=i['expected_encoded_bytes'] for i in items):raise BatchError('inconsistent_object_budget')
  for item in items:
   if item['lookup_status']!='located':continue
   if cancel.is_set():raise BatchError('cancelled')
   n=item['sample_number'];subout=plan['output']/('Sample-'+str(n).zfill(2));subout.mkdir();subplan={**item['plan'],'output':subout}
   notify('Downloading sample '+str(n)+' / '+str(len(items)))
   r,_=ranges.download(subplan,cancel,lambda s:notify('Sample '+str(n)+': '+s))
   for k in ['range_request_attempted','range_http_status','range_response_bytes_read','encoded_integrity_verified','decoded_ckey_verified','downloaded_asset_kept','unsupported_modes_hex']:item[k]=r.get(k)
   item['download_status']=r['status']
   save(plan,'batch_in_progress')
   if not r['encoded_integrity_verified']:
    status='batch_cancelled' if r['status']=='cancelled' else 'batch_stopped_after_sample_failure';failure=r['failure_reason'];break
  else:
   if any(i['lookup_status']!='located' for i in items):status='batch_completed_with_unresolved_locations'
 except Exception as exc:
  failure=str(exc) if isinstance(exc,BatchError) else ranges.reason(exc)[0];status='batch_cancelled' if failure=='cancelled' else 'batch_stopped'
 for item in items:
  if item['lookup_status']=='located' and item['download_status']=='not_started':item['download_status']='not_requested_after_stop'
 return save(plan,status,failure),plan['output']
def decline(plan):
 for item in plan['items']:
  if item['lookup_status']=='located':item['download_status']='not_requested_user_declined'
 return save(plan,'batch_download_declined'),plan['output']

def stop_before_download(plan):
 for item in plan['items']:
  if item['lookup_status']=='located':item['download_status']='not_requested_after_stop'
 return save(plan,'batch_cancelled','cancelled'),plan['output']
