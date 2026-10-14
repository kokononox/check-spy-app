import json,os,re,time,hashlib,shutil,urllib.error
from pathlib import Path
from datetime import datetime,timezone
import pilot,metadata,indexes,common
from payload import verify
from archive_index import locate,IndexError
INDEX_CAP=2*1024*1024;INDEX_BUDGET=32*1024*1024;MAX_REMOTE_INDEXES=16;GROUP_LOCAL_CAP=128*1024*1024
class RangeError(Exception):pass
def url(key,kind='data',suffix=''):return pilot.CDN+'/tpr/wow/'+kind+'/'+key[:2]+'/'+key[2:4]+'/'+key+suffix

def fetch_index(key,out,cancel,stats):
 if stats['remote_index_requests']>=MAX_REMOTE_INDEXES:raise RangeError('remote_index_request_limit')
 remaining=INDEX_BUDGET-stats['index_response_bytes_read']
 limit=min(INDEX_CAP,remaining)
 if limit<=0:raise RangeError('index_metadata_budget_limit')
 stats['remote_index_requests']+=1
 with pilot.opener().open(pilot.request(url(key,suffix='.index')),timeout=30) as r:
  n=pilot.check_response(r)
  if n is not None and n>=limit:raise RangeError('index_response_size_limit')
  pieces=[];total=0;deadline=time.monotonic()+90
  while True:
   if cancel.is_set():raise RangeError('cancelled')
   if time.monotonic()>deadline:raise RangeError('index_download_time_limit')
   b=r.read(min(65536,limit-total))
   if not b:break
   total+=len(b);stats['index_response_bytes_read']+=len(b);pieces.append(b)
   if total>=limit:raise RangeError('index_response_size_limit')
 data=b''.join(pieces)
 return data

def lookup(plan,out,cancel,notify):
 stage=plan['stage'];cache=stage/'cache/tpr/wow';prior=pilot.json_read(stage/'Retail-Staging-to-share.json');key=prior.get('target_cdn_config','')
 if not common.HEX.fullmatch(key):raise RangeError('missing_target_cdn_config_key')
 key=key.lower();stats={'cached_index_files_checked':0,'remote_index_requests':0,'index_response_bytes_read':0,'index_validation_problems':0,'index_network_problems':0,'generated_group_index_used':False,'index_search_complete':False,'cdn_config_downloaded':False}
 plan['lookup_stats']=stats
 cfg=cache/'config'/key
 if cfg.is_file():
  before=indexes.fingerprint(cfg)
  if before[0]>=pilot.META_CAP:raise RangeError('cdn_config_size_limit')
  data=cfg.read_bytes();plan['snapshots'][cfg]=before
 else:
  data=pilot.text_fetch(url(key,'config'),cancel).encode();stats['cdn_config_downloaded']=True
  (out/'cdn.config').write_bytes(data)
 if hashlib.md5(data).hexdigest()!=key:raise RangeError('cdn_config_hash_mismatch')
 fields=metadata.fields(data)
 if 'builds' in fields and prior['target_build_config'] not in fields['builds']:raise RangeError('cdn_config_does_not_advertise_target_build')
 archives=fields.get('archives',[])
 if not 0<len(archives)<=10000 or len(set(archives))!=len(archives) or not all(common.HEX.fullmatch(k) and k==k.lower() for k in archives):raise RangeError('invalid_archive_list')
 stats['configured_archives']=len(archives)
 group=fields.get('archive-group',[]);group_key=group[0] if len(group)==1 and common.HEX.fullmatch(group[0]) else None
 # Existing generated group is local only, never requested on CDN.
 if group_key:
  gp=cache/'data'/(group_key+'.index')
  if gp.is_file() and gp.stat().st_size<=GROUP_LOCAL_CAP:
   notify('Verifying the existing generated group index locally; no archive download.')
   before=indexes.fingerprint(gp)
   try:
    found,verification=locate(gp.read_bytes(),group_key,plan['target_ekey'],plan['encoded_size'],archives,cancel)
    if indexes.fingerprint(gp)!=before:raise RangeError('cached_index_changed')
    plan['snapshots'][gp]=before;stats['generated_group_index_used']=True;stats['cached_index_files_checked']+=1;stats['index_search_complete']=True
    if found:return found[0],verification
    raise RangeError('exact_target_not_found_in_verified_group_index')
   except IndexError as exc:
    if str(exc)=='cancelled':raise RangeError('cancelled')
    stats['index_validation_problems']+=1
 missing=[];checked=0
 for i,archive in enumerate(archives):
  if cancel.is_set():raise RangeError('cancelled')
  path=cache/'data'/(archive+'.index')
  if not path.is_file():missing.append(archive);continue
  notify('Reading cached target archive index '+str(i+1)+' / '+str(len(archives)))
  before=indexes.fingerprint(path)
  if before[0]>INDEX_CAP:stats['index_validation_problems']+=1;continue
  try:
   found,verification=locate(path.read_bytes(),archive,plan['target_ekey'],plan['encoded_size'],cancel=cancel)
   if indexes.fingerprint(path)!=before:raise RangeError('cached_index_changed')
   plan['snapshots'][path]=before;stats['cached_index_files_checked']+=1;checked+=1
   if found:return found[0],verification
  except IndexError as exc:
   if str(exc)=='cancelled':raise RangeError('cancelled')
   stats['index_validation_problems']+=1
 for archive in missing[:MAX_REMOTE_INDEXES]:
  if cancel.is_set():raise RangeError('cancelled')
  notify('Fetching small missing target index '+str(stats['remote_index_requests']+1)+' / '+str(min(len(missing),MAX_REMOTE_INDEXES)))
  try:
   data=fetch_index(archive,out,cancel,stats);found,verification=locate(data,archive,plan['target_ekey'],plan['encoded_size'],cancel=cancel)
   (out/(archive+'.index')).write_bytes(data);checked+=1
   if found:return found[0],verification
  except IndexError as exc:
   if str(exc)=='cancelled':raise RangeError('cancelled')
   stats['index_validation_problems']+=1
  except (pilot.PilotError,RangeError,urllib.error.URLError,OSError) as exc:
   if str(exc)=='cancelled':raise RangeError('cancelled')
   stats['index_network_problems']+=1
   if stats['index_response_bytes_read']>=INDEX_BUDGET:break
 stats['index_search_complete']=checked==len(archives)
 raise RangeError('exact_target_not_found_in_complete_index_search' if stats['index_search_complete'] else 'exact_target_not_found_within_partial_index_budget')

def new_report(plan,status,reason=None):
 return {'tool':'WoW Retail EU Archive Range Pilot 0.8','status':status,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'current_online_version':plan['current_online_version'],'pinned_target_matches_current_online_version':plan['target_version']==plan['current_online_version'],'expected_encoded_bytes':plan['encoded_size'],'lookup':plan.get('lookup_stats',{}),'failure_reason':reason,'range_request_attempted':False,'range_http_status':None,'range_response_bytes_read':0,'server_range_accepted':False,'encoded_integrity_verified':False,'decoded_ckey_verified':False,'downloaded_asset_kept':False,'installed_files_changed':False,'decoded_game_assets_saved':False,'sample_executed':False,'decryption_attempted':False,'automatic_range_retries':0,'asset_response_read_limit_bytes':pilot.CAP,'remote_index_response_read_budget_bytes':INDEX_BUDGET,'remote_index_request_limit':MAX_REMOTE_INDEXES,'full_update_engine_implemented':False,'limitations':['One exact target representation only; NOT an installed update or patch size estimate.','Existing target group/individual indexes are preferred. Missing indexes: at most 16 requests and 32 MiB response bytes read; a partial search is NOT proof that content is absent.','CDN config and two official EU metadata endpoints are small additional requests; response limits do not include network buffering/HTTP/TLS overhead.','Range requires 206 and an exact Content-Range. A 200 full-archive response is rejected before reading its body; no automatic range retry.','Encrypted/unsupported chunks remain decoded-CKey unverified. No decryption or keys extracted.','Pinned target is not silently changed if the online version differs.','No credentials, personal tags, decoded assets or private paths are included in report.'],'sources':['https://wowdev.wiki/TACT','https://wowdev.wiki/BLTE']}
def save(out,report):
 (out/'Retail-Archive-Range-to-share.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
def reason(exc):
 if isinstance(exc,(RangeError,IndexError)):return str(exc),None
 return pilot.safe_reason(exc)
def prepare(report_path,build_info,cancel,notify):
 plan=pilot.prepare(report_path,build_info,cancel,notify)
 if shutil.disk_usage(plan['stage']).free<INDEX_BUDGET+pilot.CAP+1024**2:raise RangeError('insufficient_staging_space')
 out=plan['stage']/('CDN-Range-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir();plan['output']=out
 try:
  location,proof=lookup(plan,out,cancel,notify);pilot.ensure_stable(plan['snapshots']);plan['location']=location;plan['index_verification']=proof
  return plan
 except Exception as exc:
  why,code=reason(exc);r=new_report(plan,'cancelled' if why=='cancelled' else 'index_lookup_failed',why);r['lookup_http_status']=code;save(out,r)
  return {'failed_report':r,'output':out}

def download(plan,cancel,notify):
 pilot.ensure_stable(plan['snapshots']);loc=plan['location'];size=plan['encoded_size'];out=plan['output'];part=out/'range-sample.part';dest=out/'verified-target-range-sample.blte'
 if not 0<size<pilot.CAP or loc['size']!=size or not common.HEX.fullmatch(loc['archive']) or not 0<=loc['offset']<=2**32-size:raise RangeError('invalid_range_plan')
 start=loc['offset'];end=start+size-1;r=new_report(plan,'range_download_failed');r['index_verification']=plan['index_verification'];r['index_location_found']=True
 try:
  if cancel.is_set():raise RangeError('cancelled')
  req=pilot.request(url(loc['archive']));req.add_header('Range','bytes='+str(start)+'-'+str(end));r['range_request_attempted']=True
  notify('Requesting ONLY the indexed target byte range; rejecting full archive responses.')
  with pilot.opener().open(req,timeout=30) as response:
   r['range_http_status']=response.status
   if response.status!=206:raise RangeError('server_ignored_range_body_not_read' if response.status==200 else 'range_status_not_206')
   if response.headers.get('Content-Encoding','identity').lower() not in ('identity',''):raise RangeError('unexpected_http_compression')
   cr=response.headers.get('Content-Range','');m=re.fullmatch(r'bytes (\d+)-(\d+)/(\d+)',cr)
   if not m or tuple(map(int,m.groups()[:2]))!=(start,end) or int(m[3])<=end:raise RangeError('content_range_mismatch_body_not_read')
   length=response.headers.get('Content-Length')
   if length is not None and (not length.isdigit() or int(length)!=size):raise RangeError('range_content_length_mismatch_body_not_read')
   r['server_range_accepted']=True;r['archive_total_bytes_announced']=int(m[3]);deadline=time.monotonic()+180
   with part.open('xb') as f:
    while True:
     if cancel.is_set():raise RangeError('cancelled')
     if time.monotonic()>deadline:raise RangeError('range_download_time_limit')
     b=response.read(min(65536,size+1-r['range_response_bytes_read']))
     if not b:break
     r['range_response_bytes_read']+=len(b)
     if r['range_response_bytes_read']>size:raise RangeError('range_response_exceeds_expected_size')
     f.write(b);notify('Range downloaded '+str(r['range_response_bytes_read'])+' / '+str(size)+' bytes')
   if r['range_response_bytes_read']!=size:raise RangeError('truncated_range_download')
  pilot.ensure_stable(plan['snapshots'])
  with part.open('rb') as f:proof=verify(f,size,plan['decoded_size'],plan['ckey'],plan['target_ekey'],cancel)
  pilot.ensure_stable(plan['snapshots'])
  if cancel.is_set():raise RangeError('cancelled')
  if not proof['encoded_integrity_verified']:raise RangeError('encoded_integrity_not_verified')
  part.replace(dest);r.update(status='target_range_sample_downloaded_and_encoded_verified',encoded_integrity_verified=True,decoded_ckey_verified=proof['decoded_ckey_verified'],unsupported_modes_hex=proof.get('unsupported_modes_hex',[]),downloaded_asset_kept=True)
 except Exception as exc:
  why,code=reason(exc);r['failure_reason']=why
  if code is not None:r['range_http_status']=code
  r['status']='cancelled' if why=='cancelled' else 'range_download_or_verification_failed'
 finally:
  if part.exists():part.unlink()
 save(out,r);return r,out
