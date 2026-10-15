"""Bounded HTTPS normal archive INDEX completion; never game content or installer."""
import hashlib,json,os,shutil,time,urllib.request,urllib.parse,urllib.error
from pathlib import Path
from datetime import datetime,timezone
import common,metadata,full_plan
from cdn_catalog import matches,CatalogError
CAP=64*1024*1024; PER_INDEX=8*1024*1024; META=256*1024; REQUESTS=128
CDN='https://level3.ssl.blizzard.com';BASE='https://eu.version.battle.net/v2/products/wow/'
class CompletionError(Exception):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise CompletionError('redirect_rejected')
def fetch(url,limit,stats,cancel,open_fn=None):
 if cancel.is_set():raise CompletionError('cancelled')
 if stats['requests_attempted']>=REQUESTS:raise CompletionError('request_budget_reached')
 allowance=min(limit,CAP-stats['response_bytes_read'])
 if allowance<1:raise CompletionError('response_budget_reached')
 stats['requests_attempted']+=1;stats['network_access_attempted']=True
 req=urllib.request.Request(url,headers={'User-Agent':'WoW-Retail-Index-Completion/0.11','Accept-Encoding':'identity'})
 open_fn=open_fn or urllib.request.build_opener(NoRedirect()).open
 with open_fn(req,timeout=30) as r:
  if r.status!=200:raise CompletionError('unexpected_http_status')
  if r.headers.get('Content-Encoding','identity').lower() not in ('identity',''):raise CompletionError('http_compression_rejected')
  length=r.headers.get('Content-Length')
  try:length=None if length is None else int(length)
  except ValueError:raise CompletionError('invalid_content_length')
  if length is not None and not 0<=length<allowance:raise CompletionError('response_size_limit')
  data=bytearray();deadline=time.monotonic()+90
  while True:
   if cancel.is_set():raise CompletionError('cancelled')
   if time.monotonic()>deadline:raise CompletionError('response_time_limit')
   b=r.read(min(65536,allowance-len(data)))
   stats['response_bytes_read']+=len(b);data.extend(b)
   if not b:break
   if len(data)>=allowance:raise CompletionError('response_size_limit')
  if length is not None and len(data)!=length:raise CompletionError('response_length_mismatch')
  return bytes(data)
def online(stats,cancel,fetcher):
 rows=common.rows(fetcher(BASE+'cdns',META,stats,cancel).decode('utf-8-sig'));eu=common.one([r for r in rows if r.get('Name')=='eu'])
 if eu.get('Path')!='tpr/wow':raise CompletionError('unexpected_cdn_path')
 allowed=False
 for raw in eu.get('Servers','').split():
  u=urllib.parse.urlsplit(raw)
  if u.scheme=='https' and u.hostname=='level3.ssl.blizzard.com' and u.port in (None,443) and not u.username and not u.password and u.path in ('','/'):allowed=True
 if not allowed:raise CompletionError('approved_cdn_not_advertised')
 v=common.one([r for r in common.rows(fetcher(BASE+'versions',META,stats,cancel).decode('utf-8-sig')) if r.get('Region')=='eu'])
 return v['VersionsName']
def prepare(rp,bi):
 rp=Path(rp).resolve();r=full_plan.read_report(rp);stage=rp.parent.parent;prior=full_plan.read_report(stage/'Retail-Staging-to-share.json');local=common.local_info(bi);game=local['installation']
 if r.get('tool')!='WoW Retail EU Small Archive Batch 0.9' or r.get('product')!='wow' or r.get('region')!='eu':raise CompletionError('select_original_v09_report')
 if stage==game or stage.is_relative_to(game) or game.is_relative_to(stage):raise CompletionError('stage_must_be_outside_game')
 if local['version']!=r.get('local_version'):raise CompletionError('installed_version_changed')
 if prior.get('status')!='sample_downloaded_and_content_verified' or prior.get('target_version')!=r.get('target_version'):raise CompletionError('pinned_reports_disagree')
 for key in ['target_build_config','target_cdn_config']:
  if not common.HEX.fullmatch(prior.get(key,'')):raise CompletionError('invalid_pinned_key')
 raw=(stage/'build.config').read_bytes()
 if len(raw)>4*1024**2 or common.md5(raw)!=prior['target_build_config'].lower():raise CompletionError('build_config_checksum_mismatch')
 path=stage/'cache/tpr/wow/config'/prior['target_cdn_config'].lower()
 if path.stat().st_size>4*1024**2:raise CompletionError('cdn_config_size_limit')
 raw=path.read_bytes()
 if common.md5(raw)!=prior['target_cdn_config'].lower():raise CompletionError('cdn_config_checksum_mismatch')
 f=metadata.fields(raw);archives=f.get('archives',[])
 if not 0<len(archives)<=10000 or len(set(archives))!=len(archives) or not all(common.HEX.fullmatch(a) and a==a.lower() for a in archives):raise CompletionError('invalid_archive_list')
 if 'builds' in f and prior['target_build_config'] not in f['builds']:raise CompletionError('cdn_build_conflict')
 if shutil.disk_usage(stage).free<2*1024**3:raise CompletionError('need_2GiB_free_staging')
 return rp,stage,r,archives
def run(rp,bi,cancel,notify,fetcher=fetch,rebuild=full_plan.run):
 rp,stage,old,archives=prepare(rp,bi);out=stage/('Index-Completion-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir()
 report={'tool':'WoW Retail EU Index Completion 0.11','status':'preparing','product':'wow','region':'eu','local_version':old['local_version'],'target_version':old['target_version'],'configured_normal_indexes':len(archives),'cached_scan_completed':False,'valid_cached_indexes':0,'missing_indexes_initial':0,'invalid_cached_indexes_preserved':0,'new_verified_indexes_saved':0,'remaining_normal_indexes':len(archives),'requests_attempted':0,'response_bytes_read':0,'network_access_attempted':False,'response_read_cap_bytes':CAP,'per_index_response_read_cap_bytes':PER_INDEX,'request_cap':REQUESTS,'automatic_retries':0,'partial_response_resume_supported':False,'verified_file_resume_supported':True,'game_content_download_attempted':False,'installed_files_changed':False,'full_update_engine_implemented':False,'replan_completed':False,'failure_reason':None,'limitations':['Response-read limits include EU metadata and overrun probes, not HTTP/TLS overhead or network buffering.','Only individual pinned archive .index metadata is requested; no archive-group or game content.','Existing invalid cache files are preserved and not overwritten.','Reruns revalidate and skip complete verified indexes; interrupted response is discarded, not byte-resumed.','Pinned historical target never substituted; complete indexes do not guarantee HTTP availability or a playable update.']}
 cache=stage/'cache/tpr/wow/data';missing=[]
 try:
  for i,key in enumerate(archives):
   if cancel.is_set():raise CompletionError('cancelled')
   notify('Validating cached index '+str(i+1)+' / '+str(len(archives)))
   p=cache/(key+'.index')
   if not p.is_file():missing.append(key);continue
   try:
    if p.stat().st_size>PER_INDEX:raise CatalogError('index_size_limit')
    matches(p.read_bytes(),key,{},cancel=cancel);report['valid_cached_indexes']+=1
   except (CatalogError,OSError):
    if cancel.is_set():raise CompletionError('cancelled')
    report['invalid_cached_indexes_preserved']+=1
  report['cached_scan_completed']=True;report['missing_indexes_initial']=len(missing)
  if missing:
   report['current_online_version']=online(report,cancel,fetcher);report['pinned_target_matches_current_online']=report['current_online_version']==old['target_version']
  for i,key in enumerate(missing):
   notify('Downloading INDEX ONLY '+str(i+1)+' / '+str(len(missing)))
   data=fetcher(CDN+'/tpr/wow/data/'+key[:2]+'/'+key[2:4]+'/'+key+'.index',PER_INDEX,report,cancel)
   matches(data,key,{},cancel=cancel)
   dest=cache/(key+'.index');temp=out/(key+'.part')
   created=False
   try:
    temp.write_bytes(data)
    # Exclusive create: never replace existing, including another process's cache file.
    with dest.open('xb') as f:
     created=True;f.write(data)
   except FileExistsError:raise CompletionError('cache_changed_existing_file_preserved')
   except OSError:
    # A failed new write may leave an incomplete file; remove only our newly created file.
    if created and dest.exists():dest.unlink()
    raise
   finally:
    if temp.exists():temp.unlink()
   report['new_verified_indexes_saved']+=1
  report['remaining_normal_indexes']=len(archives)-report['valid_cached_indexes']-report['new_verified_indexes_saved']
  if report['remaining_normal_indexes']==0:
   notify('All normal indexes verified. Rebuilding full plan OFFLINE…')
   result,plan_out=rebuild(rp,bi,cancel,notify);report['replan_completed']=True;report['replan_status']=result['status'];report['status']='indexes_completed_and_replanned'
   (out/'Retail-Full-Plan-to-share.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
  else:report['status']='partial_invalid_cache_preserved'
 except Exception as e:
  report['status']='cancelled' if cancel.is_set() else 'stopped_with_verified_progress_preserved'
  report['failure_reason']=('http_'+str(e.code) if isinstance(e,urllib.error.HTTPError) else str(e) if isinstance(e,(CompletionError,CatalogError,full_plan.FullPlanError,common.StageError)) else type(e).__name__)
 finally:
  report['remaining_normal_indexes']=len(archives)-report['valid_cached_indexes']-report['new_verified_indexes_saved'];report['checked_at_utc']=datetime.now(timezone.utc).isoformat()
  (out/'Retail-Index-Completion-to-share.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
 return report,out
