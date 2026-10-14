"""Single exact target object, HTTPS only, staging only. Not an installer."""
import io,json,os,sqlite3,shutil,time,urllib.request,urllib.error,urllib.parse
from pathlib import Path
from datetime import datetime,timezone
import common,indexes,metadata
from encoding import EncodingTable,EncodingError
from payload import verify,PayloadError,MAX_DECODED
CAP=8*1024*1024
META_CAP=256*1024
VERSIONS='https://eu.version.battle.net/v2/products/wow/versions'
CDNS='https://eu.version.battle.net/v2/products/wow/cdns'
CDN='https://level3.ssl.blizzard.com'
class PilotError(Exception):pass
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,req,fp,code,msg,headers,newurl):raise PilotError('redirect_rejected')
def opener():return urllib.request.build_opener(NoRedirect())
def request(url):
 return urllib.request.Request(url,headers={'User-Agent':'WoW-Retail-Limited-CDN-Pilot/0.7','Accept-Encoding':'identity'})
def check_response(response,expected=None):
 if response.status!=200:raise PilotError('unexpected_http_status')
 if response.headers.get('Content-Encoding','identity').lower() not in ('identity',''):raise PilotError('unexpected_http_compression')
 length=response.headers.get('Content-Length')
 if length is not None:
  try:n=int(length)
  except ValueError:raise PilotError('invalid_content_length')
  if n<0 or (expected is not None and n!=expected):raise PilotError('content_length_mismatch')
 return None if length is None else n
def text_fetch(url,cancel):
 if cancel.is_set():raise PilotError('cancelled')
 with opener().open(request(url),timeout=30) as response:
  length=check_response(response)
  if length is not None and length>=META_CAP:raise PilotError('metadata_size_limit')
  parts=[];total=0;deadline=time.monotonic()+60
  while True:
   if cancel.is_set():raise PilotError('cancelled')
   if time.monotonic()>deadline:raise PilotError('metadata_time_limit')
   b=response.read(min(65536,META_CAP-total))
   if not b:break
   parts.append(b);total+=len(b)
   if total>=META_CAP:raise PilotError('metadata_size_limit')
  return b''.join(parts).decode('utf-8-sig')
def online(cancel):
 cdn=common.one([r for r in common.rows(text_fetch(CDNS,cancel)) if r.get('Name')=='eu'])
 if cdn.get('Path')!='tpr/wow':raise PilotError('unexpected_cdn_path')
 advertised=[]
 for raw in cdn.get('Servers','').split():
  u=urllib.parse.urlsplit(raw)
  if u.scheme=='https' and u.hostname=='level3.ssl.blizzard.com' and u.port in (None,443) and not u.username and not u.password and u.path in ('','/'):
   advertised.append(CDN)
 if CDN not in advertised:raise PilotError('approved_https_cdn_not_currently_advertised')
 version=common.one([r for r in common.rows(text_fetch(VERSIONS,cancel)) if r.get('Region')=='eu'])
 return version['VersionsName']
def json_read(p):
 if p.stat().st_size>65536:raise PilotError('report_size_limit')
 return json.loads(p.read_text(encoding='utf-8-sig'))
def prepare(report_path,build_info,cancel,notify):
 rp=Path(report_path).resolve();stage=rp.parent.parent;report=json_read(rp)
 if report.get('tool')!='WoW Retail EU Local Payload Diagnostics 0.6' or report.get('status') not in ('payload_verification_completed','payload_verification_completed_with_coverage_gaps'):raise PilotError('select_original_v06_diagnostic_report')
 if report.get('region')!='eu' or report.get('product')!='wow':raise PilotError('unsupported_product_region')
 local=common.local_info(build_info);installation=local['installation']
 if local['version']!=report['local_version']:raise PilotError('installed_build_changed_refresh_reports')
 if stage==installation or stage.is_relative_to(installation) or installation.is_relative_to(stage):raise PilotError('stage_must_be_outside_game')
 prior_path=stage/'Retail-Staging-to-share.json';prior=json_read(prior_path)
 if prior.get('target_version')!=report['target_version'] or prior.get('status')!='sample_downloaded_and_content_verified':raise PilotError('pinned_target_reports_disagree')
 cfg=stage/'build.config';spec=metadata.config(cfg,prior['target_build_config'])
 encoded_meta=stage/'cache/tpr/wow/data'/(spec['ekey']+'.decoded')
 notify('Verifying existing target Encoding metadata locally. No asset download yet.')
 metadata.valid_decoded(encoded_meta,spec,cancel)
 dbpath=rp.parent/'payload-verify-private.sqlite'
 if not dbpath.is_file():raise PilotError('select_original_report_beside_private_database')
 source_paths=[rp,Path(build_info).resolve(),prior_path,cfg,encoded_meta,dbpath]
 snapshots={p:indexes.fingerprint(p) for p in source_paths}
 db=sqlite3.connect(dbpath.as_uri()+'?mode=ro',uri=True);db.execute('PRAGMA query_only=ON')
 try:
  columns=[r[1] for r in db.execute('PRAGMA table_info(checks)')]
  if columns!=['target_ekey','ckey','alternate_ekey','status','reason','target_encoded_bytes','target_advertises_alternate','unsupported_modes_hex']:raise PilotError('unexpected_private_database_schema')
  counts={k:(n,b) for k,n,b in db.execute('SELECT status,count(*),sum(target_encoded_bytes) FROM checks GROUP BY status')}
  if sum(x[0] for x in counts.values())!=report['input_target_candidates']:raise PilotError('candidate_count_mismatch')
  for k,v in report['summary'].items():
   if counts.get(k,(0,0))!=(v['target_objects'],v['associated_target_encoded_bytes']):raise PilotError('report_database_mismatch')
  rows=db.execute("SELECT target_ekey,ckey,target_encoded_bytes,unsupported_modes_hex FROM checks WHERE status='encoded_integrity_only' AND reason='encrypted_mode' AND target_encoded_bytes>0 AND target_encoded_bytes<? ORDER BY target_encoded_bytes,target_ekey",(CAP,)).fetchall()
  rows=[r for r in rows if json.loads(r[3])==['45']]
  if not rows:raise PilotError('no_encrypted_candidate_below_8MiB')
  ek,ck,size,_=rows[0]
  if not all(isinstance(k,bytes) and len(k)==16 for k in (ek,ck)):raise PilotError('invalid_candidate_keys')
 finally:db.close()
 found=None
 with EncodingTable(encoded_meta) as table:
  for k,decoded,eks in table.c_records(cancel,notify):
   if ek in eks:
    if k!=ck or found is not None:raise PilotError('target_ckey_mapping_mismatch')
    found=decoded
  sizes=table.e_sizes({ek},cancel,notify)
 if found is None or not 0<=found<=MAX_DECODED or sizes.get(ek)!=size:raise PilotError('target_size_mapping_mismatch')
 if shutil.disk_usage(stage).free<CAP+1024**2:raise PilotError('insufficient_staging_space')
 ensure_stable(snapshots)
 notify('Checking official EU CDN list and current version (small metadata only).')
 latest=online(cancel)
 ensure_stable(snapshots)
 return {'stage':stage,'snapshots':snapshots,'target_version':report['target_version'],'local_version':local['version'],'current_online_version':latest,'target_ekey':ek,'ckey':ck,'encoded_size':size,'decoded_size':found,'url':CDN+'/tpr/wow/data/'+ek.hex()[:2]+'/'+ek.hex()[2:4]+'/'+ek.hex()}
def ensure_stable(snapshots):
 if any(indexes.fingerprint(p)!=fp for p,fp in snapshots.items()):raise PilotError('source_changed_retry_after_refresh')
def safe_reason(exc):
 if isinstance(exc,urllib.error.HTTPError):return ({404:'direct_object_not_available',403:'direct_object_access_denied'}.get(exc.code,'http_error')),exc.code
 if isinstance(exc,urllib.error.URLError):return 'network_dns_tls_or_connection_error',None
 if isinstance(exc,PayloadError):return exc.reason,None
 if isinstance(exc,PilotError):return str(exc),None
 if isinstance(exc,(TimeoutError,OSError)):return 'network_timeout_or_io_error',None
 return 'unexpected_error',None

def download(plan,cancel,notify):
 ensure_stable(plan['snapshots'])
 expected_url=CDN+'/tpr/wow/data/'+plan['target_ekey'].hex()[:2]+'/'+plan['target_ekey'].hex()[2:4]+'/'+plan['target_ekey'].hex()
 if plan['url']!=expected_url:raise PilotError('unexpected_asset_endpoint')
 if not 0<plan['encoded_size']<CAP:raise PilotError('sample_size_limit')
 output=plan['stage']/('CDN-Pilot-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());output.mkdir()
 part=output/'sample.part';dest=output/'verified-target-sample.blte';received=0;http_status=None;result=None;reason=None
 size=plan['encoded_size']
 if not 0<size<CAP:raise PilotError('sample_size_limit')
 status='download_failed';attempted=False
 try:
  if cancel.is_set():raise PilotError('cancelled')
  attempted=True;notify('Downloading ONE exact target object. No automatic retry; no installation.')
  with opener().open(request(plan['url']),timeout=30) as response:
   http_status=response.status;check_response(response,size);deadline=time.monotonic()+180
   with part.open('xb') as f:
    while True:
     if cancel.is_set():raise PilotError('cancelled')
     if time.monotonic()>deadline:raise PilotError('download_time_limit')
     b=response.read(min(65536,size+1-received))
     if not b:break
     received+=len(b)
     if received>size:raise PilotError('response_exceeds_expected_size')
     f.write(b);notify('Downloaded '+str(received)+' / '+str(size)+' bytes')
    if received!=size:raise PilotError('truncated_download')
  ensure_stable(plan['snapshots'])
  notify('Verifying exact target EKey and every chunk. No saved decoded asset.')
  with part.open('rb') as f:result=verify(f,size,plan['decoded_size'],plan['ckey'],plan['target_ekey'],cancel)
  ensure_stable(plan['snapshots'])
  if cancel.is_set():raise PilotError('cancelled')
  if not result['encoded_integrity_verified']:raise PilotError('encoded_integrity_not_verified')
  part.replace(dest);status='target_sample_downloaded_and_encoded_verified'
 except Exception as exc:
  reason,code=safe_reason(exc)
  if code is not None:http_status=code
  status='cancelled' if reason=='cancelled' else 'download_or_verification_failed'
 finally:
  if part.exists():part.unlink()
 report={'tool':'WoW Retail EU Limited CDN Pilot 0.7','status':status,'checked_at_utc':datetime.now(timezone.utc).isoformat(),'product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'current_online_version':plan['current_online_version'],'pinned_target_matches_current_online_version':plan['target_version']==plan['current_online_version'],'sample_objects_requested':1,'expected_encoded_bytes':size,'sample_response_bytes_read':received,'asset_response_read_limit_bytes':CAP,'metadata_response_read_limit_bytes_per_endpoint':META_CAP,'metadata_endpoints_checked':2,'automatic_retries':0,'asset_download_attempted':attempted,'http_status':http_status,'failure_reason':reason,'encoded_integrity_verified':bool(status=='target_sample_downloaded_and_encoded_verified'),'decoded_ckey_verified':bool(result and result['decoded_ckey_verified'] and status=='target_sample_downloaded_and_encoded_verified'),'unsupported_modes_hex':result.get('unsupported_modes_hex',[]) if result else [],'downloaded_asset_kept':dest.exists(),'sample_executed':False,'decoded_game_assets_saved':False,'installed_files_changed':False,'decryption_attempted':False,'full_update_engine_implemented':False,'limitations':['One exact target EKey only. Not the whole update, not a patch size estimate and not an installed update.','Pinned historical target; current version is displayed but NOT substituted.','8 MiB bounds response bytes read for the one asset including oversize detection; HTTP/TLS overhead and two small metadata responses are additional.','Direct-object URL only. HTTP 403/404 does not prove content absent from CDN archives or a global CDN problem; archive/range fallback is not implemented.','Encoded integrity does not prove decoded CKey for encrypted/unsupported chunks. No decryption or key extraction.','No credentials or personal tags are sent; normal HTTPS requests expose IP address and transport metadata to the contacted servers.'],'sources':['https://wowdev.wiki/TACT','https://wowdev.wiki/BLTE']}
 (output/'Retail-CDN-Pilot-to-share.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
 return report,output
