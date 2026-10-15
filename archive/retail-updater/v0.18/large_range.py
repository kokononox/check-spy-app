"""One >=1 MiB verified target representation, strict Range, staging only."""
import json,sqlite3,hashlib,os
from pathlib import Path
from datetime import datetime,timezone
import queue_engine as q,full_plan,common
MIN_ENCODED=1024*1024
class LargeRangeError(q.SampleError):pass

def select(db):
 params=(MIN_ENCODED,q.MAX_OBJECT,q.MAX_DECODE)
 count=db.execute('SELECT count(*) FROM candidate WHERE transport_class="archive_range_location_known" AND metadata_status="mapped" AND bytes>=? AND bytes<=? AND decoded_size>=0 AND decoded_size<=?',params).fetchone()[0]
 row=db.execute('SELECT ekey,bytes,ckey,decoded_size FROM candidate WHERE transport_class="archive_range_location_known" AND metadata_status="mapped" AND bytes>=? AND bytes<=? AND decoded_size>=0 AND decoded_size<=? ORDER BY bytes,ekey LIMIT 1',params).fetchone()
 if row is None:return [],count
 ek,n,ck,ds=row
 if not isinstance(ek,bytes) or len(ek)!=16 or not isinstance(ck,bytes) or len(ck)!=16:raise LargeRangeError('invalid_target_key_metadata')
 loc=db.execute('SELECT archive,offset,bytes FROM location WHERE ekey=? AND route="archive_range" ORDER BY archive,offset LIMIT 1',(ek,)).fetchone()
 if loc is None or not common.HEX.fullmatch(loc[0]) or loc[2]!=n or not 0<=loc[1]<=2**32-n:raise LargeRangeError('invalid_target_archive_range')
 return [{'route':'archive','ekey':ek,'bytes':n,'ckey':ck,'decoded_size':ds,'archive':loc[0],'offset':loc[1]}],count

def run(rp,bi,cancel,notify):
 notify('Fresh OFFLINE plan before selecting one larger archive object.')
 plan,planout=full_plan.run(rp,bi,cancel,notify)
 if plan['status']!='global_candidate_plan_completed':raise LargeRangeError('fresh_plan_partial_no_range_request')
 stage=Path(rp).resolve().parent.parent;prior=full_plan.read_report(stage/'Retail-Staging-to-share.json');build=prior['target_build_config'];root=stage/'Large-Range-v018'/build;store=root/'objects';store.mkdir(parents=True,exist_ok=True)
 if not store.resolve().is_relative_to(stage):raise LargeRangeError('sample_store_outside_stage')
 out=root/('Run-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());out.mkdir()
 report={'tool':'WoW Retail EU Larger Archive Range Pilot 0.18','status':'preparing','product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'selected_queue_objects':0,'planned_encoded_bytes':0,'minimum_encoded_bytes':MIN_ENCODED,'maximum_encoded_bytes':q.MAX_OBJECT,'maximum_decoded_bytes':q.MAX_DECODE,'asset_response_read_cap_bytes':q.CAP,'asset_request_cap':1,'asset_requests_attempted':0,'asset_response_bytes_read':0,'strict_range_headers_verified':False,'verified_queue_cache_reused':0,'verified_previous_files_imported':0,'new_verified_objects_saved':0,'items':[],'metadata':{'requests_attempted':0,'response_bytes_read':0,'network_access_attempted':False},'automatic_retries':0,'range_request_attempted':False,'complete_verified_file_reuse_supported':True,'partial_byte_resume_supported':False,'installed_files_changed':False,'decoded_game_assets_saved':False,'assets_executed':False,'decryption_attempted':False,'full_update_engine_implemented':False,'limitations':['One smallest eligible >=1 MiB archive target only, NOT all archive availability or full playable update.','4 MiB asset response-read cap includes one overrun probe; two <256 KiB EU metadata responses, network buffering and HTTP/TLS overhead additional.','206 and exact Content-Range required; 200 full-archive response rejected before body read. No direct fallback, alternate host or retry.','Cached/imported success does not itself demonstrate a new HTTP Range request; request/header flags reported separately.','Opaque target content may have encoded integrity only, not decoded/decrypted; decoded bytes never saved/executed.','No installer/CASC writer/patch chain/rollback.']}
 db=None
 def persist():
  tmp=out/'report.tmp';tmp.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');tmp.replace(out/'Retail-Large-Range-to-share.json')
 try:
  db=sqlite3.connect((planout/'full-plan-private.sqlite').resolve().as_uri()+'?mode=ro',uri=True);items,count=select(db);db.close();db=None
  report.update(eligible_large_archive_objects=count,selected_queue_objects=len(items),planned_encoded_bytes=sum(i['bytes'] for i in items))
  if not items:report['status']='no_large_archive_object_within_caps'
  else:
   sources=[Path(rp).resolve(),Path(bi).resolve(),stage/'Retail-Staging-to-share.json',stage/'build.config'];snaps={p:hashlib.sha256(p.read_bytes()).digest() for p in sources}
   def stable():
    if any(hashlib.sha256(p.read_bytes()).digest()!=h for p,h in snaps.items()):raise LargeRangeError('source_changed')
   def before_network():
    report['current_online_version']=q.net.online(report['metadata'],cancel,q.net.fetch);report['pinned_target_matches_current_online']=report['current_online_version']==plan['target_version'];stable()
   folders=[stage/n/build/'objects' for n in ('Queue-v017','Queue-v016','Queue-v015','Route-Samples-v012','Direct-Sample-v014')]
   if any(folder.exists() and not folder.resolve().is_relative_to(stage) for folder in folders):raise LargeRangeError('previous_sample_folder_outside_stage')
   private=[dict(ekey=i['ekey'].hex(),ckey=i['ckey'].hex(),encoded_bytes=i['bytes'],decoded_bytes=i['decoded_size'],archive=i['archive'],offset=i['offset']) for i in items];(out/'range-private.json').write_text(json.dumps(private,indent=2)+'\n',encoding='utf-8')
   q.execute(items,store,report,cancel,notify,stable=stable,before_network=before_network,seed_dirs=folders,persist=persist)
   report['status']={'bounded_queue_completed':'large_archive_sample_completed','queue_stopped_with_progress_preserved':'large_archive_sample_failed','queue_cancelled_with_progress_preserved':'large_archive_sample_cancelled'}.get(report['status'],report['status'])
 except Exception as e:report.update(status='large_archive_pilot_cancelled' if cancel.is_set() else 'large_archive_pilot_stopped',failure_reason=str(e) if isinstance(e,(LargeRangeError,q.SampleError,q.net.CompletionError,q.PayloadError)) else type(e).__name__)
 finally:
  if db is not None:db.close()
  report['range_request_attempted']=report['asset_requests_attempted']>0;report['network_access_attempted']=bool(report['range_request_attempted'] or report['metadata']['network_access_attempted']);report['range_http_status']=report['items'][0]['http_status'] if report['range_request_attempted'] and report['items'] else None;report['exact_range_response_length_received']=bool(report['strict_range_headers_verified'] and report['asset_response_bytes_read']==report['planned_encoded_bytes']);report['checked_at_utc']=datetime.now(timezone.utc).isoformat();persist()
 return report,out
