"""Offline audit of direct-only candidate eligibility. No HTTP/downloader imports."""
import json,sqlite3
from pathlib import Path
from datetime import datetime,timezone
import full_plan
ENCODED_CAP=1024*1024;DECODED_CAP=16*1024*1024
class AuditError(Exception):pass

def analyse(db):
 rows=db.execute('SELECT bytes,decoded_size FROM candidate WHERE transport_class="advertised_direct_only" AND metadata_status="mapped" ORDER BY bytes,decoded_size,ekey').fetchall()
 if any(not isinstance(e,int) or not isinstance(d,int) or e<=0 or d<0 for e,d in rows):raise AuditError('invalid_candidate_sizes')
 groups={k:{'objects':0,'whole_encoded_bytes':0} for k in ['eligible_under_v012_limits','encoded_limit_only','decoded_limit_only','both_limits']}
 for e,d in rows:
  key='eligible_under_v012_limits' if e<=ENCODED_CAP and d<=DECODED_CAP else 'encoded_limit_only' if e>ENCODED_CAP and d<=DECODED_CAP else 'decoded_limit_only' if e<=ENCODED_CAP and d>DECODED_CAP else 'both_limits'
  groups[key]['objects']+=1;groups[key]['whole_encoded_bytes']+=e
 aggregate=db.execute('SELECT count(*),coalesce(sum(bytes),0),min(bytes),max(bytes),min(decoded_size),max(decoded_size) FROM candidate WHERE transport_class="advertised_direct_only" AND metadata_status="mapped"').fetchone()
 if sum(x['objects'] for x in groups.values())!=aggregate[0] or sum(x['whole_encoded_bytes'] for x in groups.values())!=aggregate[1]:raise AuditError('independent_reconciliation_failed')
 def record(e,d):return {'encoded_bytes':e,'decoded_bytes':d,'fits_v012_encoded_limit':e<=ENCODED_CAP,'fits_v012_decoded_limit':d<=DECODED_CAP,'fits_both_v012_limits':e<=ENCODED_CAP and d<=DECODED_CAP}
 least_decoded=sorted(rows,key=lambda r:(r[1],r[0]))
 eligible=[(e,d) for e,d in rows if e<=ENCODED_CAP and d<=DECODED_CAP]
 result={'direct_candidate_objects':aggregate[0],'direct_candidate_whole_encoded_bytes':aggregate[1],'v012_encoded_size_cap_bytes':ENCODED_CAP,'v012_decoded_size_cap_bytes':DECODED_CAP,'eligibility_groups':groups,'size_ranges':{'encoded_min_bytes':aggregate[2],'encoded_max_bytes':aggregate[3],'decoded_min_bytes':aggregate[4],'decoded_max_bytes':aggregate[5]},'smallest_encoded_candidates':[dict(candidate_rank=i+1,**record(e,d)) for i,(e,d) in enumerate(rows[:5])],'smallest_decoded_candidates':[dict(candidate_rank=i+1,**record(e,d)) for i,(e,d) in enumerate(least_decoded[:5])],'smallest_candidate_fitting_both_limits':record(*eligible[0]) if eligible else None,'independent_count_and_byte_check_passed':True,'hypothetical_limit_increase_applied':False}
 result['selection_explanation']='no_direct_candidates_in_current_scope' if not rows else 'v012_limits_exclude_all_direct_candidates' if not eligible else 'eligible_direct_candidates_exist_in_fresh_plan'
 return result

def run(rp,bi,cancel,notify):
 notify('Rebuilding OFFLINE plan from verified cached metadata. No network.')
 plan,out=full_plan.run(rp,bi,cancel,notify)
 if cancel.is_set():raise AuditError('cancelled')
 db=sqlite3.connect((out/'full-plan-private.sqlite').resolve().as_uri()+'?mode=ro',uri=True)
 try:
  db.set_progress_handler(lambda:1 if cancel.is_set() else 0,10000);result=analyse(db)
 finally:db.close()
 expected=plan['plan']['transport_classes']['advertised_direct_only']
 if (result['direct_candidate_objects'],result['direct_candidate_whole_encoded_bytes'])!=(expected['target_objects'],expected['whole_encoded_bytes']):raise AuditError('fresh_plan_audit_disagree')
 if cancel.is_set():raise AuditError('cancelled')
 report={'tool':'WoW Retail EU Offline Direct Eligibility Audit 0.13','status':'direct_eligibility_audit_completed' if plan['status']=='global_candidate_plan_completed' else 'direct_eligibility_audit_partial_scope','checked_at_utc':datetime.now(timezone.utc).isoformat(),'product':'wow','region':'eu','local_version':plan['local_version'],'target_version':plan['target_version'],'fresh_plan_status':plan['status'],'target_latest_online_checked':False,'scope':'ONLY fresh unmatched mapped direct-only candidates, excluding exact staged copies known to inherited planner','audit':result,'network_access_attempted':False,'game_content_download_attempted':False,'installed_files_changed':False,'game_assets_executed':False,'decoded_game_assets_saved':False,'limits_changed':False,'full_update_engine_implemented':False,'limitations':['Cached manifest and Encoding sizes are authoritative for this audit; no direct HTTP availability tested.','Minimum encoded and minimum decoded ranges may belong to DIFFERENT objects; per-candidate pairs are provided explicitly.','This explains eligibility of the CURRENT fresh plan, not every historical capture or object.','Inherited planner does not count separate v0.12 sample cache as already staged content.','Whole encoded object sums are NOT required download, binary patch or minimal playable size.','No automatic limit increase, request, installer, decryption or game execution.','Private SQLite stays local; share report contains only aggregate counts and anonymous size pairs.']}
 path=out/'Retail-Direct-Eligibility-to-share.json';path.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');return report,out
