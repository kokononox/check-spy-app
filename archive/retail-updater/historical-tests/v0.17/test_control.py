import sys,unittest,tempfile,sqlite3,json,threading,hashlib,io,urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,'/data/wow-stoptest-v017/package')
import progressive as p
STOP=threading.Event();BUILD='22'*16
class Response(io.BytesIO):
 def __init__(self,b,status=200,headers=None):super().__init__(b);self.status=status;self.headers=headers or {};self.reads=0
 def read(self,n=-1):self.reads+=1;return super().read(n)
class Network:
 def __init__(self,items,bodies,fail=None):self.items=items;self.bodies=bodies;self.fail=fail;self.calls=[]
 def open(self,req,**kwargs):
  self.calls.append(req);rng=req.get_header('Range');it=next(i for i in self.items if (rng and i.get('offset')==int(rng.split('=')[1].split('-')[0])) or (not rng and req.full_url.endswith(i['ekey'].hex())))
  if len(self.calls)==self.fail:raise urllib.error.HTTPError(req.full_url,403,'synthetic',{},None)
  h={'Content-Length':str(it['bytes'])}
  if rng:h['Content-Range']='bytes '+str(it['offset'])+'-'+str(it['offset']+it['bytes']-1)+'/4294967296'
  return Response(self.bodies[it['ekey']],206 if rng else 200,h)
class Tests(unittest.TestCase):
 def fixture(self,t,large_direct=False):
  stage=Path(t);rp=stage/'CDN-Batch-original/report.json';rp.parent.mkdir();rp.write_text('{}');bi=stage/'synthetic-info';bi.write_text('fixture');(stage/'build.config').write_text('fixture');(stage/'Retail-Staging-to-share.json').write_text(json.dumps({'target_build_config':BUILD}));out=stage/'plan';out.mkdir();db=sqlite3.connect(out/'full-plan-private.sqlite');db.execute('CREATE TABLE candidate(ekey BLOB,bytes INTEGER,ckey BLOB,decoded_size INTEGER,transport_class TEXT,metadata_status TEXT)');db.execute('CREATE TABLE location(ekey BLOB,route TEXT,archive TEXT,offset INTEGER,bytes INTEGER)');items=[];bodies={}
  for i in range(32):
   body=bytes([65+i])*(2100000+i if large_direct and i>=16 else 40+i);block=b'N'+body;h=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+len(body).to_bytes(4,'big')+hashlib.md5(block).digest();b=h+block;it={'route':'archive' if i<16 else 'direct','ekey':hashlib.md5(h).digest(),'ckey':hashlib.md5(body).digest(),'bytes':len(b),'decoded_size':len(body)}
   if i<16:it.update(archive='11'*16,offset=100+i*500)
   items.append(it);bodies[it['ekey']]=b;db.execute('INSERT INTO candidate VALUES (?,?,?,?,?,?)',(it['ekey'],it['bytes'],it['ckey'],it['decoded_size'],'archive_range_location_known' if i<16 else 'advertised_direct_only','mapped'))
   if i<16:db.execute('INSERT INTO location VALUES (?,?,?,?,?)',(it['ekey'],'archive_range',it['archive'],it['offset'],it['bytes']))
  db.commit();db.close()
  for version,known in [('015',items[:4]+items[16:20]),('016',items[4:8]+items[20:24])]:
   seed=stage/('Queue-v'+version)/BUILD/'objects';seed.mkdir(parents=True)
   for it in known:(seed/(it['ekey'].hex()+'.blte')).write_bytes(bodies[it['ekey']])
  (stage/'Queue-v016'/BUILD/'progress-private.json').write_text('original v0.16 state unchanged')
  return stage,rp,bi,out,items,bodies,{'status':'global_candidate_plan_completed','local_version':'synthetic-old','target_version':'synthetic-target'}
 def run_case(self,f,net=None,stop=STOP,notify=lambda _:None):
  net=net or Network(f[4],f[5])
  with patch.object(p.full_plan,'run',return_value=(f[6],f[3])),patch.object(p.q.net,'online',return_value='synthetic-target'),patch.object(p.q.net.urllib.request,'build_opener') as op:
   op.return_value.open=net.open;r,o=p.run(f[1],f[2],stop,notify)
  return r,o,net
 def state(self,f):return f[0]/'Queue-v017'/BUILD/'progress-private.json'
 def test_pause_two_resume_six_and_no_third_batch(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);original={x:hashlib.sha256(x.read_bytes()).digest() for x in f[0].rglob('*') if x.is_file()};r,o,net=self.run_case(f);self.assertEqual(r['status'],'controlled_pause_with_progress_preserved');self.assertEqual(r['new_verified_objects_saved'],2);self.assertTrue(r['controlled_pause_triggered']);self.assertFalse(r['controlled_resume_test_complete']);self.assertEqual(len(net.calls),2);state=json.loads(self.state(f).read_text());self.assertTrue(state['controlled_pause_reached']);self.assertFalse(state['active_queue_complete_by_current_hash_checks']);self.assertEqual(r['prior_cache_verification']['known_verified_objects'],16)
   r2,o2,net2=self.run_case(f);self.assertEqual(r2['selection_mode'],'resume_previous_incomplete_batch');self.assertEqual(r2['selected_queue_objects'],6);self.assertEqual(r2['previous_active_objects_already_verified'],2);self.assertEqual(r2['new_verified_objects_saved'],6);self.assertEqual(len(net2.calls),6);self.assertTrue(r2['controlled_resume_test_complete']);self.assertFalse(r2['controlled_pause_triggered']);state2=json.loads(self.state(f).read_text());self.assertEqual(state['active_queue_keys'],state2['active_queue_keys']);self.assertTrue(state2['active_queue_complete_by_current_hash_checks'])
   r3,o3,net3=self.run_case(f);self.assertEqual(r3['status'],'controlled_stop_resume_test_already_completed');self.assertTrue(r3['controlled_resume_test_complete']);self.assertEqual(net3.calls,[]);self.assertFalse(r3['network_access_attempted']);self.assertEqual(r3['candidate_objects_not_in_reverified_queue_cache'],8);self.assertTrue(all(hashlib.sha256(x.read_bytes()).digest()==h for x,h in original.items()))
 def test_large_direct_responses_on_second_stage(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t,large_direct=True);r,o,net=self.run_case(f);self.assertEqual(r['new_verified_objects_saved'],2);r2,o2,net2=self.run_case(f);self.assertTrue(r2['controlled_resume_test_complete']);self.assertEqual(r2['decoded_ckey_verified_objects'],6);self.assertGreater(r2['asset_response_bytes_read'],8*1024*1024);self.assertLess(r2['asset_response_bytes_read'],p.q.CAP)
 def test_network_failure_before_pause_then_one_more_to_reach_target(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);r,o,net=self.run_case(f,Network(f[4],f[5],fail=2));self.assertEqual(r['new_verified_objects_saved'],1);self.assertFalse(r['controlled_pause_triggered']);self.assertFalse(json.loads(self.state(f).read_text())['controlled_pause_reached']);r2,o2,net2=self.run_case(f);self.assertEqual(r2['new_verified_objects_saved'],1);self.assertTrue(r2['controlled_pause_triggered']);self.assertEqual(len(net2.calls),1);r3,o3,net3=self.run_case(f);self.assertTrue(r3['controlled_resume_test_complete']);self.assertEqual(r3['new_verified_objects_saved'],6)
 def test_failure_during_resume_preserves_test_phase(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);self.run_case(f);r,o,net=self.run_case(f,Network(f[4],f[5],fail=3));self.assertTrue(r['controlled_pause_previously_reached']);self.assertEqual(r['new_verified_objects_saved'],2);self.assertFalse(r['controlled_resume_test_complete']);r2,o2,net2=self.run_case(f);self.assertEqual(r2['selected_queue_objects'],4);self.assertTrue(r2['controlled_resume_test_complete']);self.assertFalse(r2['controlled_pause_triggered'])
 def test_missing_pause_marker_recovered_from_real_files(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);self.run_case(f);sp=self.state(f);state=json.loads(sp.read_text());state['controlled_pause_reached']=False;sp.write_text(json.dumps(state));r,o,net=self.run_case(f);self.assertTrue(r['pause_marker_recovered_from_verified_files']);self.assertTrue(r['controlled_resume_test_complete']);self.assertEqual(r['new_verified_objects_saved'],6)
 def test_cancel_before_two_keeps_active_queue(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);net=Network(f[4],f[5]);stop=threading.Event()
   def notify(msg):
    if len(net.calls)==1:stop.set()
   r,o,_=self.run_case(f,net,stop,notify);self.assertEqual(r['new_verified_objects_saved'],1);self.assertFalse(r['controlled_pause_triggered']);self.assertFalse((f[0]/'Queue-v017'/BUILD/'queue.lock').exists());r2,o2,_=self.run_case(f);self.assertTrue(r2['controlled_pause_triggered']);self.assertEqual(r2['new_verified_objects_saved'],1)
 def test_invalid_phase_preserved(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);r,o,_=self.run_case(f);sp=self.state(f);state=json.loads(sp.read_text());state['controlled_pause_reached']='yes';text=json.dumps(state);sp.write_text(text);r2,o2,net=self.run_case(f);self.assertEqual(sp.read_text(),text);self.assertEqual(r2['failure_reason'],'invalid_test_phase_preserved');self.assertEqual(net.calls,[])
 def test_stale_lock_preserved(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);root=f[0]/'Queue-v017'/BUILD;root.mkdir(parents=True);lock=root/'queue.lock';lock.write_text('other-owner');r,o,net=self.run_case(f);self.assertEqual(lock.read_text(),'other-owner');self.assertFalse(r['network_access_attempted'])
 def test_need_three_objects_no_download(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);db=sqlite3.connect(f[3]/'full-plan-private.sqlite');db.execute('DELETE FROM candidate WHERE ekey NOT IN (?,?)',(f[4][8]['ekey'],f[4][9]['ekey']));db.commit();db.close();r,o,net=self.run_case(f);self.assertEqual(r['failure_reason'],'need_at_least_three_eligible_objects_for_stop_resume_test');self.assertEqual(net.calls,[])
 def test_corrupt_cache_preserved_and_no_network(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);x=next((f[0]/'Queue-v016'/BUILD/'objects').glob('*.blte'));x.write_bytes(b'bad');r,o,net=self.run_case(f);self.assertEqual(x.read_bytes(),b'bad');self.assertEqual(net.calls,[])
 def test_share_report_no_private_ids(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);r,o,_=self.run_case(f);text=(o/'Retail-Controlled-Resume-to-share.json').read_text();self.assertNotIn(str(f[0]),text);self.assertNotIn(f[4][8]['ekey'].hex(),text);self.assertFalse(r['installed_files_changed']);self.assertFalse(r['decoded_game_assets_saved'])
 def test_scan_cap_stops_before_request(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t)
   with patch.object(p,'MAX_CACHE_FILES',1):r,o,net=self.run_case(f)
   self.assertEqual(r['failure_reason'],'cache_scan_limit_no_network_started');self.assertEqual(net.calls,[])
 def stats(self):return {'asset_requests_attempted':0,'asset_response_bytes_read':0}
 def test_range200_reject_before_body(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);it=f[4][0];r=Response(f[5][it['ekey']],200)
   with self.assertRaises(p.q.SampleError):p.q.transfer(it,self.stats(),STOP,lambda *a,**k:r)
   self.assertEqual(r.reads,0)
 def test_direct206_reject_before_body(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);it=f[4][-1];r=Response(f[5][it['ekey']],206)
   with self.assertRaises(p.q.SampleError):p.q.transfer(it,self.stats(),STOP,lambda *a,**k:r)
   self.assertEqual(r.reads,0)
 def test_overrun_and_request_caps(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);it=f[4][-1];r=Response(f[5][it['ekey']]+b'X'*100,200);stats=self.stats()
   with self.assertRaises(p.q.SampleError):p.q.transfer(it,stats,STOP,lambda *a,**k:r)
   self.assertEqual(stats['asset_response_bytes_read'],it['bytes']+1)
   for k,v in [('asset_requests_attempted',8),('asset_response_bytes_read',p.q.CAP)]:
    stats=self.stats();stats[k]=v
    with self.assertRaises(p.q.SampleError):p.q.transfer(it,stats,STOP)
 def test_redirects_rejected(self):
  with self.assertRaises(p.q.net.CompletionError):p.q.net.NoRedirect().redirect_request(None,None,302,'',{},'https://example.com')
if __name__=='__main__':unittest.main()
