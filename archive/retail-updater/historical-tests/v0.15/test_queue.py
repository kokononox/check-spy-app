import sys,unittest,tempfile,io,hashlib,threading,sqlite3,json,urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,'/data/wow-queue-v015/package')
import queue_engine as q
STOP=threading.Event()
def case(n=8,large=False):
 items=[];bodies={}
 for i in range(n):
  body=(bytes([65+i])*(2100000+i*100 if large and i>=n//2 else 40+i));block=b'N'+body;header=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+len(body).to_bytes(4,'big')+hashlib.md5(block).digest();blob=header+block;it={'route':'archive' if i<n//2 else 'direct','ekey':hashlib.md5(header).digest(),'ckey':hashlib.md5(body).digest(),'bytes':len(blob),'decoded_size':len(body)}
  if it['route']=='archive':it.update(archive='11'*16,offset=100+i*500)
  items.append(it);bodies[it['ekey']]=blob
 return items,bodies
class Response(io.BytesIO):
 def __init__(self,b,status=200,headers=None):super().__init__(b);self.status=status;self.headers=headers or {};self.reads=0
 def read(self,n=-1):self.reads+=1;return super().read(n)
class Network:
 def __init__(self,items,bodies,fail=None,code=403,corrupt=False):self.items=items;self.bodies=bodies;self.fail=fail;self.code=code;self.corrupt=corrupt;self.calls=[];self.responses=[]
 def open(self,req,**kwargs):
  self.calls.append(req);rng=req.get_header('Range');it=next(i for i in self.items if (rng and i.get('offset')==int(rng.split('=')[1].split('-')[0])) or (not rng and req.full_url.endswith(i['ekey'].hex())))
  if self.fail==len(self.calls) and not self.corrupt:raise urllib.error.HTTPError(req.full_url,self.code,'failure',{},None)
  b=self.bodies[it['ekey']]
  if self.fail==len(self.calls) and self.corrupt:b=b[:-1]+bytes([b[-1]^1])
  h={'Content-Length':str(len(b))}
  if rng:h['Content-Range']='bytes '+str(it['offset'])+'-'+str(it['offset']+len(b)-1)+'/4294967296'
  r=Response(b,206 if rng else 200,h);self.responses.append(r);return r
class Tests(unittest.TestCase):
 def report(self):return {'items':[],'asset_requests_attempted':0,'asset_response_bytes_read':0,'new_verified_objects_saved':0,'verified_queue_cache_reused':0,'verified_previous_files_imported':0}
 def test_both_routes_large_samples_and_resume_no_network(self):
  items,b=case(8,True);net=Network(items,b);ready=[];snap=[]
  with tempfile.TemporaryDirectory() as t:
   r=self.report();q.execute(items,Path(t),r,STOP,lambda _:None,net.open,before_network=lambda:ready.append(True),persist=lambda:snap.append(json.dumps(r)))
   self.assertEqual(r['status'],'bounded_queue_completed');self.assertEqual(r['decoded_ckey_verified_objects'],8);self.assertEqual(len(ready),1);self.assertEqual(len(net.calls),8);self.assertLess(r['asset_response_bytes_read'],q.CAP);self.assertGreater(len(snap),8)
   r2=self.report()
   def no_net():raise AssertionError('no network with complete queue')
   q.execute(items,Path(t),r2,STOP,lambda _:None,before_network=no_net);self.assertEqual(r2['verified_queue_cache_reused'],8);self.assertEqual(r2['asset_requests_attempted'],0);self.assertEqual(r2['verified_reused_queue_bytes'],sum(i['bytes'] for i in items));self.assertTrue(r2['verified_byte_categories_reconcile'])
 def test_failure_preserves_progress_and_restarts_at_missing(self):
  items,b=case();net=Network(items,b,fail=3)
  with tempfile.TemporaryDirectory() as t:
   r=self.report();q.execute(items,Path(t),r,STOP,lambda _:None,net.open);self.assertEqual(r['encoded_verified_objects'],2);self.assertEqual(r['items'][2]['http_status'],403);self.assertEqual(len(net.calls),3);self.assertEqual(r['items'][3]['status'],'not_attempted_after_stop');self.assertEqual(len(list(Path(t).iterdir())),2)
   net2=Network(items,b);r2=self.report();q.execute(items,Path(t),r2,STOP,lambda _:None,net2.open);self.assertEqual(r2['verified_queue_cache_reused'],2);self.assertEqual(len(net2.calls),6);self.assertEqual(r2['status'],'bounded_queue_completed')
 def test_previous_pilot_import_preserves_sources(self):
  items,b=case();net=Network(items,b)
  with tempfile.TemporaryDirectory() as t:
   seed=Path(t)/'previous';seed.mkdir();store=Path(t)/'new';store.mkdir();original={}
   for it in [items[0],items[1],items[4]]:
    p=seed/(it['ekey'].hex()+'.blte');p.write_bytes(b[it['ekey']]);original[p]=p.read_bytes()
   r=self.report();q.execute(items,store,r,STOP,lambda _:None,net.open,seed_dirs=[seed]);self.assertEqual(r['verified_previous_files_imported'],3);self.assertEqual(r['new_verified_objects_saved'],5);self.assertTrue(all(p.read_bytes()==v for p,v in original.items()));self.assertEqual(len(net.calls),5)
 def test_invalid_seed_and_invalid_queue_preserved(self):
  items,b=case(2)
  for existing in ['seed','queue']:
   with tempfile.TemporaryDirectory() as t:
    store=Path(t)/'queue';store.mkdir();seed=Path(t)/'seed';seed.mkdir();p=(store if existing=='queue' else seed)/(items[0]['ekey'].hex()+'.blte');p.write_bytes(b'invalid');r=self.report();q.execute(items,store,r,STOP,lambda _:None,seed_dirs=[seed]);self.assertEqual(r['asset_requests_attempted'],0);self.assertEqual(p.read_bytes(),b'invalid');self.assertEqual(r['status'],'queue_stopped_with_progress_preserved')
 def test_cancel_after_first_preserves_file(self):
  items,b=case();net=Network(items,b);stop=threading.Event()
  def persist():
   if r.get('new_verified_objects_saved')==1:stop.set()
  with tempfile.TemporaryDirectory() as t:
   r=self.report();q.execute(items,Path(t),r,stop,lambda _:None,net.open,persist=persist);self.assertEqual(len(list(Path(t).iterdir())),1);self.assertEqual(r['status'],'queue_cancelled_with_progress_preserved');self.assertEqual(r['items'][2]['status'],'not_attempted_after_stop')
 def test_archive200_rejected_no_body(self):
  it,b=case();response=Response(b[it[0]['ekey']],200)
  with self.assertRaises(q.SampleError):q.transfer(it[0],self.report(),STOP,lambda *a,**k:response)
  self.assertEqual(response.reads,0)
 def test_bad_range_and_compression_no_body(self):
  it,b=case();i=it[0]
  for h in [{'Content-Range':'bytes 0-1/99'},{'Content-Range':'bytes '+str(i['offset'])+'-'+str(i['offset']+i['bytes']-1)+'/999999','Content-Encoding':'gzip'}]:
   r=Response(b[i['ekey']],206,h)
   with self.assertRaises(q.SampleError):q.transfer(i,self.report(),STOP,lambda *a,**k:r)
   self.assertEqual(r.reads,0)
 def test_direct206_rejected_no_body(self):
  it,b=case();i=it[-1];r=Response(b[i['ekey']],206)
  with self.assertRaises(q.SampleError):q.transfer(i,self.report(),STOP,lambda *a,**k:r)
  self.assertEqual(r.reads,0)
 def test_overrun_probe(self):
  it,b=case();i=it[-1];r=Response(b[i['ekey']]+b'XX'*100,200);stats=self.report()
  with self.assertRaises(q.SampleError):q.transfer(i,stats,STOP,lambda *a,**k:r)
  self.assertEqual(stats['asset_response_bytes_read'],i['bytes']+1)
 def test_short_response(self):
  it,b=case();i=it[-1]
  with self.assertRaises(q.SampleError):q.transfer(i,self.report(),STOP,lambda *a,**k:Response(b[i['ekey']][:-1]))
 def test_request_and_byte_caps(self):
  it,b=case()
  for k,v in [('asset_requests_attempted',8),('asset_response_bytes_read',q.CAP)]:
   r=self.report();r[k]=v
   with self.assertRaises(q.SampleError):q.transfer(it[-1],r,STOP)
 def test_corrupt_response_not_saved(self):
  it,b=case();net=Network(it,b,fail=2,corrupt=True)
  with tempfile.TemporaryDirectory() as t:
   r=self.report();q.execute(it,Path(t),r,STOP,lambda _:None,net.open);self.assertEqual(len(list(Path(t).iterdir())),1);self.assertEqual(len(net.calls),2)
 def test_sources_changed_no_requests(self):
  it,b=case();net=Network(it,b)
  def changed():raise q.SampleError('source_changed')
  with tempfile.TemporaryDirectory() as t:
   r=self.report();q.execute(it,Path(t),r,STOP,lambda _:None,net.open,stable=changed);self.assertEqual(net.calls,[])
 def db(self,path=':memory:'):
  db=sqlite3.connect(path);db.execute('CREATE TABLE candidate(ekey BLOB,bytes INTEGER,ckey BLOB,decoded_size INTEGER,transport_class TEXT,metadata_status TEXT)');db.execute('CREATE TABLE location(ekey BLOB,route TEXT,archive TEXT,offset INTEGER,bytes INTEGER)');return db
 def insert(self,db,items):
  for it in items:
   db.execute('INSERT INTO candidate VALUES (?,?,?,?,?,?)',(it['ekey'],it['bytes'],it['ckey'],it['decoded_size'],'archive_range_location_known' if it['route']=='archive' else 'advertised_direct_only','mapped'))
   if it['route']=='archive':db.execute('INSERT INTO location VALUES (?,?,?,?,?)',(it['ekey'],'archive_range',it['archive'],it['offset'],it['bytes']))
  db.commit()
 def test_selection_balanced_and_reserves_all_probe_bytes(self):
  it,b=case();it=[dict(i,bytes=q.MAX_OBJECT) for i in it];db=self.db();self.insert(db,it);selected,counts=q.select(db);self.assertEqual(len(selected),4);self.assertEqual(sum(i['route']=='archive' for i in selected),2);self.assertLessEqual(sum(i['bytes']+1 for i in selected),q.CAP);self.assertEqual(counts,{'archive':4,'direct':4});db.close()
 def test_eight_selected_and_decoded_cap_filter(self):
  it,b=case(10);it[0]['decoded_size']=q.MAX_DECODE+1;it[-1]['bytes']=q.MAX_OBJECT+1;db=self.db();self.insert(db,it);selected,counts=q.select(db);self.assertEqual(len(selected),8);self.assertEqual(counts,{'archive':4,'direct':4});db.close()
 def test_progress_counters_reconcile(self):
  it,b=case();net=Network(it,b)
  with tempfile.TemporaryDirectory() as t:
   r=self.report();q.execute(it,Path(t),r,STOP,lambda _:None,net.open);self.assertEqual(r['encoded_verified_objects'],r['new_verified_objects_saved']+r['verified_queue_cache_reused']+r['verified_previous_files_imported'])
 def test_full_run_report_and_private_manifest(self):
  it,b=case(2);net=Network(it,b)
  with tempfile.TemporaryDirectory() as t:
   stage=Path(t);rp=stage/'CDN-Batch-original/report.json';rp.parent.mkdir();rp.write_text('{}');bi=stage/'synthetic-info';bi.write_text('fixture');(stage/'build.config').write_text('fixture');build='22'*16;(stage/'Retail-Staging-to-share.json').write_text(json.dumps({'target_build_config':build}));out=stage/'plan';out.mkdir();db=self.db(str(out/'full-plan-private.sqlite'));self.insert(db,it);db.close();plan={'status':'global_candidate_plan_completed','local_version':'synthetic-old','target_version':'synthetic-new'}
   with patch.object(q.full_plan,'run',return_value=(plan,out)),patch.object(q.net,'online',return_value='synthetic-new'),patch.object(q.net.urllib.request,'build_opener') as op:
    op.return_value.open=net.open;r,o=q.run(rp,bi,STOP,lambda _:None)
   self.assertEqual(r['status'],'bounded_queue_completed');self.assertTrue((o/'queue-private.json').exists());text=(o/'Retail-Queue-to-share.json').read_text();self.assertNotIn(str(stage),text);self.assertNotIn(it[0]['ekey'].hex(),text);self.assertFalse(r['installed_files_changed']);self.assertFalse(r['decoded_game_assets_saved']);self.assertTrue(r['network_access_attempted'])
 def test_concurrent_file_not_overwritten(self):
  it,b=case(2);net=Network(it,b)
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/(it[0]['ekey'].hex()+'.blte')
   def op(*a,**k):p.write_bytes(b'other-process');return net.open(*a,**k)
   r=self.report();q.execute(it,Path(t),r,STOP,lambda _:None,op);self.assertEqual(p.read_bytes(),b'other-process');self.assertEqual(r['new_verified_objects_saved'],0)
 def test_opaque_not_claimed_decoded(self):
  it,b=case(2);i=it[0];block=b'Eopaque';h=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+i['decoded_size'].to_bytes(4,'big')+hashlib.md5(block).digest();i.update(ekey=hashlib.md5(h).digest(),bytes=len(h+block));b[i['ekey']]=h+block;net=Network(it,b)
  with tempfile.TemporaryDirectory() as t:
   r=self.report();q.execute(it,Path(t),r,STOP,lambda _:None,net.open);self.assertEqual(r['encoded_verified_objects'],2);self.assertEqual(r['decoded_ckey_verified_objects'],1)
 def test_redirect_rejected(self):
  with self.assertRaises(q.net.CompletionError):q.net.NoRedirect().redirect_request(None,None,302,'',{},'https://example.com')
if __name__=='__main__':unittest.main()
