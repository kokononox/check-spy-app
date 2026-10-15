import sys,unittest,tempfile,io,hashlib,threading,sqlite3,json,urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,'/data/wow-direct-pilot-v014/package')
import sampler as s
STOP=threading.Event()
def case(size=41):
 body=b'A'*size;block=b'N'+body;header=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+len(body).to_bytes(4,'big')+hashlib.md5(block).digest();blob=header+block
 return {'route':'direct','bytes':len(blob),'decoded_size':len(body),'ekey':hashlib.md5(header).digest(),'ckey':hashlib.md5(body).digest()},blob
class Response(io.BytesIO):
 def __init__(self,b,status=200,headers=None):super().__init__(b);self.status=status;self.headers=headers or {};self.reads=0
 def read(self,n=-1):self.reads+=1;return super().read(n)
class Tests(unittest.TestCase):
 def report(self):return {'samples':[],'asset_requests_attempted':0,'asset_response_bytes_read':0,'new_verified_samples_saved':0,'verified_cached_samples_reused':0}
 def test_large_sample_and_verified_file_reuse(self):
  it,b=case(2200000);calls=[]
  def op(req,**kw):calls.append(req);self.assertIsNone(req.get_header('Range'));self.assertTrue(req.full_url.startswith(s.net.CDN+'/tpr/wow/data/'));return Response(b,headers={'Content-Length':str(len(b))})
  with tempfile.TemporaryDirectory() as t:
   store=Path(t);r=self.report();s.execute([it],store,r,STOP,lambda _:None,op);self.assertEqual(r['status'],'direct_sample_completed');self.assertEqual(r['decoded_ckey_verified_samples'],1);self.assertEqual(r['asset_response_bytes_read'],len(b));self.assertEqual(r['new_verified_samples_saved'],1)
   r2=self.report();s.execute([it],store,r2,STOP,lambda _:None,op);self.assertEqual(len(calls),1);self.assertEqual(r2['verified_cached_samples_reused'],1);self.assertEqual(r2['asset_requests_attempted'],0)
 def test_403_saved_as_failure_no_retry(self):
  it,b=case();calls=[]
  def op(req,**kw):calls.append(req);raise urllib.error.HTTPError(req.full_url,403,'Forbidden',{},None)
  with tempfile.TemporaryDirectory() as t:
   r=self.report();s.execute([it],Path(t),r,STOP,lambda _:None,op);self.assertEqual(r['samples'][0]['http_status'],403);self.assertEqual(r['status'],'direct_sample_failed');self.assertEqual(len(calls),1);self.assertEqual(list(Path(t).iterdir()),[])
 def test_non200_rejected_before_body(self):
  it,b=case()
  for status in [206,302,404]:
   response=Response(b,status);r=self.report()
   with self.assertRaises(s.SampleError):s.transfer(it,r,STOP,lambda *a,**k:response)
   self.assertEqual(response.reads,0)
 def test_length_and_encoding_rejected_before_body(self):
  it,b=case()
  for h in [{'Content-Length':'999'},{'Content-Length':'-1'},{'Content-Length':'text'},{'Content-Encoding':'gzip'}]:
   response=Response(b,headers=h)
   with self.assertRaises(s.SampleError):s.transfer(it,self.report(),STOP,lambda *a,**k:response)
   self.assertEqual(response.reads,0)
 def test_overrun_only_one_probe_byte(self):
  it,b=case();response=Response(b+b'XX'*100);r=self.report()
  with self.assertRaises(s.SampleError):s.transfer(it,r,STOP,lambda *a,**k:response)
  self.assertEqual(r['asset_response_bytes_read'],it['bytes']+1)
 def test_short_response(self):
  it,b=case()
  with self.assertRaises(s.SampleError):s.transfer(it,self.report(),STOP,lambda *a,**k:Response(b[:-1]))
 def test_request_and_response_caps(self):
  it,b=case()
  for k,v in [('asset_requests_attempted',1),('asset_response_bytes_read',s.CAP)]:
   r=self.report();r[k]=v
   with self.assertRaises(s.SampleError):s.transfer(it,r,STOP)
 def test_only_one_direct_route_accepted(self):
  it,b=case()
  with tempfile.TemporaryDirectory() as t:
   for items in [[it,it],[dict(it,route='archive')]]:
    with self.assertRaises(s.SampleError):s.execute(items,Path(t),self.report(),STOP,lambda _:None)
  with self.assertRaises(s.SampleError):s.transfer(dict(it,route='archive'),self.report(),STOP)
 def test_hash_failure_no_file_saved(self):
  it,b=case();bad=b[:-1]+b'B'
  with tempfile.TemporaryDirectory() as t:
   r=self.report();s.execute([it],Path(t),r,STOP,lambda _:None,lambda *a,**k:Response(bad));self.assertEqual(r['encoded_verified_samples'],0);self.assertEqual(list(Path(t).iterdir()),[])
 def test_invalid_cache_preserved(self):
  it,b=case()
  with tempfile.TemporaryDirectory() as t:
   p=Path(t)/(it['ekey'].hex()+'.blte');p.write_bytes(b'bad');r=self.report();s.execute([it],Path(t),r,STOP,lambda _:None);self.assertEqual(p.read_bytes(),b'bad');self.assertEqual(r['asset_requests_attempted'],0)
 def test_cancel_no_request(self):
  it,b=case();stop=threading.Event();stop.set()
  with tempfile.TemporaryDirectory() as t:
   r=self.report();s.execute([it],Path(t),r,stop,lambda _:None);self.assertEqual(r['status'],'cancelled');self.assertEqual(r['asset_requests_attempted'],0)
 def test_source_change_no_request(self):
  it,b=case()
  def changed():raise s.SampleError('source_changed')
  with tempfile.TemporaryDirectory() as t:
   r=self.report();s.execute([it],Path(t),r,STOP,lambda _:None,stable=changed);self.assertEqual(r['asset_requests_attempted'],0);self.assertEqual(r['samples'][0]['failure_reason'],'source_changed')
 def test_opaque_not_claimed_decoded(self):
  it,b=case();block=b'Eopaque';header=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+it['decoded_size'].to_bytes(4,'big')+hashlib.md5(block).digest();b=header+block;it.update(ekey=hashlib.md5(header).digest(),bytes=len(b))
  with tempfile.TemporaryDirectory() as t:
   r=self.report();s.execute([it],Path(t),r,STOP,lambda _:None,lambda *a,**k:Response(b));self.assertEqual(r['encoded_verified_samples'],1);self.assertEqual(r['decoded_ckey_verified_samples'],0)
 def db(self,path=':memory:'):
  db=sqlite3.connect(path);db.execute('CREATE TABLE candidate(ekey BLOB,bytes INTEGER,ckey BLOB,decoded_size INTEGER,transport_class TEXT,metadata_status TEXT)');return db
 def put(self,db,it,route='advertised_direct_only',status='mapped'):db.execute('INSERT INTO candidate VALUES (?,?,?,?,?,?)',(it['ekey'],it['bytes'],it['ckey'],it['decoded_size'],route,status));db.commit()
 def test_selection_uses_one_smallest_and_exact_limits(self):
  db=self.db();it,b=case();self.put(db,dict(it,bytes=s.CAP,ekey=b'1'*16));self.put(db,dict(it,bytes=100,decoded_size=s.MAX_DECODE+1,ekey=b'2'*16));self.put(db,dict(it,bytes=99,ekey=b'3'*16),route='archive_range_location_known');self.put(db,dict(it,bytes=90,ekey=b'4'*16),status='not_checked');self.put(db,dict(it,bytes=2108300,decoded_size=2862812,ekey=b'5'*16));self.put(db,dict(it,bytes=2132658,decoded_size=4773194,ekey=b'6'*16));selected=s.select(db);self.assertEqual(len(selected),1);self.assertEqual(selected[0]['bytes'],2108300);self.assertEqual(selected[0]['decoded_size'],2862812);db.close()
 def test_reserved_probe_boundary_and_no_eligible(self):
  db=self.db();it,b=case();self.put(db,dict(it,bytes=s.CAP));self.assertEqual(s.select(db),[]);self.put(db,dict(it,bytes=s.CAP-1,decoded_size=s.MAX_DECODE,ekey=b'1'*16));self.assertEqual(len(s.select(db)),1);db.close()
 def test_concurrent_sample_not_overwritten(self):
  it,b=case()
  with tempfile.TemporaryDirectory() as t:
   dest=Path(t)/(it['ekey'].hex()+'.blte')
   def op(*args,**kw):dest.write_bytes(b'other-process');return Response(b)
   r=self.report();s.execute([it],Path(t),r,STOP,lambda _:None,op);self.assertEqual(dest.read_bytes(),b'other-process');self.assertEqual(r['samples'][0]['failure_reason'],'concurrent_sample_preserved')
 def test_full_orchestration_report_privacy(self):
  it,b=case()
  with tempfile.TemporaryDirectory() as t:
   stage=Path(t);folder=stage/'CDN-Batch-original';folder.mkdir();rp=folder/'report.json';rp.write_text('{}');bi=stage/'build-info';bi.write_text('fixture');(stage/'build.config').write_text('fixture');(stage/'Retail-Staging-to-share.json').write_text(json.dumps({'target_build_config':'22'*16}));out=stage/'plan';out.mkdir();db=self.db(str(out/'full-plan-private.sqlite'));self.put(db,it);db.close();plan={'status':'global_candidate_plan_completed','local_version':'synthetic-old','target_version':'synthetic-target'}
   with patch.object(s.full_plan,'run',return_value=(plan,out)),patch.object(s.net,'online',return_value='synthetic-target'),patch.object(s.net.urllib.request,'build_opener') as op:
    op.return_value.open=lambda *a,**k:Response(b);r,o=s.run(rp,bi,STOP,lambda _:None)
   self.assertEqual(r['tool'],'WoW Retail EU Single Direct Pilot 0.14');self.assertEqual(r['status'],'direct_sample_completed');text=(o/'Retail-Direct-Pilot-to-share.json').read_text();self.assertNotIn(str(stage),text);self.assertNotIn(it['ekey'].hex(),text);self.assertFalse(r['installed_files_changed']);self.assertEqual(r['max_selected_samples'],1)
 def test_redirects_rejected(self):
  with self.assertRaises(s.net.CompletionError):s.net.NoRedirect().redirect_request(None,None,302,'',{},'https://example.com')
if __name__=='__main__':unittest.main()
