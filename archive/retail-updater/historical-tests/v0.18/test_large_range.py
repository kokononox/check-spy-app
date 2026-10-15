import sys,unittest,tempfile,io,sqlite3,hashlib,json,threading,urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,'/data/wow-range-large-v018/package')
import large_range as l
STOP=threading.Event();BUILD='22'*16
class Response(io.BytesIO):
 def __init__(self,b,status=206,headers=None):super().__init__(b);self.status=status;self.headers=headers or {};self.reads=0
 def read(self,n=-1):self.reads+=1;return super().read(n)
def multichunk():
 bodies=[b'A'*1200000,b'B'*1200000];chunks=[b'N'+b for b in bodies];head=b'BLTE'+(60).to_bytes(4,'big')+b'\x0f\0\0\2'+b''.join(len(c).to_bytes(4,'big')+len(b).to_bytes(4,'big')+hashlib.md5(c).digest() for c,b in zip(chunks,bodies));blob=head+b''.join(chunks);return {'route':'archive','ekey':hashlib.md5(head).digest(),'ckey':hashlib.md5(b''.join(bodies)).digest(),'bytes':len(blob),'decoded_size':sum(map(len,bodies)),'archive':'11'*16,'offset':2**30},blob
class Tests(unittest.TestCase):
 def fixture(self,t):
  stage=Path(t);rp=stage/'CDN-Batch-original/report.json';rp.parent.mkdir();rp.write_text('{}');bi=stage/'synthetic-info';bi.write_text('fixture');(stage/'build.config').write_text('fixture');(stage/'Retail-Staging-to-share.json').write_text(json.dumps({'target_build_config':BUILD}));out=stage/'plan';out.mkdir();db=self.db(out/'full-plan-private.sqlite');it,b=multichunk();self.put(db,it);db.close();return stage,rp,bi,out,it,b,{'status':'global_candidate_plan_completed','local_version':'synthetic-old','target_version':'synthetic-target'}
 def db(self,path=':memory:'):
  db=sqlite3.connect(path);db.execute('CREATE TABLE candidate(ekey BLOB,bytes INTEGER,ckey BLOB,decoded_size INTEGER,transport_class TEXT,metadata_status TEXT)');db.execute('CREATE TABLE location(ekey BLOB,route TEXT,archive TEXT,offset INTEGER,bytes INTEGER)');return db
 def put(self,db,it,kind='archive_range_location_known',metadata='mapped'):
  db.execute('INSERT INTO candidate VALUES (?,?,?,?,?,?)',(it['ekey'],it['bytes'],it['ckey'],it['decoded_size'],kind,metadata));db.execute('INSERT INTO location VALUES (?,?,?,?,?)',(it['ekey'],'archive_range',it['archive'],it['offset'],it['bytes']));db.commit()
 def response(self,f,status=206,headers=None,b=None):
  it=f[4];h={'Content-Length':str(it['bytes']),'Content-Range':'bytes '+str(it['offset'])+'-'+str(it['offset']+it['bytes']-1)+'/4294967296'}
  if headers is not None:h=headers
  return Response(f[5] if b is None else b,status,h)
 def run_case(self,f,response=None,opener=None):
  response=response or self.response(f);calls=[]
  def op(req,**kw):calls.append(req);return response
  with patch.object(l.full_plan,'run',return_value=(f[6],f[3])),patch.object(l.q.net,'online',return_value='synthetic-target'),patch.object(l.q.net.urllib.request,'build_opener') as build:
   build.return_value.open=opener or op;r,o=l.run(f[1],f[2],STOP,lambda _:None)
  return r,o,calls
 def test_large_two_chunk_range_success_and_cache_rerun(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);original={p:hashlib.sha256(p.read_bytes()).digest() for p in f[0].rglob('*') if p.is_file()};r,o,calls=self.run_case(f);self.assertEqual(r['status'],'large_archive_sample_completed');self.assertEqual(r['range_http_status'],206);self.assertTrue(r['range_request_attempted']);self.assertTrue(r['strict_range_headers_verified']);self.assertTrue(r['exact_range_response_length_received']);self.assertEqual(r['decoded_ckey_verified_objects'],1);self.assertGreater(r['asset_response_bytes_read'],2*1024*1024);self.assertEqual(len(calls),1);self.assertEqual(calls[0].get_header('Range'),'bytes='+str(f[4]['offset'])+'-'+str(f[4]['offset']+f[4]['bytes']-1));self.assertTrue(all(hashlib.sha256(p.read_bytes()).digest()==h for p,h in original.items()))
   r2,o2,calls2=self.run_case(f);self.assertEqual(r2['verified_queue_cache_reused'],1);self.assertFalse(r2['range_request_attempted']);self.assertFalse(r2['strict_range_headers_verified']);self.assertFalse(r2['network_access_attempted']);self.assertEqual(calls2,[])
 def test_full_archive200_rejected_before_body(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);response=self.response(f,200);r,o,_=self.run_case(f,response);self.assertEqual(response.reads,0);self.assertEqual(r['status'],'large_archive_sample_failed');self.assertEqual(r['asset_response_bytes_read'],0);self.assertFalse(r['strict_range_headers_verified'])
 def test_mismatched_or_invalid_total_range_no_body(self):
  for cr in ['bytes 0-1/99','bytes 1073741824-1076141885/1076141885','bytes 1073741824-1076141885/*']:
   with tempfile.TemporaryDirectory() as t:
    f=self.fixture(t);response=self.response(f,headers={'Content-Range':cr});r,o,_=self.run_case(f,response);self.assertEqual(response.reads,0);self.assertFalse(r['strict_range_headers_verified']);self.assertEqual(r['new_verified_objects_saved'],0)
 def test_wrong_length_or_compression_no_body(self):
  for h in [{'Content-Length':'bad'},{'Content-Encoding':'gzip'},{'Content-Length':'999'}]:
   with tempfile.TemporaryDirectory() as t:
    f=self.fixture(t);it=f[4];h=dict(h,**{'Content-Range':'bytes '+str(it['offset'])+'-'+str(it['offset']+it['bytes']-1)+'/4294967296'});response=self.response(f,headers=h);r,o,_=self.run_case(f,response);self.assertEqual(response.reads,0);self.assertFalse(r['strict_range_headers_verified'])
 def test_oversize_reads_only_one_probe(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);it=f[4];cr='bytes '+str(it['offset'])+'-'+str(it['offset']+it['bytes']-1)+'/4294967296';response=self.response(f,headers={'Content-Range':cr},b=f[5]+b'X'*100);r,o,_=self.run_case(f,response);self.assertEqual(r['asset_response_bytes_read'],it['bytes']+1);self.assertEqual(r['new_verified_objects_saved'],0)
 def test_truncated_body(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);response=self.response(f,b=f[5][:-1]);r,o,_=self.run_case(f,response);self.assertEqual(r['new_verified_objects_saved'],0);self.assertFalse(r['exact_range_response_length_received'])
 def test_corrupt_second_chunk_no_sample_kept(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);response=self.response(f,b=f[5][:-1]+b'X');r,o,_=self.run_case(f,response);self.assertEqual(r['new_verified_objects_saved'],0);self.assertTrue(r['strict_range_headers_verified']);self.assertTrue(r['exact_range_response_length_received']);self.assertEqual(r['encoded_verified_objects'],0)
 def test_http403_no_retry(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);count=[]
   def op(req,**kw):count.append(req);raise urllib.error.HTTPError(req.full_url,403,'synthetic',{},None)
   r,o,_=self.run_case(f,opener=op);self.assertEqual(len(count),1);self.assertEqual(r['range_http_status'],403);self.assertEqual(r['new_verified_objects_saved'],0)
 def test_metadata403_not_reported_as_archive_http(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t)
   with patch.object(l.full_plan,'run',return_value=(f[6],f[3])),patch.object(l.q.net,'online',side_effect=urllib.error.HTTPError('https://eu.version.battle.net/',403,'synthetic',{},None)):
    r,o=l.run(f[1],f[2],STOP,lambda _:None)
   self.assertFalse(r['range_request_attempted']);self.assertIsNone(r['range_http_status'])
 def test_no_eligible_candidate_no_request(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);db=sqlite3.connect(f[3]/'full-plan-private.sqlite');db.execute('UPDATE candidate SET bytes=100');db.commit();db.close();r,o,calls=self.run_case(f);self.assertEqual(r['status'],'no_large_archive_object_within_caps');self.assertEqual(calls,[])
 def test_selection_bounds_and_direct_exclusion(self):
  db=self.db();it,b=multichunk()
  for i,(n,ds,kind,status) in enumerate([(100,100,'archive_range_location_known','mapped'),(l.q.CAP,1,'archive_range_location_known','mapped'),(l.MIN_ENCODED,l.q.MAX_DECODE+1,'archive_range_location_known','mapped'),(l.MIN_ENCODED,1,'advertised_direct_only','mapped'),(l.MIN_ENCODED,1,'archive_range_location_known','not_checked'),(l.MIN_ENCODED+50,1,'archive_range_location_known','mapped'),(l.MIN_ENCODED,1,'archive_range_location_known','mapped')]):self.put(db,dict(it,ekey=bytes([i+1])*16,bytes=n,decoded_size=ds),kind,status)
  selected,count=l.select(db);self.assertEqual(count,2);self.assertEqual(len(selected),1);self.assertEqual(selected[0]['bytes'],l.MIN_ENCODED);db.close()
 def test_invalid_existing_sample_preserved(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);store=f[0]/'Large-Range-v018'/BUILD/'objects';store.mkdir(parents=True);p=store/(f[4]['ekey'].hex()+'.blte');p.write_bytes(b'invalid');r,o,calls=self.run_case(f);self.assertEqual(p.read_bytes(),b'invalid');self.assertEqual(calls,[]);self.assertFalse(r['range_request_attempted'])
 def test_older_exact_sample_import_no_range_claim(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);store=f[0]/'Queue-v016'/BUILD/'objects';store.mkdir(parents=True);p=store/(f[4]['ekey'].hex()+'.blte');p.write_bytes(f[5]);r,o,calls=self.run_case(f);self.assertEqual(r['verified_previous_files_imported'],1);self.assertFalse(r['range_request_attempted']);self.assertEqual(calls,[]);self.assertEqual(p.read_bytes(),f[5])
 def test_opaque_large_payload_not_claimed_decoded(self):
  with tempfile.TemporaryDirectory() as t:
   f=list(self.fixture(t));block=b'E'+b'opaque'*(200000);ds=2000000;head=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+ds.to_bytes(4,'big')+hashlib.md5(block).digest();it=dict(f[4],ekey=hashlib.md5(head).digest(),bytes=len(head+block),decoded_size=ds);f[4]=it;f[5]=head+block;db=sqlite3.connect(f[3]/'full-plan-private.sqlite');db.execute('DELETE FROM candidate');db.execute('DELETE FROM location');self.put(db,it);db.close();r,o,_=self.run_case(f);self.assertEqual(r['status'],'large_archive_sample_completed');self.assertEqual(r['encoded_verified_objects'],1);self.assertEqual(r['decoded_ckey_verified_objects'],0);self.assertTrue(r['strict_range_headers_verified'])
 def test_one_request_cap_and_redirect(self):
  it,b=multichunk()
  with self.assertRaises(l.q.SampleError):l.q.transfer(it,{'asset_requests_attempted':1,'asset_response_bytes_read':0},STOP)
  with self.assertRaises(l.q.net.CompletionError):l.q.net.NoRedirect().redirect_request(None,None,302,'',{},'https://example.com')
 def test_share_report_private_keys_and_paths_absent(self):
  with tempfile.TemporaryDirectory() as t:
   f=self.fixture(t);r,o,_=self.run_case(f);text=(o/'Retail-Large-Range-to-share.json').read_text();self.assertNotIn(str(f[0]),text);self.assertNotIn(f[4]['ekey'].hex(),text);self.assertFalse(r['installed_files_changed']);self.assertFalse(r['decoded_game_assets_saved']);self.assertTrue((o/'range-private.json').exists())
if __name__=='__main__':unittest.main()
