import sys,io,json,hashlib,pathlib,tempfile,threading,unittest,urllib.error
from unittest.mock import patch
sys.path.insert(0,'/data/wow-batch-v09/package')
import pilot,range_pilot as engine
from archive_index import locate,IndexError
from test_pilot import fixture,plan,opaque,Response,Open,STOP

def index_blob(records,group=False):
 ob=6 if group else 4;bs=4096;epb=bs//(20+ob);blocks=[];toc_ek=[];hashes=[]
 for i in range(0,len(records),epb):
  subset=records[i:i+epb];block=bytearray()
  for ek,size,offset,ai in subset:block+=ek+size.to_bytes(4,'big')+(ai.to_bytes(2,'big') if group else b'')+offset.to_bytes(4,'big')
  block+=bytes(bs-len(block));blocks.append(bytes(block));toc_ek.append(subset[-1][0]);hashes.append(hashlib.md5(block).digest()[:8])
 toc=b''.join(toc_ek+hashes);base=bytes([1,0,0,4,ob,4,16,8])+len(records).to_bytes(4,'little');base+=hashlib.md5(base+bytes(8)).digest()[:8];footer=hashlib.md5(toc).digest()[:8]+base
 return b''.join(blocks)+toc+footer,hashlib.md5(footer).hexdigest()
class IndexTests(unittest.TestCase):
 def test_normal(self):
  ek=b'A'*16;b,k=index_blob([(ek,80,1024,0)]);loc,p=locate(b,k,ek,80);self.assertEqual(loc,[{'archive':k,'offset':1024,'size':80}]);self.assertTrue(p['all_index_block_checksums_verified'])
 def test_group(self):
  ek=b'A'*16;b,k=index_blob([(ek,80,1024,1)],True);loc,p=locate(b,k,ek,80,['X'*32,'Y'*32]);self.assertEqual(loc[0]['archive'],'Y'*32)
 def test_group_duplicate_keys(self):
  ek=b'A'*16;b,k=index_blob([(ek,80,i,0) for i in range(160)],True);loc,p=locate(b,k,ek,80,['a'*32]);self.assertEqual(len(loc),160)
 def test_wrong_name(self):
  b,k=index_blob([(b'A'*16,80,0,0)])
  with self.assertRaises(IndexError):locate(b,'0'*32,b'A'*16,80)
 def test_corrupt_block(self):
  b,k=index_blob([(b'A'*16,80,0,0)]);b=bytes([b[0]^1])+b[1:]
  with self.assertRaises(IndexError):locate(b,k,b'A'*16,80)
 def test_corrupt_toc(self):
  b,k=index_blob([(b'A'*16,80,0,0)]);b=b[:4096]+bytes([b[4096]^1])+b[4097:]
  with self.assertRaises(IndexError):locate(b,k,b'A'*16,80)
 def test_unknown_format(self):
  b,k=index_blob([(b'A'*16,80,0,0)]);b=b[:-20]+bytes([2])+b[-19:]
  with self.assertRaises(IndexError):locate(b,k,b'A'*16,80)
 def test_no_match(self):
  b,k=index_blob([(b'A'*16,80,0,0)]);self.assertEqual(locate(b,k,b'B'*16,80)[0],[])
 def test_size_mismatch(self):
  b,k=index_blob([(b'A'*16,80,0,0)]);self.assertEqual(locate(b,k,b'A'*16,81)[0],[])
 def test_archive_id_bounds(self):
  b,k=index_blob([(b'A'*16,80,0,2)],True)
  with self.assertRaises(IndexError):locate(b,k,b'A'*16,80,['a'*32])
 def test_used_block_sort_order(self):
  b,k=index_blob([(b'B'*16,80,0,0),(b'A'*16,80,100,0)])
  with self.assertRaises(IndexError):locate(b,k,b'A'*16,80)
 def test_cancel(self):
  b,k=index_blob([(b'A'*16,80,0,0)]);stop=threading.Event();stop.set()
  with self.assertRaises(IndexError):locate(b,k,b'A'*16,80,cancel=stop)
class Track(Response):
 def __init__(self,*a,**kw):super().__init__(*a,**kw);self.reads=0
 def read(self,*a,**kw):self.reads+=1;return super().read(*a,**kw)
class RangeTests(unittest.TestCase):
 def trial(self,status=206,cr=None,transform=lambda b:b,encrypted=False,headers=None,exception=None):
  with tempfile.TemporaryDirectory() as t:
   stage=pathlib.Path(t);p,body=plan(stage,opaque(b'synthetic plaintext') if encrypted else None);out=stage/'out';out.mkdir();p['output']=out;p['location']={'archive':'a'*32,'offset':1024,'size':len(body)};p['index_verification']={'all_index_block_checksums_verified':True}
   h={'Content-Range':cr or 'bytes 1024-'+str(1024+len(body)-1)+'/4096'};h.update(headers or {});response=Track(transform(body),h,status);op=Open(response)
   if exception:op.open=lambda *a,**k:(_ for _ in ()).throw(exception)
   with patch('pilot.opener',return_value=op):r,out=engine.download(p,STOP,lambda s:None)
   self.assertFalse((out/'range-sample.part').exists());self.assertFalse(r['installed_files_changed']);self.assertFalse(r['sample_executed']);self.assertFalse(r['decryption_attempted'])
   return r,response.reads
 def test_exact_range_plain_success(self):
  r,n=self.trial();self.assertTrue(r['encoded_integrity_verified']);self.assertTrue(r['decoded_ckey_verified'])
 def test_exact_range_encrypted_success(self):
  r,n=self.trial(encrypted=True);self.assertTrue(r['encoded_integrity_verified']);self.assertFalse(r['decoded_ckey_verified'])
 def test_whole_archive_200_body_not_read(self):
  r,n=self.trial(status=200);self.assertEqual(n,0);self.assertEqual(r['failure_reason'],'server_ignored_range_body_not_read')
 def test_wrong_range_body_not_read(self):
  r,n=self.trial(cr='bytes 0-100/4096');self.assertEqual(n,0);self.assertFalse(r['server_range_accepted'])
 def test_unknown_total_body_not_read(self):
  r,n=self.trial(cr='bytes 1024-1080/*');self.assertEqual(n,0)
 def test_range_length_wrong_body_not_read(self):
  r,n=self.trial(headers={'Content-Length':'999'});self.assertEqual(n,0)
 def test_compressed_response_body_not_read(self):
  r,n=self.trial(headers={'Content-Encoding':'gzip'});self.assertEqual(n,0)
 def test_truncation(self):
  r,n=self.trial(transform=lambda b:b[:-1]);self.assertEqual(r['failure_reason'],'truncated_range_download')
 def test_overrun(self):
  r,n=self.trial(transform=lambda b:b+b'X');self.assertEqual(r['failure_reason'],'range_response_exceeds_expected_size')
 def test_corrupt_content(self):
  r,n=self.trial(transform=lambda b:b[:-1]+bytes([b[-1]^1]));self.assertFalse(r['encoded_integrity_verified'])
 def test_http_416(self):
  r,n=self.trial(exception=urllib.error.HTTPError('https://example.invalid',416,'',{},None));self.assertEqual(r['range_http_status'],416);self.assertEqual(n,0)
 def test_cached_group_end_to_end(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);rp,bi,body=fixture(root);stage=root/'stage';ek=plan(stage,body)[0]['target_ekey'];idx,archive=index_blob([(ek,len(body),1024,0)]);group,gk=index_blob([(ek,len(body),1024,0)],True)
   cfg=('archives = '+archive+'\narchive-group = '+gk+'\n').encode();key=hashlib.md5(cfg).hexdigest();cache=stage/'cache/tpr/wow';(cache/'config').mkdir();(cache/'config'/key).write_bytes(cfg);(cache/'data'/(gk+'.index')).write_bytes(group)
   pp=stage/'Retail-Staging-to-share.json';prior=json.loads(pp.read_text());prior['target_cdn_config']=key;pp.write_text(json.dumps(prior))
   original={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
   with patch('pilot.online',return_value='12.1.5.70391'),patch('pilot.opener') as op:p=engine.prepare(rp,bi,STOP,lambda s:None);op.assert_not_called()
   self.assertNotIn('failed_report',p);self.assertTrue(p['lookup_stats']['generated_group_index_used'])
   h={'Content-Range':'bytes 1024-'+str(1024+len(body)-1)+'/4096'}
   with patch('pilot.opener',return_value=Open(Response(body,h,206))):r,out=engine.download(p,STOP,lambda s:None)
   self.assertTrue(r['encoded_integrity_verified']);self.assertTrue(all(hashlib.sha256(p.read_bytes()).hexdigest()==v for p,v in original.items()))
 def test_missing_index_budget_honest_partial(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);p,b=plan(root);pp=root/'Retail-Staging-to-share.json';cache=root/'cache/tpr/wow/config';cache.mkdir(parents=True);archives=['%032x'%i for i in range(1,21)];cfg=('archives = '+' '.join(archives)+'\n').encode();key=hashlib.md5(cfg).hexdigest();(cache/key).write_bytes(cfg);pp.write_text(json.dumps({'target_cdn_config':key}));p['target_build_config']='x'
   with patch('range_pilot.fetch_index',side_effect=pilot.PilotError('unavailable')) as f:
    with self.assertRaises(engine.RangeError):engine.lookup(p,root,STOP,lambda s:None)
    self.assertEqual(f.call_count,16);self.assertFalse(p['lookup_stats']['index_search_complete'])
 def test_fetch_index_budget(self):
  with tempfile.TemporaryDirectory() as t:
   stats={'remote_index_requests':0,'index_response_bytes_read':engine.INDEX_BUDGET}
   with patch('pilot.opener') as op:
    with self.assertRaises(engine.RangeError):engine.fetch_index('a'*32,pathlib.Path(t),STOP,stats)
    op.assert_not_called()
if __name__=='__main__':
 suite=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(c) for c in [IndexTests,RangeTests]]);r=unittest.TextTestRunner().run(suite)
 if not r.wasSuccessful():raise SystemExit(1)
 pathlib.Path('/data/wow-batch-v09/research/range-tests.json').write_text(json.dumps({'range_and_index_tests_passed':r.testsRun,'synthetic_cached_group_end_to_end_passed':True,'whole_archive_200_rejected_before_body_read':True,'original_game_and_cache_unchanged_in_fixture':True,'actual_windows_runtime_tested':False},indent=2))
