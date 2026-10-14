import sys,io,json,hashlib,threading,tempfile,sqlite3,unittest,pathlib,urllib.error
from unittest.mock import patch
sys.path.insert(0,'/data/wow-batch-v09/package')
import pilot
from fixtures import table,blte,spec
STOP=threading.Event()
def opaque(body):
 block=b'E'+b'opaque-synthetic-payload'
 header=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+len(body).to_bytes(4,'big')+hashlib.md5(block).digest()
 return header+block
class Response(io.BytesIO):
 def __init__(self,body,headers=None,status=200):super().__init__(body);self.headers={} if headers is None else headers;self.status=status
class Open:
 def __init__(self,response):self.response=response;self.calls=0
 def open(self,*args,**kwargs):self.calls+=1;return self.response

def plan(stage,body=None):
 plain=b'synthetic plaintext';body=blte(plain,b'Z',True) if body is None else body
 hs=int.from_bytes(body[4:8],'big');ek=hashlib.md5(body[:hs] if hs else body).digest()
 return {'stage':stage,'snapshots':{},'target_version':'12.1.5.70391','local_version':'12.1.0.69933','current_online_version':'12.1.5.70391','encoded_size':len(body),'decoded_size':len(plain),'ckey':hashlib.md5(plain).digest(),'target_ekey':ek,'url':pilot.CDN+'/tpr/wow/data/'+ek.hex()[:2]+'/'+ek.hex()[2:4]+'/'+ek.hex()},body

def fixture(root):
 game=root/'game';game.mkdir();stage=root/'stage';stage.mkdir();out=stage/'Payload-Verify-fixture';out.mkdir()
 payload=opaque(b'synthetic plaintext');pl,blob=plan(stage,payload);ek=pl['target_ekey'];ck=pl['ckey']
 enc=table([(ck,pl['decoded_size'],[ek])],{ek:len(blob)});es=spec(enc,blte(enc));cfg=('build-uid = wow\nencoding = '+es['ckey']+' '+es['ekey']+'\nencoding-size = '+str(es['decoded'])+' '+str(es['encoded'])+'\n').encode();build=hashlib.md5(cfg).hexdigest()
 (stage/'build.config').write_bytes(cfg);cache=stage/'cache/tpr/wow/data';cache.mkdir(parents=True);(cache/(es['ekey']+'.decoded')).write_bytes(enc)
 prior={'status':'sample_downloaded_and_content_verified','target_version':pl['target_version'],'target_build_config':build};(stage/'Retail-Staging-to-share.json').write_text(json.dumps(prior))
 info=game/'.build.info';info.write_text('Branch|Active|Build Key|Tags|Version|Product\neu|1|'+build+'|Windows x86_64 EU enUS text speech|'+pl['local_version']+'|wow\n')
 report={'tool':'WoW Retail EU Local Payload Diagnostics 0.6','status':'payload_verification_completed','region':'eu','product':'wow','local_version':pl['local_version'],'target_version':pl['target_version'],'input_target_candidates':1,'summary':{'encoded_integrity_only':{'target_objects':1,'associated_target_encoded_bytes':len(blob)}}}
 rp=out/'Retail-Payload-Diagnostic-to-share.json';rp.write_text(json.dumps(report))
 db=sqlite3.connect(out/'payload-verify-private.sqlite');db.execute('CREATE TABLE checks(target_ekey BLOB PRIMARY KEY,ckey BLOB,alternate_ekey BLOB,status TEXT,reason TEXT,target_encoded_bytes INTEGER,target_advertises_alternate INTEGER,unsupported_modes_hex TEXT) WITHOUT ROWID');db.execute('INSERT INTO checks VALUES (?,?,?,?,?,?,?,?)',(ek,ck,b'X'*16,'encoded_integrity_only','encrypted_mode',len(blob),0,'["45"]'));db.commit();db.close()
 return rp,info,blob
class Tests(unittest.TestCase):
 def trial(self,mode='plain',response_transform=lambda b:b,headers=None,exc=None,cancel=None):
  with tempfile.TemporaryDirectory() as t:
   stage=pathlib.Path(t);p,body=plan(stage,opaque(b'synthetic plaintext') if mode=='encrypted' else None)
   op=Open(Response(response_transform(body),headers))
   if exc:op.open=lambda *a,**k:(_ for _ in ()).throw(exc)
   with patch('pilot.opener',return_value=op):r,out=pilot.download(p,cancel or STOP,lambda s:None)
   self.assertFalse((out/'sample.part').exists());self.assertTrue((out/'Retail-CDN-Pilot-to-share.json').exists())
   self.assertFalse(r['installed_files_changed']);self.assertFalse(r['decoded_game_assets_saved']);self.assertFalse(r['decryption_attempted'])
   return r, (out/'verified-target-sample.blte').exists()
 def test_plain_success(self):
  r,kept=self.trial();self.assertTrue(kept);self.assertTrue(r['decoded_ckey_verified'])
 def test_encrypted_success_no_decryption(self):
  r,kept=self.trial('encrypted');self.assertTrue(kept);self.assertTrue(r['encoded_integrity_verified']);self.assertFalse(r['decoded_ckey_verified']);self.assertEqual(r['unsupported_modes_hex'],['45'])
 def test_corruption(self):
  r,kept=self.trial('encrypted',lambda b:b[:-1]+bytes([b[-1]^1]));self.assertFalse(kept);self.assertEqual(r['failure_reason'],'encoded_chunk_checksum_mismatch')
 def test_truncated(self):
  r,kept=self.trial(response_transform=lambda b:b[:-1]);self.assertFalse(kept);self.assertEqual(r['failure_reason'],'truncated_download')
 def test_oversize(self):
  r,kept=self.trial(response_transform=lambda b:b+b'X');self.assertFalse(kept);self.assertEqual(r['failure_reason'],'response_exceeds_expected_size')
 def test_bad_length(self):
  r,kept=self.trial(headers={'Content-Length':'99999999'});self.assertFalse(kept);self.assertEqual(r['sample_response_bytes_read'],0)
 def test_http_encoding(self):
  r,kept=self.trial(headers={'Content-Encoding':'gzip'});self.assertFalse(kept);self.assertEqual(r['failure_reason'],'unexpected_http_compression')
 def test_404(self):
  r,kept=self.trial(exc=urllib.error.HTTPError('https://example.invalid',404,'not found',{},None));self.assertFalse(kept);self.assertEqual(r['failure_reason'],'direct_object_not_available');self.assertEqual(r['http_status'],404)
 def test_403_reported_no_retry(self):
  r,kept=self.trial(exc=urllib.error.HTTPError('https://example.invalid',403,'denied',{},None));self.assertFalse(kept);self.assertEqual(r['failure_reason'],'direct_object_access_denied');self.assertEqual(r['http_status'],403);self.assertEqual(r['automatic_retries'],0)
 def test_cancel(self):
  stop=threading.Event();stop.set();r,kept=self.trial(cancel=stop);self.assertFalse(kept);self.assertFalse(r['asset_download_attempted']);self.assertEqual(r['status'],'cancelled')
 def test_official_cdn_query_parameters(self):
  cdns='Name|Path|Hosts|Servers\neu|tpr/wow|level3.blizzard.com|http://level3.blizzard.com/?maxhosts=8 https://level3.ssl.blizzard.com/?maxhosts=8&fallback=1\n'
  versions='Region|VersionsName\neu|12.1.5.70391\n'
  with patch('pilot.text_fetch',side_effect=[cdns,versions]):self.assertEqual(pilot.online(STOP),'12.1.5.70391')
 def test_unapproved_cdn_rejected(self):
  cdns='Name|Path|Hosts|Servers\neu|tpr/wow|bad.invalid|https://bad.invalid/\n'
  with patch('pilot.text_fetch',return_value=cdns):
   with self.assertRaises(pilot.PilotError):pilot.online(STOP)
 def test_no_redirect(self):
  with self.assertRaises(pilot.PilotError):pilot.NoRedirect().redirect_request(None,None,302,'',{},'http://bad.invalid')
 def test_limit_before_network(self):
  with tempfile.TemporaryDirectory() as t:
   p,b=plan(pathlib.Path(t));p['encoded_size']=pilot.CAP
   with patch('pilot.opener') as op:
    with self.assertRaises(pilot.PilotError):pilot.download(p,STOP,lambda s:None)
    op.assert_not_called()
 def test_endpoint_before_network(self):
  with tempfile.TemporaryDirectory() as t:
   p,b=plan(pathlib.Path(t));p['url']='http://bad.invalid'
   with patch('pilot.opener') as op:
    with self.assertRaises(pilot.PilotError):pilot.download(p,STOP,lambda s:None)
    op.assert_not_called()
 def test_metadata_size_limit(self):
  op=Open(Response(b'x'*pilot.META_CAP))
  with patch('pilot.opener',return_value=op):
   with self.assertRaises(pilot.PilotError):pilot.text_fetch(pilot.CDNS,STOP)
 def test_source_changed(self):
  with tempfile.TemporaryDirectory() as t:
   p,b=plan(pathlib.Path(t));f=pathlib.Path(t)/'source';f.write_text('old');p['snapshots']={f:pilot.indexes.fingerprint(f)};f.write_text('new-long')
   with self.assertRaises(pilot.PilotError):pilot.download(p,STOP,lambda s:None)
 def test_end_to_end_prepare(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);rp,info,body=fixture(root);original={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()}
   with patch('pilot.online',return_value='12.1.5.newer'):p=pilot.prepare(rp,info,STOP,lambda s:None)
   with patch('pilot.opener',return_value=Open(Response(body))):r,out=pilot.download(p,STOP,lambda s:None)
   self.assertFalse(r['pinned_target_matches_current_online_version']);self.assertTrue(r['encoded_integrity_verified']);self.assertFalse(r['decoded_ckey_verified'])
   self.assertTrue(all(hashlib.sha256(p.read_bytes()).hexdigest()==h for p,h in original.items()))
 def test_report_db_mismatch(self):
  with tempfile.TemporaryDirectory() as t:
   rp,info,b=fixture(pathlib.Path(t));r=json.loads(rp.read_text());r['input_target_candidates']=2;rp.write_text(json.dumps(r))
   with self.assertRaises(pilot.PilotError):pilot.prepare(rp,info,STOP,lambda s:None)
if __name__=='__main__':
 r=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 if not r.wasSuccessful():raise SystemExit(1)
 pathlib.Path('/data/wow-batch-v09/research/test-results.json').write_text(json.dumps({'synthetic_tests_passed':r.testsRun,'synthetic_end_to_end_passed':True,'original_game_and_cache_unchanged_in_fixture':True,'actual_windows_runtime_tested':False,'real_user_private_databases_tested':False},indent=2))
