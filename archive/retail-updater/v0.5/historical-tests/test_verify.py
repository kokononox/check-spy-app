import sys,pathlib,tempfile,threading,hashlib,io,json,sqlite3,unittest
from unittest.mock import patch
sys.path.insert(0,'/data/wow-verify-v05/package');from payload import verify,PayloadError,MAX_DECODED
import verify_local as v
from fixtures import table,blte,spec,idx
STOP=threading.Event()
def check(body,mode=b'N',chunked=False):
 encoded=blte(body,mode,chunked);s=spec(body,encoded)
 return verify(io.BytesIO(encoded),len(encoded),len(body),bytes.fromhex(s['ckey']),bytes.fromhex(s['ekey']),STOP)

def opaque(plaintext,mode=b'E'):
 block=mode+b'opaque-encoded-fixture'
 header=b'BLTE'+(36).to_bytes(4,'big')+b'\x0f\0\0\1'+len(block).to_bytes(4,'big')+len(plaintext).to_bytes(4,'big')+hashlib.md5(block).digest()
 return header+block

def full_fixture(root):
 game=root/'game';game.mkdir();stage=root/'stage';stage.mkdir();content=stage/'Content-fixture';content.mkdir()
 bodies=[b'same actual content'*50,b'bad candidate content'*50,b'pretend encrypted plaintext'*30,b'not locally indexed'*30]
 cks=[hashlib.md5(b).digest() for b in bodies]
 payloads=[blte(bodies[0],b'Z',True),blte(bodies[1],b'N',True),opaque(bodies[2]),blte(bodies[3])]
 alt=[bytes.fromhex(spec(body,blob)['ekey']) for body,blob in zip(bodies,payloads)]
 targets=[bytes([x])*16 for x in [0xa1,0xa2,0xb1,0xc1,0xd1,0xe1]];encoded_sizes=dict(zip(targets,[100,105,110,120,130,140]))
 target=table([(cks[0],len(bodies[0]),[targets[0],targets[1],alt[0]]),(cks[1],len(bodies[1]),[targets[2]]),(cks[2],len(bodies[2]),[targets[3]]),(cks[3],len(bodies[3]),[targets[4]])],{**encoded_sizes,alt[0]:len(payloads[0])})
 old=table([(ck,len(body),[key]) for ck,body,key in zip(cks,bodies,alt)],{key:len(blob) for key,blob in zip(alt,payloads)})
 ts=spec(target,blte(target));ls=spec(old,blte(old))
 def cfg(s):return ('build-uid = wow\nencoding = '+s['ckey']+' '+s['ekey']+'\nencoding-size = '+str(s['decoded'])+' '+str(s['encoded'])+'\n').encode()
 tcfg=cfg(ts);lcfg=cfg(ls);tk=hashlib.md5(tcfg).hexdigest();lk=hashlib.md5(lcfg).hexdigest()
 (stage/'build.config').write_bytes(tcfg);lc=game/'Data/config'/lk[:2]/lk[2:4]/lk;lc.parent.mkdir(parents=True);lc.write_bytes(lcfg)
 (content/'local-encoding.decoded').write_bytes(old);cache=stage/'cache/tpr/wow/data';cache.mkdir(parents=True);(cache/(ts['ekey']+'.decoded')).write_bytes(target)
 info=game/'.build.info';info.write_text('Branch|Active|Build Key|Tags|Version|Product\neu|1|'+lk+'|Windows x86_64 EU enUS speech text|12.1.0.69933|wow\n')
 (stage/'Retail-Staging-to-share.json').write_text(json.dumps({'status':'sample_downloaded_and_content_verified','target_version':'12.1.5.70391','target_build_config':tk}))
 db=sqlite3.connect(content/'content-private.sqlite');db.execute('CREATE TABLE content_comparison(target_ekey BLOB PRIMARY KEY,ckey BLOB,alternate_ekey BLOB,status TEXT,target_encoded_bytes INTEGER) WITHOUT ROWID')
 rows=[(targets[0],cks[0],alt[0],100),(targets[1],cks[0],alt[0],105),(targets[2],cks[1],alt[1],110),(targets[3],cks[2],alt[2],120),(targets[4],cks[3],alt[3],130),(targets[5],b'X'*16,alt[0],140)]
 db.executemany('INSERT INTO content_comparison VALUES (?,?,?,?,?)',[(t,ck,a,'alternate_encoding_same_content_candidate',n) for t,ck,a,n in rows]);db.commit();db.close()
 report=content/'Retail-Content-to-share.json';report.write_text(json.dumps({'product':'wow','region':'eu','status':'candidate_content_comparison_completed','local_version':'12.1.0.69933','target_version':'12.1.5.70391','summary':{'alternate_encoding_same_content_candidate':{'target_objects':len(rows),'target_whole_encoded_bytes':sum(r[3] for r in rows)}}}))
 d=game/'Data/data';d.mkdir(parents=True);archive=bytearray();entries=[]
 for key,blob in zip(alt[:3],payloads[:3]):
  off=len(archive)
  if key==alt[1]:blob=blob[:-1]+bytes([blob[-1]^1])
  archive.extend(b'\0'*30+blob);entries.append((key,off,len(blob)+30))
 (d/'data.000').write_bytes(archive);(d/'0000000001.idx').write_bytes(idx(entries))
 original={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in game.rglob('*') if p.is_file()}
 result,output=v.run(report,info,STOP,lambda s:None)
 counts={k:x['target_objects'] for k,x in result['summary'].items()}
 assert counts['content_verified']==2 and counts['validation_failed']==1 and counts['encoded_integrity_only']==1 and counts['location_not_found']==1 and counts['metadata_unresolved']==1
 assert result['unique_local_alternatives_evaluated']==4
 assert result['verified_content_target_metadata_advertises_alternate']==2
 assert not result['decoded_game_assets_saved'] and not result['network_downloads_attempted'] and not result['installed_files_changed']
 assert all(hashlib.sha256(p.read_bytes()).hexdigest()==h for p,h in original.items())
 return True
class Tests(unittest.TestCase):
 def test_n(self):self.assertEqual(check(b'a'*100)['status'],'content_verified')
 def test_z(self):self.assertEqual(check(b'a'*10000,b'Z')['status'],'content_verified')
 def test_chunked(self):self.assertEqual(check(b'asset'*100,b'Z',True)['status'],'content_verified')
 def test_raw(self):
  body=b'raw data';key=hashlib.md5(body).digest();self.assertEqual(verify(io.BytesIO(body),len(body),len(body),key,key,STOP)['status'],'content_verified')
 def test_empty_raw(self):
  key=hashlib.md5(b'').digest();self.assertEqual(verify(io.BytesIO(b''),0,0,key,key,STOP)['status'],'content_verified')
 def test_corrupted_payload(self):
  body=b'asset';encoded=blte(body,chunked=True);s=spec(body,encoded)
  with self.assertRaises(PayloadError):verify(io.BytesIO(encoded[:-1]+b'X'),len(encoded),len(body),bytes.fromhex(s['ckey']),bytes.fromhex(s['ekey']),STOP)
 def test_wrong_ckey(self):
  body=b'asset';encoded=blte(body);s=spec(body,encoded)
  with self.assertRaises(PayloadError):verify(io.BytesIO(encoded),len(encoded),len(body),b'X'*16,bytes.fromhex(s['ekey']),STOP)
 def test_wrong_ekey(self):
  body=b'asset';encoded=blte(body);s=spec(body,encoded)
  with self.assertRaises(PayloadError):verify(io.BytesIO(encoded),len(encoded),len(body),bytes.fromhex(s['ckey']),b'X'*16,STOP)
 def test_encrypted_not_decrypted(self):
  body=b'plaintext';encoded=opaque(body);s=spec(body,encoded);r=verify(io.BytesIO(encoded),len(encoded),len(body),bytes.fromhex(s['ckey']),bytes.fromhex(s['ekey']),STOP)
  self.assertEqual(r['status'],'encoded_integrity_only');self.assertFalse(r['decoded_ckey_verified'])
 def test_unsupported_mode(self):
  body=b'plaintext';encoded=opaque(body,b'4');s=spec(body,encoded);r=verify(io.BytesIO(encoded),len(encoded),len(body),bytes.fromhex(s['ckey']),bytes.fromhex(s['ekey']),STOP);self.assertEqual(r['reason'],'unsupported_compression_mode')
 def test_corrupted_opaque(self):
  body=b'plaintext';encoded=opaque(body);s=spec(body,encoded)
  with self.assertRaises(PayloadError):verify(io.BytesIO(encoded[:-1]+b'X'),len(encoded),len(body),bytes.fromhex(s['ckey']),bytes.fromhex(s['ekey']),STOP)
 def test_size_limit(self):
  with self.assertRaises(PayloadError) as ctx:verify(io.BytesIO(b''),10,MAX_DECODED+1,b'X'*16,b'Y'*16,STOP)
  self.assertEqual(ctx.exception.kind,'not_checked_size_limit')
 def test_cancel(self):
  stop=threading.Event();stop.set()
  with self.assertRaises(PayloadError) as ctx:verify(io.BytesIO(b'abcdefghi'),9,1,b'X'*16,b'Y'*16,stop)
  self.assertEqual(ctx.exception.kind,'cancelled')
 def test_read_failed(self):
  with tempfile.TemporaryDirectory() as t:
   path=pathlib.Path(t)/'file';path.write_bytes(b'a'*20);s={'alternate':b'Y'*16,'ckey':b'X'*16,'encoded_size':20,'decoded_size':20}
   with patch('pathlib.Path.open',side_effect=PermissionError()):r=v.check_one(s,{b'Y'*9:[(path,0,20)]},STOP)
   self.assertEqual(r['status'],'read_failed')
 def test_full_fixture(self):
  with tempfile.TemporaryDirectory() as t:self.assertTrue(full_fixture(pathlib.Path(t)))
if __name__=='__main__':
 r=unittest.TextTestRunner(verbosity=1).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
 if not r.wasSuccessful():raise SystemExit(1)
 pathlib.Path('/data/wow-verify-v05/research/fixture-test.json').write_text(json.dumps({'unit_tests_passed':r.testsRun,'full_fixture_passed':True,'decoded_asset_output_not_created':True,'synthetic_game_files_unchanged':True,'deduplicated_local_payload_checks_tested':True,'encrypted_and_unsupported_modes_not_claimed_decoded':True,'actual_windows_user_archives_tested':False},indent=2));print('Payload verification tests passed:',r.testsRun)
