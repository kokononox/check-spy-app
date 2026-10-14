import sys,json,pathlib,hashlib,sqlite3,tempfile,threading,unittest,urllib.error
from unittest.mock import patch
sys.path.insert(0,'/data/wow-batch-v09/package')
import batch,pilot,range_pilot as ranges
from test_range import index_blob,Track
from fixtures import table,blte,spec
from test_pilot import opaque,STOP

def fixture(root,count=8,large=False,mixed=False):
 game=root/'game';game.mkdir();stage=root/'stage';stage.mkdir();diag=stage/'Payload-Verify-fixture';diag.mkdir()
 blobs=[];metadata=[];locs=[];offset=2048
 for i in range(count):
  plain=(('Synthetic batch sample '+str(i)).encode())
  if large:plain=bytes([65+i])*1500000
  blob=opaque(plain) if mixed and i==count-1 else blte(plain,b'N' if large else b'Z',True)
  spec_=spec(plain,blob);ek=bytes.fromhex(spec_['ekey']);ck=hashlib.md5(plain).digest()
  blobs.append((ek,ck,blob,len(plain),offset));metadata.append((ck,len(plain),[ek]));locs.append((ek,len(blob),offset,0));offset+=len(blob)+100
 enc=table(metadata,{ek:len(blob) for ek,ck,blob,ds,off in blobs});es=spec(enc,blte(enc));cfg=('build-uid = wow\nencoding = '+es['ckey']+' '+es['ekey']+'\nencoding-size = '+str(es['decoded'])+' '+str(es['encoded'])+'\n').encode();build=hashlib.md5(cfg).hexdigest();(stage/'build.config').write_bytes(cfg)
 cache=stage/'cache/tpr/wow';(cache/'data').mkdir(parents=True);(cache/'config').mkdir();(cache/'data'/(es['ekey']+'.decoded')).write_bytes(enc)
 records=sorted(locs);normal,archive=index_blob(records);group,gk=index_blob(records,True);(cache/'data'/(gk+'.index')).write_bytes(group);(cache/'data'/(archive+'.index')).write_bytes(normal)
 cdn=('archives = '+archive+'\narchive-group = '+gk+'\n').encode();cdk=hashlib.md5(cdn).hexdigest();(cache/'config'/cdk).write_bytes(cdn)
 (stage/'Retail-Staging-to-share.json').write_text(json.dumps({'status':'sample_downloaded_and_content_verified','target_version':'12.1.5.70391','target_build_config':build,'target_cdn_config':cdk}))
 info=game/'.build.info';info.write_text('Branch|Active|Build Key|Tags|Version|Product\neu|1|'+build+'|Windows x86_64 EU enUS text speech|12.1.0.69933|wow\n')
 report={'tool':'WoW Retail EU Local Payload Diagnostics 0.6','status':'payload_verification_completed','region':'eu','product':'wow','local_version':'12.1.0.69933','target_version':'12.1.5.70391','input_target_candidates':count,'summary':{'encoded_integrity_only':{'target_objects':count,'associated_target_encoded_bytes':sum(len(b) for ek,ck,b,ds,off in blobs)}}};rp=diag/'Retail-Payload-Diagnostic-to-share.json';rp.write_text(json.dumps(report))
 db=sqlite3.connect(diag/'payload-verify-private.sqlite');db.execute('CREATE TABLE checks(target_ekey BLOB PRIMARY KEY,ckey BLOB,alternate_ekey BLOB,status TEXT,reason TEXT,target_encoded_bytes INTEGER,target_advertises_alternate INTEGER,unsupported_modes_hex TEXT) WITHOUT ROWID');db.executemany('INSERT INTO checks VALUES (?,?,?,?,?,?,?,?)',[(ek,ck,b'X'*16,'encoded_integrity_only','encrypted_mode',len(blob),0,'["45"]') for ek,ck,blob,ds,off in blobs]);db.commit();db.close()
 return rp,info,{off:blob for ek,ck,blob,ds,off in blobs},stage
class Network:
 def __init__(self,bodies,fail_at=None,corrupt=False,cancel=None):self.bodies=bodies;self.fail_at=fail_at;self.corrupt=corrupt;self.calls=0;self.responses=[];self.cancel=cancel
 def open(self,req,**kwargs):
  self.calls+=1;header=req.get_header('Range');start,end=map(int,header.split('=')[1].split('-'));body=self.bodies[start]
  status=200 if self.fail_at==self.calls and not self.corrupt else 206
  if self.fail_at==self.calls and self.corrupt:body=body[:-1]+bytes([body[-1]^1])
  if self.cancel and self.calls==3:self.cancel.set()
  r=Track(body,{'Content-Range':'bytes '+str(start)+'-'+str(end)+'/99999999'},status);self.responses.append(r);return r
class BatchTests(unittest.TestCase):
 def prepare(self,rp,bi,stop=STOP):
  with patch('pilot.online',return_value='12.1.5.70391'):return batch.prepare(rp,bi,stop,lambda s:None)
 def test_eight_end_to_end_and_unchanged_sources(self):
  with tempfile.TemporaryDirectory() as t:
   root=pathlib.Path(t);rp,bi,bodies,stage=fixture(root);original={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob('*') if p.is_file()};p=self.prepare(rp,bi)
   self.assertEqual(len(p['items']),8);self.assertEqual(p['shared_stats']['remote_index_requests'],0);net=Network(bodies)
   with patch('pilot.opener',return_value=net):r,out=batch.run(p,STOP,lambda s:None)
   self.assertEqual(r['status'],'batch_completed');self.assertEqual(r['encoded_verified_objects'],8);self.assertEqual(r['decoded_ckey_verified_objects'],8);self.assertEqual(net.calls,8)
   self.assertEqual(r['range_response_bytes_read'],r['planned_range_bytes']);self.assertEqual(len(list(out.glob('Sample-*/verified-target-range-sample.blte'))),8)
   self.assertTrue(all(hashlib.sha256(p.read_bytes()).hexdigest()==h for p,h in original.items()))
 def test_first_failure_stops_and_retains_two(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));p=self.prepare(rp,bi);net=Network(bodies,fail_at=3)
   with patch('pilot.opener',return_value=net):r,out=batch.run(p,STOP,lambda s:None)
   self.assertEqual(net.calls,3);self.assertEqual(net.responses[-1].reads,0);self.assertEqual(r['encoded_verified_objects'],2);self.assertEqual(r['counts_by_download_status']['not_requested_after_stop'],5)
   self.assertEqual(len(list(out.glob('Sample-*/verified-target-range-sample.blte'))),2);self.assertEqual(r['status'],'batch_stopped_after_sample_failure')
 def test_hash_failure_stops(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));p=self.prepare(rp,bi);net=Network(bodies,fail_at=2,corrupt=True)
   with patch('pilot.opener',return_value=net):r,out=batch.run(p,STOP,lambda s:None)
   self.assertEqual(net.calls,2);self.assertEqual(r['encoded_verified_objects'],1);self.assertEqual(r['status'],'batch_stopped_after_sample_failure')
 def test_cancel_retains_successes(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));stop=threading.Event();p=self.prepare(rp,bi,stop);net=Network(bodies,cancel=stop)
   with patch('pilot.opener',return_value=net):r,out=batch.run(p,stop,lambda s:None)
   self.assertEqual(net.calls,3);self.assertEqual(r['encoded_verified_objects'],2);self.assertEqual(r['status'],'batch_cancelled')
 def test_decline_no_asset_requests(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));p=self.prepare(rp,bi)
   with patch('pilot.opener') as op:r,out=batch.decline(p);op.assert_not_called()
   self.assertEqual(r['range_requests_attempted'],0);self.assertEqual(r['status'],'batch_download_declined')
 def test_byte_budget_limits_selection(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t),large=True);p=self.prepare(rp,bi)
   self.assertEqual(len(p['items']),5);self.assertLess(sum(i['expected_encoded_bytes'] for i in p['items']),batch.CAP)
 def test_mixed_target_encryption_not_claimed_decoded(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t),mixed=True);p=self.prepare(rp,bi)
   with patch('pilot.opener',return_value=Network(bodies)):r,out=batch.run(p,STOP,lambda s:None)
   self.assertEqual(r['encoded_verified_objects'],8);self.assertEqual(r['decoded_ckey_verified_objects'],7);self.assertEqual(r['status'],'batch_completed')
 def test_partial_lookup_downloads_only_located(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));real=ranges.lookup;calls=0
   def partial(*a,**k):
    nonlocal calls
    calls+=1
    if calls==2:raise ranges.RangeError('exact_target_not_found_within_partial_index_budget')
    return real(*a,**k)
   with patch('range_pilot.lookup',side_effect=partial):p=self.prepare(rp,bi)
   net=Network(bodies)
   with patch('pilot.opener',return_value=net):r,out=batch.run(p,STOP,lambda s:None)
   self.assertEqual(net.calls,7);self.assertEqual(r['encoded_verified_objects'],7);self.assertEqual(r['counts_by_download_status']['not_requested_unresolved_location'],1)
 def test_shared_remote_index_budget_and_no_duplicate_requests(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));cache=stage/'cache/tpr/wow';
   for f in (cache/'data').glob('*.index'):f.unlink()
   cfg=('archives = '+' '.join('%032x'%i for i in range(1,31))+'\n').encode();key=hashlib.md5(cfg).hexdigest();(cache/'config'/key).write_bytes(cfg);pp=stage/'Retail-Staging-to-share.json';r=json.loads(pp.read_text());r['target_cdn_config']=key;pp.write_text(json.dumps(r))
   op=Network({});op.open=lambda *a,**k:(_ for _ in ()).throw(urllib.error.HTTPError('https://example.invalid',404,'',{},None))
   with patch('pilot.opener',return_value=op),patch.object(op,'open',wraps=op.open) as mocked:p=self.prepare(rp,bi)
   self.assertEqual(mocked.call_count,16);self.assertEqual(p['failed_report']['lookup']['remote_index_requests'],16);self.assertEqual(p['failed_report']['located_target_objects'],0)
 def test_missing_cdn_config_only_one_request_across_batch(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));cache=stage/'cache/tpr/wow/config'
   for f in cache.iterdir():f.unlink()
   with patch('pilot.text_fetch',side_effect=pilot.PilotError('metadata_unavailable')) as fetch:p=self.prepare(rp,bi)
   self.assertEqual(fetch.call_count,1);self.assertEqual(p['failed_report']['lookup']['cdn_config_requests'],1)
 def test_inconsistent_per_object_budget_no_network(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));p=self.prepare(rp,bi);p['items'][0]['plan']['encoded_size']+=1
   with patch('pilot.opener') as op:r,out=batch.run(p,STOP,lambda s:None);op.assert_not_called()
   self.assertEqual(r['failure_reason'],'inconsistent_object_budget')
 def test_invalid_aggregate_budget_no_network(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));p=self.prepare(rp,bi);p['items'][0]['expected_encoded_bytes']=batch.CAP
   with patch('pilot.opener') as op:
    with self.assertRaises(AssertionError):batch.run(p,STOP,lambda s:None)
    op.assert_not_called()
 def test_source_changed_no_download(self):
  with tempfile.TemporaryDirectory() as t:
   rp,bi,bodies,stage=fixture(pathlib.Path(t));p=self.prepare(rp,bi);rp.write_text('{}')
   with patch('pilot.opener') as op:r,out=batch.run(p,STOP,lambda s:None);op.assert_not_called()
   self.assertEqual(r['encoded_verified_objects'],0);self.assertEqual(r['status'],'batch_stopped')
if __name__=='__main__':
 r=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(BatchTests))
 if not r.wasSuccessful():raise SystemExit(1)
 pathlib.Path('/data/wow-batch-v09/research/batch-tests.json').write_text(json.dumps({'batch_tests_passed':r.testsRun,'eight_object_end_to_end_passed':True,'stop_after_first_failure_and_preserve_success_tested':True,'shared_metadata_budget_tested':True,'original_game_and_cache_unchanged_in_fixture':True,'actual_windows_runtime_tested':False},indent=2))
