"""Synthetic addon tests. Does not run target, mitmdump, TLS or Windows APIs."""
import importlib.util, json, os, pathlib, sys, tempfile, types, unittest
from unittest.mock import patch
BASE=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(BASE))
fake=types.ModuleType('mitmproxy');fake.http=types.SimpleNamespace(Response=types.SimpleNamespace(make=lambda code,body:types.SimpleNamespace(status_code=code)))
sys.modules['mitmproxy']=fake
spec=importlib.util.spec_from_file_location('erm_addon',BASE/'Telemetry-Fields.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
 def tearDown(self):self.temp.cleanup()
 def addon(self,opt=True):
  env={'ERM_TLS_SUMMARY':str(self.root/'summary.json'),'ERM_TLS_TARGET':'test.exe','ERM_TLS_PORT':'5555','ERM_TLS_IDS':'','ERM_TLS_PRIVATE_CAPTURE':'1' if opt else '0'}
  with patch.dict(os.environ,env):a=mod.TelemetryFields()
  a.allowed_client=lambda c:True
  return a
 def flow(self,body=b'{"computername":"PRIVATE_COMPUTER_ABC","password":"PRIVATE_BODY_SECRET"}',host=mod.HOST,port=443):
  r=types.SimpleNamespace(host=host,port=port,method='POST',url='https://'+host+'/v1/events?token=PRIVATE_QUERY_SECRET',path='/v1/events?token=PRIVATE_QUERY_SECRET',raw_content=body,headers={'content-type':'application/json','authorization':'PRIVATE_HEADER_SECRET','cookie':'PRIVATE_COOKIE_SECRET'})
  return types.SimpleNamespace(request=r,client_conn=types.SimpleNamespace(tls_established=True),metadata={},response=None)
 def test_url_body_and_public_redaction(self):
  a=self.addon();f=self.flow();a.request(f)
  pub=(self.root/'summary.json').read_text();private=json.loads((self.root/'private-requests.json').read_text())
  for secret in ['PRIVATE_QUERY_SECRET','PRIVATE_BODY_SECRET','PRIVATE_COMPUTER_ABC','PRIVATE_HEADER_SECRET','PRIVATE_COOKIE_SECRET','/v1/events']:
   self.assertNotIn(secret,pub)
  item=private['Requests'][0];self.assertEqual(item['URL'],f.request.url);self.assertIn('PRIVATE_BODY_SECRET',item['BodyText'])
  self.assertNotIn('PRIVATE_HEADER_SECRET',json.dumps(private));self.assertNotIn('PRIVATE_COOKIE_SECRET',json.dumps(private))
  self.assertIn('ComputerName',a.state['Requests'][0]['FieldCategories'])
 def test_opt_out(self):
  a=self.addon(False);a.request(self.flow());self.assertFalse((self.root/'private-requests.json').exists())
 def test_out_of_scope(self):
  for host,port in [('account.battle.net',443),(mod.HOST,80)]:
   a=self.addon();a.request(self.flow(host=host,port=port));self.assertEqual(a.state['Requests'],[])
  self.assertFalse((self.root/'private-requests.json').exists())
 def test_failed_attribution(self):
  a=self.addon();a.allowed_client=lambda c:False;f=self.flow();a.request(f);self.assertEqual(f.response.status_code,403);self.assertFalse((self.root/'private-requests.json').exists())
 def test_body_cap(self):
  a=self.addon();f=self.flow(b'Z'*300000);a.request(f);x=a.private['Requests'][0]
  self.assertTrue(x['BodyTruncated']);self.assertEqual(x['BodyStoredBytes'],262144);self.assertEqual(x['BodyRawBytes'],300000)
 def test_binary(self):
  a=self.addon();a.request(self.flow(b'\xff\x00\x80'));self.assertIsNone(a.private['Requests'][0]['BodyText']);self.assertEqual(a.private['Requests'][0]['BodyRawBase64'],'/wCA')
 def test_compressed_is_not_blindly_decoded(self):
  a=self.addon();f=self.flow(b'compressed');f.request.headers['content-encoding']='gzip';a.request(f);self.assertIsNone(a.private['Requests'][0]['BodyText'])
 def test_response(self):
  a=self.addon();f=self.flow();a.request(f);f.response=types.SimpleNamespace(status_code=204);a.response(f)
  self.assertEqual(a.state['Requests'][0]['ResponseStatus'],204);self.assertEqual(a.private['Requests'][0]['ResponseStatus'],204)
 def test_budget(self):
  a=self.addon();a.private_bytes=16777215;a.request(self.flow());self.assertTrue(a.private['StorageBudgetReached']);self.assertEqual(a.private['Requests'],[])
 def test_request_limit(self):
  a=self.addon();a.state['Requests']=[{}]*128;f=self.flow();a.request(f);self.assertEqual(f.response.status_code,503);self.assertFalse((self.root/'private-requests.json').exists())
 def test_missing_body(self):
  a=self.addon();a.request(self.flow(None));self.assertFalse(a.private['Requests'][0]['BodyAvailable'])
if __name__=='__main__':unittest.main(verbosity=2)
