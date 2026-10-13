import pathlib,sys,unittest,types,tempfile,os,json,importlib.util
from unittest.mock import patch
BASE=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(BASE))
from TLSFailureDiagnostics import classify,MAX_ERROR_CHARS
fake=types.ModuleType('mitmproxy');fake.http=types.SimpleNamespace(Response=types.SimpleNamespace(make=lambda code,body:types.SimpleNamespace(status_code=code)));sys.modules['mitmproxy']=fake
spec=importlib.util.spec_from_file_location('tls_diag_addon',BASE/'Telemetry-Fields.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class Tests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.temp.name)
  with patch.dict(os.environ,{'ERM_TLS_SUMMARY':str(self.root/'summary.json'),'ERM_TLS_TARGET':'owned-fixture.exe','ERM_TLS_PORT':'5500','ERM_TLS_IDS':'','ERM_TLS_PRIVATE_CAPTURE':'0'}):self.a=mod.TelemetryFields()
  self.a.allowed_client=lambda c:True
 def tearDown(self):self.temp.cleanup()
 def data(self,host=mod.HOST,port=443,sni=mod.HOST):
  c=types.SimpleNamespace(id='fixture-id',tls_established=False,error="Client TLS handshake failed: TLSV1_ALERT_UNKNOWN_CA PRIVATE_TOKEN PRIVATE_USER https://private.example/secret")
  s=types.SimpleNamespace(address=(host,port),tls_established=False,error='certificate verify failed PRIVATE_SERVER')
  return types.SimpleNamespace(context=types.SimpleNamespace(client=c,server=s),client_hello=types.SimpleNamespace(sni=sni),ignore_connection=False)
 def test_unknown_ca_indicator(self):self.assertEqual(classify('TLSV1_ALERT_UNKNOWN_CA')['ErrorIndicators'],['AlertUnknownCA'])
 def test_spaces_case(self):self.assertEqual(classify('TLSv1 alert unknown ca')['ErrorIndicators'],['AlertUnknownCA'])
 def test_bad_certificate(self):self.assertIn('AlertBadCertificate',classify('sslv3 alert bad certificate')['ErrorIndicators'])
 def test_verify_failure(self):self.assertEqual(classify('certificate verify failed')['ErrorIndicators'],['LocalCertificateVerifyFailure'])
 def test_official_32_bad_certificate(self):self.assertEqual(classify('ssl/tls alert bad certificate')['ErrorIndicators'],['AlertBadCertificate'])
 def test_official_rewritten_unknownca(self):self.assertEqual(classify("The client does not trust the proxy's certificate for PRIVATE_HOST (tlsv1 alert unknown ca)")['ErrorIndicators'],['AlertUnknownCA'])
 def test_official_rewritten_protocol(self):self.assertEqual(classify('Client and mitmproxy cannot agree on a TLS version to use. You may need to adjust mitmproxy options.')['ErrorIndicators'],['TLSVersionDisagreementReported'])
 def test_disconnect_is_not_certificate_proof(self):self.assertEqual(classify("The client disconnected during the handshake. This may indicate that the client does not trust the proxy's certificate.")['ErrorIndicators'],['HandshakeDisconnectReported'])
 def test_generic_cert_guess_is_not_proof(self):self.assertEqual(classify("The client may not trust the proxy's certificate for PRIVATE_HOST (unknown message)")['ErrorIndicators'],[])
 def test_missing(self):
  for value in [None,'',Exception('secret')]:self.assertEqual(classify(value)['IndicatorStatus'],'Unavailable')
 def test_unknown_no_guess(self):self.assertEqual(classify('pinning or user private message')['IndicatorStatus'],'NoAllowlistedIndicator')
 def test_word_boundaries(self):self.assertEqual(classify('FAKE_TLSV1_ALERT_UNKNOWN_CA_SECRET')['ErrorIndicators'],[])
 def test_scan_bound(self):
  r=classify('x'*MAX_ERROR_CHARS+' tlsv1 alert unknown ca');self.assertTrue(r['ErrorScanTruncated']);self.assertEqual(r['ErrorIndicators'],[])
 def test_client_hook(self):
  d=self.data();self.a.tls_clienthello(d);self.a.tls_failed_client(d);r=self.a.state['TLSFailureDetails'][0]
  self.assertTrue(r['ScopedClientHelloAuthorized']);self.assertEqual(r['ErrorIndicators'],['AlertUnknownCA']);self.assertFalse(r['PinningEstablished']);self.assertEqual(self.a.state['ClientTLSFailures'],1)
 def test_server_hook(self):
  d=self.data();self.a.tls_clienthello(d);self.a.tls_failed_server(d);self.assertEqual(self.a.state['TLSFailureDetails'][0]['ErrorIndicators'],['LocalCertificateVerifyFailure']);self.assertEqual(self.a.state['ServerTLSFailures'],1)
 def test_error_privacy(self):
  d=self.data();self.a.tls_clienthello(d);self.a.tls_failed_client(d);self.a.tls_failed_server(d);s=(self.root/'summary.json').read_text()
  for secret in ['PRIVATE_TOKEN','PRIVATE_USER','PRIVATE_SERVER','private.example','fixture-id','TLSV1_ALERT_UNKNOWN_CA']:self.assertNotIn(secret,s)
  self.assertFalse(self.a.state['RawTLSErrorStored'])
 def test_wrong_port_ignored(self):
  d=self.data(port=80);self.a.tls_clienthello(d);self.a.tls_failed_client(d);self.assertTrue(d.ignore_connection);self.assertEqual(self.a.state['ClientTLSFailures'],0)
 def test_wrong_host_ignored(self):
  d=self.data(host='login.example');self.a.tls_clienthello(d);self.a.tls_failed_client(d);self.assertTrue(d.ignore_connection);self.assertEqual(self.a.state['TLSFailureDetails'],[])
 def test_wrong_sni_unattributed(self):
  d=self.data(sni='login.example');self.a.tls_clienthello(d);self.a.tls_failed_client(d);r=self.a.state['TLSFailureDetails'][0];self.assertTrue(d.ignore_connection);self.assertFalse(r['ScopedClientHelloAuthorized']);self.assertEqual(r['IndicatorStatus'],'Unavailable')
 def test_unapproved_no_error_export(self):
  d=self.data();self.a.allowed_client=lambda c:False;self.a.tls_clienthello(d);self.a.tls_failed_client(d);self.assertTrue(d.ignore_connection);self.assertFalse(self.a.state['TLSFailureDetails'][0]['ScopedClientHelloAuthorized']);self.assertEqual(self.a.state['TLSFailureDetails'][0]['ErrorIndicators'],[])
 def test_failure_without_clienthello(self):
  d=self.data();self.a.tls_failed_client(d);self.assertFalse(self.a.state['TLSFailureDetails'][0]['ScopedClientHelloAuthorized'])
 def test_record_budget(self):
  d=self.data();self.a.tls_clienthello(d)
  for _ in range(20):self.a.tls_failed_client(d)
  self.assertEqual(len(self.a.state['TLSFailureDetails']),16);self.assertTrue(self.a.state['TLSFailureDetailsTruncated']);self.assertEqual(self.a.state['ClientTLSFailures'],20)
 def test_tls_state_not_asserted(self):
  d=self.data();self.a.tls_clienthello(d);self.a.tls_failed_client(d);r=self.a.state['TLSFailureDetails'][0];self.assertFalse(r['ClientTLSEstablished']);self.assertFalse(r['ServerTLSEstablished']);self.assertFalse(r['RootCauseEstablished'])
if __name__=='__main__':unittest.main(verbosity=2)
