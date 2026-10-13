import sys,pathlib,json,base64,unittest,gzip
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from analyze import summarize,parse_http,hardware_fields,origin

def event(body,api='SSL_write',**kw):return dict(type='plaintext',api=api,dataBase64=base64.b64encode(body).decode(),capturedBytes=len(body),callId='c',stream='one',stage='before_login',**kw)
def request(body,path='/collect?token=SYNTHETIC_SECRET'):
 return b'POST '+path.encode()+b' HTTP/1.1\r\nHost: owned.invalid\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
class Tests(unittest.TestCase):
 def test_json(self):self.assertEqual(hardware_fields(b'{"cpu_brand":"fixture","auth_token":"SYNTHETIC_SECRET"}'),['cpu_brand'])
 def test_nested(self):self.assertEqual(hardware_fields(b'{"spec":{"engine_log":{"gpu_name":"fixture"}}}'),['gpu_name'])
 def test_binary(self):self.assertEqual(hardware_fields(b'\x08\x00'),[])
 def test_malformed(self):self.assertEqual(hardware_fields(b'{"cpu_brand"'),[])
 def test_gzip(self):self.assertEqual(hardware_fields(gzip.compress(b'{"memoryCPU":16}'),'gzip'),['memoryCPU'])
 def test_gzip_invalid(self):self.assertEqual(hardware_fields(b'bad','gzip'),[])
 def test_complete(self):self.assertEqual(parse_http(request(b'{"cpu_brand":"fixture"}'))['body'],b'{"cpu_brand":"fixture"}')
 def test_partial(self):self.assertIsNone(parse_http(request(b'abc')[:-1]))
 def test_http2(self):self.assertIsNone(parse_http(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'))
 def test_chunked(self):self.assertIsNone(parse_http(b'POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n'))
 def test_url_private(self):
  s,p=summarize([event(request(b'{"cpu_brand":"fixture","password":"SYNTHETIC_SECRET"}'))]);self.assertNotIn('SYNTHETIC_SECRET',json.dumps(s));self.assertNotIn('/collect',json.dumps(s));self.assertIn('SYNTHETIC_SECRET',p[0]['url'])
 def test_split_tls(self):
  r=request(b'{"gpu_name":"fixture"}');s,p=summarize([event(r[:30]),event(r[30:])]);self.assertEqual(s['ParsedRequestRecords'],1);self.assertEqual(s['Requests'][0]['hardwareFieldNamesInCapturedJSON'],['gpu_name'])
 def test_no_data(self):self.assertEqual(summarize([])[0]['Status'],'NoPlaintextObserved')
 def test_unknown_dest(self):self.assertIsNone(origin('not-a-url'))
 def test_origin_credentials(self):self.assertEqual(origin('https://secret:secret@owned.invalid:443/x?secret=1'),'https://owned.invalid:443')
 def test_false_return(self):
  s,p=summarize([event(request(b'{}')),{'type':'call_result','callId':'c','accepted':False}]);self.assertFalse(s['Requests'][0]['allObservedApiResultsAccepted']);self.assertFalse(s['Requests'][0]['serverReceiptProven'])
 def test_winhttp_chunks(self):
  events=[{'type':'request_attempt','callId':'start','requestHandle':'r','url':'https://owned.invalid/path?token=SYNTHETIC_SECRET','method':'POST'},event(b'{"gpu_',api='WinHttpWriteData',requestHandle='r'),event(b'name":"fixture"}',api='WinHttpWriteData',requestHandle='r')]
  s,p=summarize(events);self.assertEqual(s['Requests'][0]['hardwareFieldNamesInCapturedJSON'],['gpu_name']);self.assertNotIn('SYNTHETIC_SECRET',json.dumps(s))
 def test_no_headers_or_values_in_share(self):
  s,p=summarize([event(request(b'{"cpu_brand":"PRIVATE_CPU_MODEL"}'))]);self.assertNotIn('PRIVATE_CPU_MODEL',json.dumps(s));self.assertNotIn('bodyBase64',json.dumps(s))
 def test_protobuf_not_inferred(self):self.assertEqual(summarize([event(request(b'\x92\x0a\x01A'))])[0]['Requests'][0]['hardwareFieldNamesInCapturedJSON'],[])
 def test_truncated_marked(self):self.assertTrue(summarize([event(request(b'{}'),truncated=True)])[0]['Requests'][0]['truncated'])
 def test_multiple_requests(self):self.assertEqual(summarize([event(request(b'{}')+request(b'{}','/two'))])[0]['ParsedRequestRecords'],2)
 def test_ipv6(self):self.assertEqual(origin('https://[::1]:1234/x'),'https://[::1]:1234')
if __name__=='__main__':unittest.main()
