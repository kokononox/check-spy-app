import os,tempfile,pathlib,threading,ssl,http.server,subprocess,socket,time,json,datetime,requests
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
root=pathlib.Path(tempfile.mkdtemp(prefix='erm-integration-'));key=rsa.generate_private_key(public_exponent=65537,key_size=2048);name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'QA origin only')]);now=datetime.datetime.now(datetime.timezone.utc)
cert=x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName('telemetry-in.battle.net'),x509.DNSName('eu.account.battle.net')]),critical=False).sign(key,hashes.SHA256())
(root/'origin.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM));(root/'origin-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
received=[]
class Handler(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  received.append(self.rfile.read(int(self.headers.get('content-length','0'))));self.send_response(204);self.end_headers()
 def log_message(self,*args):pass
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'origin.pem',root/'origin-key.pem')
class OriginServer(http.server.ThreadingHTTPServer):
 daemon_threads=True
 def get_request(self):
  sock,address=super().get_request();sock.settimeout(3)
  try:return context.wrap_socket(sock,server_side=True),address
  except Exception:sock.close();raise
server=OriginServer(('127.0.0.1',0),Handler);origin_port=server.server_port;threading.Thread(target=server.serve_forever,daemon=True).start()
s=socket.socket();s.bind(('127.0.0.1',0));proxy_port=s.getsockname()[1];s.close()
# Production addon unchanged. QA-only shim replaces PID lookup and routes to a local origin.
shim=root/'qa_shim.py';shim.write_text('import importlib.util\nfrom mitmproxy import ctx\nspec=importlib.util.spec_from_file_location("erm", "../app/Telemetry-Fields.py")\nm=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)\na=m.TelemetryFields();a.allowed_client=lambda c: True\noriginal_hello=a.tls_clienthello\ndef scoped_hello(data):\n saved=data.context.server.address\n data.context.server.address=(data.client_hello.sni or "unknown",443)\n try: original_hello(data)\n finally: data.context.server.address=saved\na.tls_clienthello=scoped_hello\nclass OriginRoute:\n def server_connect(self,data):\n  data.server.address=("127.0.0.1", '+str(origin_port)+')\n  data.server.sni="telemetry-in.battle.net"\naddons=[a,OriginRoute()]\n')
env=os.environ.copy();env.update(ERM_TLS_SUMMARY=str(root/'summary.json'),ERM_TLS_TARGET='/synthetic.exe',ERM_TLS_PORT=str(proxy_port));env.pop('ERM_TLS_IDS',None)
cmd=['/data/qa/v26/venv/bin/mitmdump','-q','--mode','regular','--listen-host','127.0.0.1','--listen-port',str(proxy_port),'--set','confdir='+str(root/'ca'),'--set','allow_hosts=(?i)^telemetry-in[.]battle[.]net:443$','--set','ssl_insecure=false','--set','upstream_cert=false','--set','connection_strategy=lazy','--set','flow_detail=0','--set','body_size_limit=2m','--set','ssl_verify_upstream_trusted_ca='+str(root/'origin.pem'),'-s',str(shim)]
p=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 for _ in range(100):
  if (root/'summary.json').exists() and json.loads((root/'summary.json').read_text())['Ready']:break
  if p.poll() is not None:raise RuntimeError(p.communicate()[1].decode()[:800])
  time.sleep(.1)
 client=requests.Session();client.trust_env=False;client.proxies={'https':'http://127.0.0.1:'+str(proxy_port)}
 response=client.post('https://telemetry-in.battle.net/private?token=SECRET_SENTINEL',json={'cpu_model':'PRIVATE_CPU','account_id':'PRIVATE_ACCOUNT','device_id':'PRIVATE_DEVICE'},headers={'Authorization':'Bearer PRIVATE_TOKEN'},verify=str(root/'ca'/'mitmproxy-ca-cert.pem'),timeout=10);assert response.status_code==204
 # The account host must pass unmodified TLS and accept only the origin certificate here.
 response=client.post('https://eu.account.battle.net/private',json={'password':'PRIVATE_PASSWORD'},verify=str(root/'origin.pem'),timeout=10);assert response.status_code==204
 time.sleep(.5);state=json.loads((root/'summary.json').read_text());assert len(state['Requests'])==1;record=state['Requests'][0];assert record['TLSClientEstablished'] and record['ResponseStatus']==204;assert set(record['FieldCategories'])=={'CPUModel','AccountID','DeviceID'};assert record['AuthorizationHeaderPresent']
 assert 'PRIVATE_' not in json.dumps(state) and 'SECRET_SENTINEL' not in json.dumps(state)
 assert len(received)==2
 print('PASS: real TLS interception of scoped JSON, validated upstream TLS, HTTP response metadata, account host certificate untouched, no private values or paths in summary')
finally:p.terminate();p.wait(timeout=10);server.shutdown()
