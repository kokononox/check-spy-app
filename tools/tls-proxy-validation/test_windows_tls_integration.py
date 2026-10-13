"""Real loopback TLS on Windows. Owned fixtures only; no OS CA import or game."""
import argparse, base64, datetime, hashlib, http.client, http.server, ipaddress
import json, os, pathlib, shutil, socket, ssl, subprocess, sys, tempfile, threading, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
BASE=pathlib.Path(__file__).resolve().parent
FIXTURE_BODY=b'{"computername":"SYNTHETIC_FIXTURE_MACHINE","deviceid":"SYNTHETIC_FIXTURE_ID","event":"fixture"}'
FIXTURE_PATH='/owned-fixture?token=SYNTHETIC_QUERY_ONLY'
VENDOR_SHA='36a45aadeb842185b8064b8f0be3730e079c9f9c125bc8be22363332969857bf'

def write_certificates(root):
    now=datetime.datetime.now(datetime.timezone.utc)
    def new_ca(label):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,label)])
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
              .not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True)
              .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
              .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),critical=False)
              .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),critical=True)
              .sign(key,hashes.SHA256()))
        return key,cert
    ca_key,ca=new_ca('Owned loopback fixture CA');_,wrong_ca=new_ca('Unrelated owned fixture CA')
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]))
          .issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False)
          .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),x509.IPAddress(ipaddress.ip_address('127.0.0.1')),x509.IPAddress(ipaddress.ip_address('::1'))]),critical=False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False)
          .add_extension(x509.KeyUsage(True,False,True,False,False,False,False,False,False),critical=True)
          .sign(ca_key,hashes.SHA256()))
    for n,c in [('origin-ca.pem',ca),('wrong-ca.pem',wrong_ca),('origin-cert.pem',cert)]:
        (root/n).write_bytes(c.public_bytes(serialization.Encoding.PEM))
    (root/'origin-key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))

class FixtureState:
    def __init__(self):self.lock=threading.Lock();self.posts=0;self.bodies_match=True
    def observe(self,body):
        with self.lock:self.posts+=1;self.bodies_match &= body==FIXTURE_BODY
    def count(self):
        with self.lock:return self.posts
STATE=FixtureState()
class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def do_POST(self):
        body=self.rfile.read(int(self.headers.get('content-length','0')))
        STATE.observe(body)
        self.send_response(200);self.send_header('Content-Length','2');self.send_header('Connection','close');self.end_headers();self.wfile.write(b'OK')
class IPv6Server(http.server.ThreadingHTTPServer):
    address_family=socket.AF_INET6
    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        super().server_bind()

def start_origin(root):
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(root/'origin-cert.pem'),str(root/'origin-key.pem'))
    servers=[]
    try:
        for cls,address in [(http.server.ThreadingHTTPServer,('127.0.0.1',443)),(IPv6Server,('::1',443))]:
            try:server=cls(address,Handler)
            except OSError:
                if cls is IPv6Server:continue
                raise RuntimeError('Owned loopback fixture port 443 unavailable; no process will be terminated.')
            server.socket=context.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
        return servers
    except BaseException:
        for server in servers:server.shutdown();server.server_close()
        raise

def root_store_snapshot():
    command="@(Get-ChildItem Cert:\\CurrentUser\\Root | ForEach-Object {$_.Thumbprint} | Sort-Object) | ConvertTo-Json -Compress"
    p=subprocess.run(['powershell.exe','-NoLogo','-NoProfile','-Command',command],capture_output=True,timeout=30)
    if p.returncode:raise RuntimeError('Cannot obtain owned runner CA-store snapshot.')
    return p.stdout

def stop_owned_proxy(proc):
    # PyInstaller vendor builds may have a child process. Stop ONLY this live,
    # freshly created fixture process tree, never by image name or an external PID.
    if proc.poll() is None:
        finished=subprocess.run(['taskkill.exe','/PID',str(proc.pid),'/T','/F'],capture_output=True,timeout=20)
        if finished.returncode and proc.poll() is None:
            raise RuntimeError('Owned fixture proxy tree cleanup failed.')
        proc.wait(timeout=20)

def read_summary(path):
    try:return json.loads(path.read_text(encoding='utf-8-sig'))
    except (FileNotFoundError,json.JSONDecodeError):return None

def wait_summary(path,proc,predicate,seconds=35):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        s=read_summary(path)
        if s and predicate(s):return s
        if proc.poll() is not None:raise RuntimeError('Fixture proxy exited unexpectedly; see owned-fixture log if failure.')
        time.sleep(.1)
    raise RuntimeError('Fixture state timed out.')

def run_proxy(exe,root,case,private=False,wrong_target=False,wrong_origin_ca=False):
    directory=root/case;directory.mkdir();port_socket=socket.socket();port_socket.bind(('127.0.0.1',0));port=port_socket.getsockname()[1];port_socket.close()
    # One fixture-only hostname substitution; production source is not weakened.
    source=(BASE/'Telemetry-Fields.py').read_text(encoding='utf-8-sig')
    marker="HOST = 'telemetry-in.battle.net'";assert source.count(marker)==1
    addon=directory/'Telemetry-Fields.py';addon.write_text(source.replace(marker,"HOST = 'localhost'"),encoding='utf-8')
    shutil.copy2(BASE/'TLSFailureDiagnostics.py',directory/'TLSFailureDiagnostics.py')
    env=dict(os.environ);env.update(ERM_TLS_SUMMARY=str(directory/'summary.json'),ERM_TLS_TARGET=str(root/'nonexistent-owned-fixture.exe') if wrong_target else os.path.abspath(sys.executable),ERM_TLS_PORT=str(port),ERM_TLS_IDS='',ERM_TLS_PRIVATE_CAPTURE='1' if private else '0')
    for key in ['SSLKEYLOGFILE','MITMPROXY_SSLKEYLOGFILE','HTTP_PROXY','HTTPS_PROXY','ALL_PROXY']:env.pop(key,None)
    args=[str(exe),'-q','--mode','regular','--listen-host','127.0.0.1','--listen-port',str(port),
          '--set','confdir='+str(directory/'proxy-ca'),'--set','allow_hosts=(?i)^localhost:443$',
          '--set','ssl_insecure=false','--set','upstream_cert=false','--set','connection_strategy=lazy',
          '--set','flow_detail=0','--set','body_size_limit=2m',
          '--set','ssl_verify_upstream_trusted_ca='+str(root/('wrong-ca.pem' if wrong_origin_ca else 'origin-ca.pem')),
          '-s',str(addon)]
    log=(directory/'owned-proxy-log.txt').open('wb')
    proc=subprocess.Popen(args,env=env,stdout=log,stderr=subprocess.STDOUT)
    try:
        wait_summary(directory/'summary.json',proc,lambda s:s.get('Ready'),90)
        ca=directory/'proxy-ca'/'mitmproxy-ca-cert.pem'
        deadline=time.monotonic()+15
        while not ca.exists() and time.monotonic()<deadline:time.sleep(.1)
        if not ca.exists():raise RuntimeError('Owned fixture proxy CA not created.')
        return proc,log,directory,port,ca
    except BaseException:
        stop_owned_proxy(proc)
        log.close();raise

def post(port,host,ca):
    context=ssl.create_default_context(cafile=str(ca));context.minimum_version=ssl.TLSVersion.TLSv1_2
    connection=http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=12)
    connection.set_tunnel(host,443)
    try:
        connection.request('POST',FIXTURE_PATH,body=FIXTURE_BODY,headers={'Content-Type':'application/json','Authorization':'SYNTHETIC_AUTH_ONLY','Cookie':'SYNTHETIC_COOKIE_ONLY'})
        response=connection.getresponse();status=response.status;response.read();return status
    finally:connection.close()

def abort_after_clienthello(port,ca):
    connection=http.client.HTTPConnection('127.0.0.1',port,timeout=10);connection.set_tunnel('localhost',443)
    try:
        connection.connect();context=ssl.create_default_context(cafile=str(ca))
        incoming,outgoing=ssl.MemoryBIO(),ssl.MemoryBIO();engine=context.wrap_bio(incoming,outgoing,server_side=False,server_hostname='localhost')
        try:engine.do_handshake()
        except ssl.SSLWantReadError:pass
        hello=outgoing.read();assert hello
        connection.sock.sendall(hello)
        assert connection.sock.recv(65536),'No TLS server flight received.'
        # Deliberate owned-fixture disconnect, without completing TLS or sending HTTP.
    finally:connection.close()

def validate_public(s):
    text=json.dumps(s)
    for value in ['SYNTHETIC_QUERY_ONLY','SYNTHETIC_AUTH_ONLY','SYNTHETIC_COOKIE_ONLY','SYNTHETIC_FIXTURE_MACHINE','SYNTHETIC_FIXTURE_ID','/owned-fixture']:
        assert value not in text,'Synthetic sensitive value leaked into public report.'
    assert not s['RawContentStored'] and not s['ValuesStored'] and not s['RawTLSErrorStored']
    assert s['AttributionFailures']==0,'Windows live TCP owner/path attribution failed.'


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--mitmdump',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    if os.name!='nt':raise RuntimeError('This integration test must run on Windows.')
    exe=pathlib.Path(args.mitmdump).resolve();assert hashlib.sha256(exe.read_bytes()).hexdigest()==VENDOR_SHA
    result={'FixtureOnly':True,'UserGameExecuted':False,'UserFilesIncluded':False,'OSRootCAImported':False,'TLSVerificationDisabled':False,'ScopeSubstitution':'localhost for owned loopback fixture only','Cases':[],'GameCompatibilityEstablished':False,'GUICAInstallationAndCleanupTested':False}
    store_before=root_store_snapshot()
    with tempfile.TemporaryDirectory(prefix='owned-tls-proxy-fixture-') as temp:
        root=pathlib.Path(temp);write_certificates(root);servers=start_origin(root)
        try:
            for case in ['trusted-client','untrusted-client-ca','disconnect-during-handshake','wrong-target-path','out-of-scope-tunnel','private-owned-fixture','untrusted-origin-ca']:
                proc,log,directory,port,ca=run_proxy(exe,root,case,private=case=='private-owned-fixture',wrong_target=case=='wrong-target-path',wrong_origin_ca=case=='untrusted-origin-ca')
                before=STATE.count();status=None
                try:
                    if case=='untrusted-client-ca':
                        try:post(port,'localhost',root/'wrong-ca.pem')
                        except ssl.SSLCertVerificationError:pass
                        else:raise AssertionError('Untrusted proxy CA was accepted.')
                        s=wait_summary(directory/'summary.json',proc,lambda x:x['ClientTLSFailures']>=1)
                        detail=s['TLSFailureDetails'][-1];assert detail['ScopedClientHelloAuthorized'];assert 'AlertUnknownCA' in detail['ErrorIndicators'];assert not s['Requests'];assert STATE.count()==before
                    elif case=='disconnect-during-handshake':
                        abort_after_clienthello(port,ca)
                        s=wait_summary(directory/'summary.json',proc,lambda x:x['ClientTLSFailures']>=1)
                        detail=s['TLSFailureDetails'][-1];assert detail['ScopedClientHelloAuthorized'];assert set(detail['ErrorIndicators'])&{'HandshakeDisconnectReported','TransportUnexpectedEOF','TransportConnectionReset'};assert not s['Requests'];assert STATE.count()==before
                    elif case=='wrong-target-path':
                        try:post(port,'localhost',ca)
                        except OSError as e:assert '403' in str(e)
                        else:raise AssertionError('Mismatched executable path was allowed.')
                        s=wait_summary(directory/'summary.json',proc,lambda x:x['OtherProcessesBlocked']>=1);assert not s['Requests'];assert STATE.count()==before
                    elif case=='out-of-scope-tunnel':
                        status=post(port,'127.0.0.1',root/'origin-ca.pem');assert status==200
                        s=read_summary(directory/'summary.json');assert not s['Requests'];assert STATE.count()==before+1
                    elif case=='untrusted-origin-ca':
                        try:status=post(port,'localhost',ca)
                        except (OSError,http.client.HTTPException):status=None
                        s=wait_summary(directory/'summary.json',proc,lambda x:x['ServerTLSFailures']>=1)
                        detail=s['TLSFailureDetails'][-1];assert detail['Side']=='Server' and detail['ScopedClientHelloAuthorized'];assert 'LocalCertificateVerifyFailure' in detail['ErrorIndicators'];assert STATE.count()==before
                    else:
                        status=post(port,'localhost',ca);assert status==200
                        s=wait_summary(directory/'summary.json',proc,lambda x:len(x['Requests'])==1 and x['Requests'][0]['ResponseStatus']==200)
                        record=s['Requests'][0];assert record['TLSClientEstablished'];assert record['RawBodyBytes']==len(FIXTURE_BODY);assert set(record['FieldCategories'])>={'ComputerName','DeviceID'};assert STATE.count()==before+1
                        if case=='private-owned-fixture':
                            private=json.loads((directory/'private-requests.json').read_text());entry=private['Requests'][0]
                            assert entry['URL']=='https://localhost'+FIXTURE_PATH
                            assert base64.b64decode(entry['BodyRawBase64'])==FIXTURE_BODY
                            text=json.dumps(private);assert 'SYNTHETIC_AUTH_ONLY' not in text and 'SYNTHETIC_COOKIE_ONLY' not in text
                    validate_public(s)
                    if case!='private-owned-fixture':assert not (directory/'private-requests.json').exists()
                    labels=sorted({label for d in s['TLSFailureDetails'] for label in d['ErrorIndicators']})
                    result['Cases'].append({'Case':case,'Passed':True,'ResponseStatus':status,'ReadableRequestCount':len(s['Requests']),'ClientTLSFailures':s['ClientTLSFailures'],'ServerTLSFailures':s['ServerTLSFailures'],'ErrorIndicators':labels,'OwnOriginReceivedPost':STATE.count()>before,'SafeReportNoSyntheticSensitiveValues':True})
                    print('PASS:',case,flush=True)
                except BaseException:
                    stop_owned_proxy(proc)
                    log.close()
                    print('OWNED-FIXTURE-LOG:',(directory/'owned-proxy-log.txt').read_text(errors='replace')[-7000:],flush=True)
                    raise
                finally:
                    stop_owned_proxy(proc)
                    log.close()
            assert STATE.bodies_match
        finally:
            for server in servers:server.shutdown();server.server_close()
    result['CurrentUserRootStoreUnchanged']=root_store_snapshot()==store_before;assert result['CurrentUserRootStoreUnchanged']
    result['Passed']=True;output=pathlib.Path(args.output);output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2));print('REAL_WINDOWS_TLS_INTEGRATION: PASS',flush=True)
if __name__=='__main__':main()
