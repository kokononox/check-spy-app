import sys,pathlib,tempfile,http.server,threading,subprocess,time,json
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
import frida
from collect import Recorder,attach_capture,save
class H(http.server.BaseHTTPRequestHandler):
 received=[]
 def do_POST(self):
  self.received.append((self.path,self.rfile.read(int(self.headers['Content-Length']))));self.send_response(200);self.end_headers();self.wfile.write(b'OK')
 def log_message(self,*args):pass
with tempfile.TemporaryDirectory() as td:
 root=pathlib.Path(td);ready=root/'go';out=root/'result';server=http.server.ThreadingHTTPServer(('127.0.0.1',0),H);threading.Thread(target=server.serve_forever,daemon=True).start()
 child=subprocess.Popen([sys.executable,str(pathlib.Path(__file__).with_name('owned_winhttp_fixture.py')),str(ready),str(server.server_port)])
 rec=Recorder(out);session=None;script=None
 try:
  session,script=attach_capture(frida.get_local_device(),child.pid,rec);ready.write_text('go');assert child.wait(timeout=60)==0
  time.sleep(1);script.unload();script=None;session.detach();session=None;rec.close();safe=save(rec.events,out,'OwnedFixtureCompleted')
  assert len(H.received)==2,'Owned server did not receive both known requests'
  assert safe['PlaintextBufferEvents']>=3,safe
  rows=safe['Requests'];assert len(rows)==2,rows
  for r in rows:assert {'cpu_brand','gpu_name','memoryCPU'}<=set(r['hardwareFieldNamesInCapturedJSON']),r
  s=json.dumps(safe);assert 'SYNTHETIC_SECRET' not in s and 'SYNTHETIC_CPU' not in s and '/probe' not in s
  private=json.loads((out/'PRIVATE-requests.json').read_text());assert any('token=SYNTHETIC_SECRET' in (r.get('url') or '') for r in private)
  assert all(r['serverReceiptProven'] is False for r in rows)
  print('PASS: real Frida interception of owned Windows WinHTTP client; optional body and split WriteData body matched owned loopback server; sharing redaction passed. This is not a game/TLS compatibility test.')
 except Exception as exc:
  # Only owned fixture data appear in this public CI annotation. Never run this on user captures.
  detail=type(exc).__name__+": "+str(exc)+" | events: "+str(rec.events[:20])
  print("::error::"+detail.replace("%","%25").replace("\r","%0D").replace("\n","%0A")[:10000],flush=True)
  raise
 finally:
  if script:
   try:script.unload()
   except Exception:pass
  if session:
   try:session.detach()
   except Exception:pass
  if child.poll() is None:child.kill()
  server.shutdown()
