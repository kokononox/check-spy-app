import tempfile,os,subprocess,socket,time,json,pathlib
root=pathlib.Path(tempfile.mkdtemp(prefix='erm-start-'));s=socket.socket();s.bind(('127.0.0.1',0));port=s.getsockname()[1];s.close()
env=os.environ.copy();env.update(ERM_TLS_SUMMARY=str(root/'summary.json'),ERM_TLS_TARGET='/synthetic.exe',ERM_TLS_PORT=str(port));env.pop('ERM_TLS_IDS',None)
cmd=['/data/qa/v26/venv/bin/mitmdump','-q','--mode','regular','--listen-host','127.0.0.1','--listen-port',str(port),'--set','confdir='+str(root/'ca'),'--set','allow_hosts=(?i)^telemetry-in[.]battle[.]net:443$','--set','ssl_insecure=false','--set','upstream_cert=false','--set','connection_strategy=lazy','--set','flow_detail=0','--set','body_size_limit=2m','-s','../app/Telemetry-Fields.py']
p=subprocess.Popen(cmd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:
 for _ in range(100):
  if (root/'summary.json').exists() and json.loads((root/'summary.json').read_text())['Ready']:break
  if p.poll() is not None:raise RuntimeError(p.communicate()[1].decode()[:800])
  time.sleep(.1)
 assert (root/'ca'/'mitmproxy-ca-cert.cer').exists()
 client=socket.create_connection(('127.0.0.1',port));client.sendall(b'CONNECT telemetry-in.battle.net:443 HTTP/1.1\r\nHost: telemetry-in.battle.net:443\r\n\r\n');response=client.recv(1024);assert b'403' in response;client.close()
 state=json.loads((root/'summary.json').read_text());assert state['AttributionFailures']>0 and not state['Requests']
 print('PASS: production startup options, generated public CA, addon-ready acknowledgement, fail-closed client attribution, no HTTP content captured')
finally:p.terminate();p.wait(timeout=10)
