import os, tempfile, importlib.util,json,types,gzip
from mitmproxy import http, connection
root=tempfile.mkdtemp(prefix='erm-test-');os.environ['ERM_TLS_SUMMARY']=root+'/summary.json';os.environ['ERM_TLS_TARGET']='/synthetic.exe';os.environ['ERM_TLS_PORT']='7777'
spec=importlib.util.spec_from_file_location('telemetry','../app/Telemetry-Fields.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
a=module.TelemetryFields();a.allowed_client=lambda c:True;a.ids={'ComputerName':'PRIVATE_MACHINE','CPUModel':'PRIVATE_CPU'}
def flow(host='telemetry-in.battle.net',body=b'',content_type='application/json',encoding=''):
 c=connection.Client(peername=('127.0.0.1',12345),sockname=('127.0.0.1',7777));c.tls=True;c.timestamp_tls_setup=1
 f=http.HTTPFlow(c,connection.Server(address=(host,443)));f.request=http.Request.make('POST','https://'+host+'/secret?access_token=PRIVATE_TOKEN',body,{'Content-Type':content_type,'Authorization':'Bearer PRIVATE_TOKEN','Cookie':'PRIVATE_COOKIE'});
 if encoding:f.request.headers['Content-Encoding']=encoding
 return f
f=flow(body=json.dumps({'computer_name':'PRIVATE_MACHINE','cpu_model':'PRIVATE_CPU','account_id':'PRIVATE_ACCOUNT','other':{'serial_number':'PRIVATE_SERIAL'}}).encode());a.request(f);assert a.state['Requests'][0]['TLSClientEstablished'];assert a.state['Requests'][0]['LocalIdentifierMatches']==['CPUModel','ComputerName'];assert 'AccountID' in a.state['Requests'][0]['FieldCategories']
f.response=http.Response.make(204,b'');a.response(f);assert a.state['Requests'][0]['ResponseStatus']==204
before=len(a.state['Requests']);a.request(flow('eu.account.battle.net',b'{"password":"PRIVATE_PASSWORD"}'));assert len(a.state['Requests'])==before
compressed=gzip.compress(json.dumps({'os_version':'PRIVATE_OS'}).encode());a.request(flow(body=compressed,encoding='gzip'));assert a.state['Requests'][-1]['BodyFormat']=='JSON'
a.request(flow(body=gzip.compress(b'x'*(3*1024*1024)),encoding='gzip'));assert a.state['Requests'][-1]['LimitReached']
a.request(flow(body=b'PRIVATE_BINARY',content_type='application/octet-stream'));assert a.state['Requests'][-1]['BodyFormat']=='Binary or unsupported content type'
raw=json.dumps(a.state);assert not any(x in raw for x in ['PRIVATE_','/secret','access_token=','Bearer'])
assert 'Root' not in raw
s=json.loads(open(os.environ['ERM_TLS_SUMMARY']).read());assert s['ValuesStored'] is False and s['RawContentStored'] is False
# No client attribution means no request body is examined/recorded.
b=module.TelemetryFields();b.allowed_client=lambda c:False;blocked=flow(body=b'{"cpu":"PRIVATE"}');b.request(blocked);assert blocked.response.status_code==403 and not b.state['Requests']
# Out-of-scope TLS is forced to passthrough.
data=types.SimpleNamespace(context=types.SimpleNamespace(server=types.SimpleNamespace(address=('eu.account.battle.net',443)),client=None),ignore_connection=False);a.tls_clienthello(data);assert data.ignore_connection
fail=types.SimpleNamespace(context=types.SimpleNamespace(server=types.SimpleNamespace(address=('telemetry-in.battle.net',443))));a.tls_failed_client(fail);assert a.state['ClientTLSFailures']==1
print('PASS: scope, TLS metadata, JSON field categories, exact opt-in identifiers, response status, bounded gzip, binary caveat, no secret values/paths, fail-closed attribution, passthrough scope, TLS failure flag')
