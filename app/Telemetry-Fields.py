"""Only the named telemetry host is inspected. No raw flows, values, keys, or URLs are written."""
import ctypes, ctypes.wintypes as wt
import datetime, json, os, re, tempfile
from urllib.parse import parse_qsl
from mitmproxy import http
HOST = 'telemetry-in.battle.net'
FIELDS = {
 'username':'WindowsUserOrUserName','computername':'ComputerName','hostname':'HostName',
 'os':'OperatingSystem','osversion':'OSVersion','platform':'Platform','cpu':'CPU','cpumodel':'CPUModel','cpuvendor':'CPUVendor',
 'gpu':'GPU','gpumodel':'GPUModel','memory':'Memory','ram':'RAM','deviceid':'DeviceID','machineid':'MachineID','hardwareid':'HardwareID',
 'hardware':'HardwareFields','systeminfo':'SystemInfo','serialnumber':'SerialNumber','motherboard':'Motherboard','bios':'BIOS','manufacturer':'Manufacturer',
 'accountid':'AccountID','userid':'UserID','sessionid':'SessionID','locale':'Locale','language':'Language','timezone':'Timezone',
 'event':'Event','eventname':'EventName','applicationversion':'ApplicationVersion','appversion':'ApplicationVersion',
 'ipaddress':'IPAddress','macaddress':'MACAddress','installedapps':'InstalledApplications','installedapplications':'InstalledApplications'}
def norm(s): return re.sub('[^a-z0-9]', '', str(s).lower())
def now(): return datetime.datetime.now(datetime.timezone.utc).isoformat()
def owner_pid(source_port, proxy_port):
 if os.name != 'nt': return None
 size=wt.DWORD();api=ctypes.WinDLL('iphlpapi').GetExtendedTcpTable
 api.argtypes=[ctypes.c_void_p,ctypes.POINTER(wt.DWORD),wt.BOOL,wt.ULONG,wt.ULONG,wt.ULONG];api.restype=wt.DWORD
 api(None,ctypes.byref(size),False,2,5,0)
 if not 4 <= size.value <= 16*1024*1024: return None
 buf=ctypes.create_string_buffer(size.value)
 if api(buf,ctypes.byref(size),False,2,5,0):return None
 import struct
 data=buf.raw;n=struct.unpack_from('<I',data)[0]
 if n > (len(data)-4)//24:return None
 for i in range(n):
  state,local,lp,remote,rp,pid=struct.unpack_from('<6I',data,4+24*i)
  port=lambda p:((p&255)<<8)|((p>>8)&255)
  if port(lp)==source_port and port(rp)==proxy_port and remote==0x0100007f:return pid
 return None
def process_path(pid):
 k=ctypes.WinDLL('kernel32',use_last_error=True)
 k.OpenProcess.argtypes=[wt.DWORD,wt.BOOL,wt.DWORD];k.OpenProcess.restype=wt.HANDLE
 k.QueryFullProcessImageNameW.argtypes=[wt.HANDLE,wt.DWORD,wt.LPWSTR,ctypes.POINTER(wt.DWORD)];k.QueryFullProcessImageNameW.restype=wt.BOOL
 k.CloseHandle.argtypes=[wt.HANDLE];k.CloseHandle.restype=wt.BOOL
 handle=k.OpenProcess(0x1000,False,pid)
 if not handle:return None
 try:
  buf=ctypes.create_unicode_buffer(32768);length=wt.DWORD(len(buf))
  return buf.value if k.QueryFullProcessImageNameW(handle,0,buf,ctypes.byref(length)) else None
 finally:k.CloseHandle(handle)
class TelemetryFields:
 def __init__(self):
  self.output=os.environ.get('ERM_TLS_SUMMARY','');self.target=os.environ.get('ERM_TLS_TARGET','');self.port=int(os.environ.get('ERM_TLS_PORT','0'))
  self.ids={};p=os.environ.get('ERM_TLS_IDS','')
  if p:
   with open(p,encoding='utf-8-sig') as f:self.ids=json.load(f)
  self.state={'Version':'2.6','ScopeHost':HOST,'Ready':False,'Requests':[],'ClientTLSFailures':0,'ServerTLSFailures':0,'AttributionFailures':0,'OtherProcessesBlocked':0,'RequestLimitReached':False,'RawContentStored':False,'ValuesStored':False}
  self.trusted_clients=set()
 def save(self):
  if not self.output:return
  fd,temp=tempfile.mkstemp(dir=os.path.dirname(self.output),prefix='summary-',suffix='.tmp')
  try:
   with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(self.state,f,ensure_ascii=True)
   os.replace(temp,self.output)
  finally:
   if os.path.exists(temp):os.unlink(temp)
 def running(self):self.state['Ready']=True;self.save()
 def allowed_client(self, client):
  if client.id in self.trusted_clients:return True
  try:
   pid=owner_pid(client.peername[1],self.port);path=process_path(pid) if pid else None
   if not path:self.state['AttributionFailures']+=1;self.save();return False
   if os.path.normcase(os.path.abspath(path))!=os.path.normcase(os.path.abspath(self.target)):
    self.state['OtherProcessesBlocked']+=1;self.save();return False
   self.trusted_clients.add(client.id);return True
  except Exception:self.state['AttributionFailures']+=1;self.save();return False
 def http_connect(self,flow):
  if not self.allowed_client(flow.client_conn):flow.response=http.Response.make(403,b'Process attribution required')
 def tls_clienthello(self,data):
  address=data.context.server.address
  if not address or str(address[0]).lower()!=HOST or address[1]!=443 or str(data.client_hello.sni or '').lower()!=HOST or not self.allowed_client(data.context.client):
   data.ignore_connection=True
 def tls_failed_client(self,data):
  address=data.context.server.address
  if address and str(address[0]).lower()==HOST:
   self.state['ClientTLSFailures']+=1;self.save()
 def tls_failed_server(self,data):
  address=data.context.server.address
  if address and str(address[0]).lower()==HOST:
   self.state['ServerTLSFailures']+=1;self.save()
 def requestheaders(self,flow):
  address=flow.server_conn.address
  if address and str(address[0]).lower()==HOST and flow.client_conn.tls_established and (flow.request.host.lower()!=HOST or flow.request.port!=443):
   flow.response=http.Response.make(421,b'Out of scoped TLS host')
 def request(self,flow):
  if flow.request.host.lower()!=HOST or flow.request.port!=443:return
  if not self.allowed_client(flow.client_conn):flow.response=http.Response.make(403,b'Process attribution required');return
  if len(self.state['Requests'])>=128:
   self.state['RequestLimitReached']=True;self.save();flow.response=http.Response.make(503,b'Diagnostic limit');return
  req=flow.request;record={'TimeUTC':now(),'Host':HOST,'Method':req.method if req.method in ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'] else 'Other',
   'TLSClientEstablished':bool(flow.client_conn.tls_established),'RawBodyBytes':len(req.raw_content or b''),'BodyFormat':'Not parsed',
   'FieldCategories':[],'LocalIdentifierMatches':[],'AuthorizationHeaderPresent':'authorization' in req.headers,'CookieHeaderPresent':'cookie' in req.headers,
   'ResponseStatus':None,'LimitReached':False}
  cats=set();matches=set();nodes=0
  def value(v):
   if isinstance(v,(str,int,float)) and not isinstance(v,bool):
    for label,expected in self.ids.items():
     if label in ['ComputerName','WindowsUser','OSVersion','CPUModel','GPUModel'] and str(expected) and str(v).strip().casefold()==str(expected).strip().casefold():matches.add(label)
  def walk(obj,depth=0):
   nonlocal nodes
   nodes+=1
   if nodes>10000 or depth>24:record['LimitReached']=True;return
   if isinstance(obj,dict):
    for k,v in obj.items():
     if nodes>10000:record['LimitReached']=True;break
     if norm(k) in FIELDS:cats.add(FIELDS[norm(k)])
     walk(v,depth+1)
   elif isinstance(obj,list):
    for v in obj:
     if nodes>10000:record['LimitReached']=True;break
     walk(v,depth+1)
   else:value(obj)
  try:
   # Query names only; values are compared privately, never persisted.
   for k,v in parse_qsl(req.path.partition('?')[2],max_num_fields=512):
    if norm(k) in FIELDS:cats.add(FIELDS[norm(k)])
    value(v)
   if len(req.raw_content or b'')<=2*1024*1024:
    # Bound decompression; HTTP content can still be binary/protobuf and remain uninterpreted.
    raw=req.raw_content
    if raw is None:raise ValueError('Streamed content unavailable')
    encoding=req.headers.get('content-encoding','').strip().lower()
    if encoding in ('','identity'):body=raw
    elif encoding in ('gzip','deflate'):
     import zlib
     decoder=zlib.decompressobj(31 if encoding=='gzip' else 15)
     body=decoder.decompress(raw,2*1024*1024+1)
     if len(body)<=2*1024*1024 and not decoder.eof:raise ValueError('Incomplete compressed body')
    else:raise ValueError('Unsupported content encoding')
    if len(body)>2*1024*1024:record['BodyFormat']='Decoded body exceeds limit';record['LimitReached']=True
    else:
     ct=req.headers.get('content-type','').lower().split(';')[0].strip()
     if ct=='application/json' or ct.endswith('+json'):
      walk(json.loads(body));record['BodyFormat']='JSON'
     elif ct=='application/x-www-form-urlencoded':
      for k,v in parse_qsl(body.decode('utf-8'),max_num_fields=512):
       if norm(k) in FIELDS:cats.add(FIELDS[norm(k)])
       value(v)
      record['BodyFormat']='Form'
     elif not body:record['BodyFormat']='Empty'
     else:record['BodyFormat']='Binary or unsupported content type'
   else:record['BodyFormat']='Body exceeds limit';record['LimitReached']=True
  except Exception:record['BodyFormat']='Parse failed or unsupported encoding'
  record['FieldCategories']=sorted(cats);record['LocalIdentifierMatches']=sorted(matches)
  self.state['Requests'].append(record);flow.metadata['erm_record']=len(self.state['Requests'])-1;self.save()
 def response(self,flow):
  index=flow.metadata.get('erm_record')
  if index is not None:self.state['Requests'][index]['ResponseStatus']=flow.response.status_code;self.save()
addons=[TelemetryFields()]
