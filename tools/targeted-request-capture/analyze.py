"""Local analysis only. Sharing summary contains no bodies, URLs, credentials or field values."""
import base64,json,re,urllib.parse,zlib
MAX_BODY=1024*1024
HARDWARE_KEYS={'cpuvendor','cpubrand','gpuname','memorycpu','memorygpu','memorysharedgpu','osversion','motherboardmanufacturername','boardname','biosvendor','biosreleasedate','biosversion','processorname','totalphysicalmemory','gpudeviceid','gpuvendorid','cpucount','cpucores','cputhreads','ram','cpu','gpu','bios'}
def origin(url):
    try:
        u=urllib.parse.urlsplit(url)
        if u.scheme not in ('http','https') or not u.hostname:return None
        host=u.hostname
        if ':' in host:host='['+host+']'
        return u.scheme+'://'+host+(':'+str(u.port) if u.port else '')
    except ValueError:return None

def hardware_fields(raw,encoding=''):
    if 'gzip' in encoding.lower():
        try:
            decoder=zlib.decompressobj(16+zlib.MAX_WBITS);raw=decoder.decompress(raw,MAX_BODY+1)
            if len(raw)>MAX_BODY or not decoder.eof:return []
        except zlib.error:return []
    try:obj=json.loads(raw.decode('utf-8'))
    except (ValueError,UnicodeError):return []
    found=set();todo=[(obj,0)];visited=0
    while todo and visited<10000:
        obj,depth=todo.pop();visited+=1
        if depth>30:continue
        if isinstance(obj,dict):
            for k,v in obj.items():
                norm=re.sub('[^a-z0-9]','',k.lower())
                if norm in HARDWARE_KEYS:found.add(k[:80])
                todo.append((v,depth+1))
        elif isinstance(obj,list):todo.extend((v,depth+1) for v in obj[:10000])
    return sorted(found)

def parse_http(raw):
    """Parse ONE complete HTTP/1 request; never infer HTTP/2 or binary payload fields."""
    split=raw.find(b'\r\n\r\n')
    if split<0 or split>65536:return None
    try:
        header=raw[:split].decode('iso-8859-1');lines=header.split('\r\n');method,path,version=lines[0].split(' ',2)
        if method not in {'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','CONNECT'} or not version.startswith('HTTP/1.'):return None
        h={}
        for line in lines[1:]:
            k,sep,v=line.partition(':')
            if sep:h[k.lower().strip()]=v.strip()
        # Do not misframe chunked requests as empty or complete.
        if h.get('transfer-encoding'):return None
        size=int(h.get('content-length','0'))
        if not 0<=size<=MAX_BODY or len(raw)<split+4+size:return None
        host=h.get('host');url=path if path.startswith(('http://','https://')) else ('https://'+host+path if host and path.startswith('/') else None)
        return {'method':method,'url':url,'body':raw[split+4:split+4+size],'consumed':split+4+size,'encoding':h.get('content-encoding',''),'urlSource':'HTTP/1 plaintext with Host; HTTPS scheme inferred from TLS/SSPI input'}
    except (ValueError,UnicodeError):return None

def summarize(events):
    hooks=set();results={};plain=[];private=[];streams={};win={}
    for e in events:
        t=e.get('type')
        if t=='hook_installed':hooks.add((e.get('module'),e.get('api')))
        if t=='call_result':results[e.get('callId')]=e
        if t=='request_attempt':
            rec={k:e.get(k) for k in ('callId','requestHandle','method','url','urlSource','stage','elapsedSeconds')};rec['body']=bytearray();rec['bodyCallIds']=[];private.append(rec)
            if rec.get('requestHandle'):win[rec['requestHandle']]=rec
        if t=='plaintext':
            try:b=base64.b64decode(e.get('dataBase64',''),validate=True)
            except ValueError:continue
            plain.append(e)
            if e.get('api') in ('WinHttpSendRequest','WinHttpWriteData'):
                handle=e.get('requestHandle');rec=win.get(handle)
                if rec is None:
                    rec={k:e.get(k) for k in ('callId','requestHandle','method','url','stage','elapsedSeconds')};rec.update(body=bytearray(),bodyCallIds=[],urlSource='URL may be unavailable when attachment happened after handle construction');private.append(rec)
                    if handle:win[handle]=rec
                room=max(0,MAX_BODY-len(rec['body']));rec['body'].extend(b[:room]);rec['bodyCallIds'].append(e.get('callId'));rec['truncated']=rec.get('truncated',False) or e.get('truncated',False) or len(b)>room
            else:
                key=(e.get('api'),e.get('stream'));s=streams.setdefault(key,{'bytes':bytearray(),'meta':e,'callIds':[],'truncated':False})
                if len(s['bytes'])+len(b)>MAX_BODY+65536:s['bytes'].clear();s['callIds'].clear();s['truncated']=True;continue
                s['bytes'].extend(b);s['callIds'].append(e.get('callId'));s['truncated']=s['truncated'] or e.get('truncated',False)
                while True:
                    r=parse_http(bytes(s['bytes']))
                    if not r:break
                    m=s['meta'];r.update(stage=m.get('stage'),elapsedSeconds=m.get('elapsedSeconds'),bodyCallIds=list(s['callIds']),truncated=s['truncated'],api=e.get('api'));private.append(r)
                    del s['bytes'][:r['consumed']];s['callIds']=[];s['meta']=e;s['truncated']=False
    rows=[]
    for n,r in enumerate(private,1):
        body=bytes(r.pop('body',b''));r['bodyBase64']=base64.b64encode(body).decode();r['id']=n
        fields=hardware_fields(body,r.get('encoding',''))
        ids=r.get('bodyCallIds') or [r.get('callId')];accept=[results[i].get('accepted') for i in ids if i in results]
        rows.append({'id':n,'stage':r.get('stage'),'elapsedSeconds':r.get('elapsedSeconds'),'destinationOrigin':origin(r.get('url') or ''),'hardwareFieldNamesInCapturedJSON':fields,'capturedBodyBytes':len(body),'truncated':r.get('truncated',False),'apiResultsObserved':len(accept),'allObservedApiResultsAccepted':all(accept) if accept else None,'serverReceiptProven':False})
    safe={'Version':'1.0','Status':'PlaintextObserved' if plain else 'NoPlaintextObserved','InstalledHooks':[{'module':m,'api':a} for m,a in sorted(hooks)],'PlaintextBufferEvents':len(plain),'ParsedRequestRecords':len(rows),'Requests':rows,'FullURLsAndBodiesIncluded':False,'StageMarkersAreUserSupplied':True,'StaticSchemasNotUsedAsSentData':True,'Limitations':['Only exported APIs were intercepted; static/hidden/custom TLS can be missed.','API acceptance is not server receipt.','HTTP/2, chunked bodies, binary protobuf, encrypted/compressed custom envelopes are not decoded by this prototype.','No observation is not evidence of no transmission.','Repeated nested TLS/SSPI calls may duplicate plaintext.','Capture starts after attach, not at process startup.']}
    return safe,private
