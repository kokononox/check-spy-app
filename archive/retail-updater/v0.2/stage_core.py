"""EU Retail one-file staging prototype. NEVER modifies a game installation."""
import hashlib, json, os, re, shutil, ssl, struct, subprocess, time, urllib.parse, urllib.request, zlib
from datetime import datetime, timezone
from pathlib import Path
META = 'https://eu.version.battle.net/v2/products/wow/'
HEX = re.compile(r'^[0-9a-fA-F]{32}$')
MAX_MANIFEST = 4*1024*1024
class StageError(Exception): pass

def md5(b): return hashlib.md5(b).hexdigest()
def rows(text):
    lines=[s.strip() for s in text.lstrip('\ufeff').splitlines() if s.strip() and not s.lstrip().startswith('#')]
    if len(lines)<2: raise StageError('Empty metadata table')
    head=[s.split('!')[0] for s in lines[0].split('|')]
    if len(set(head))!=len(head): raise StageError('Duplicate metadata columns')
    result=[]
    for line in lines[1:]:
        fields=line.split('|')
        if len(fields)!=len(head): raise StageError('Malformed metadata row')
        result.append(dict(zip(head,fields)))
    return result

def one(items):
    if len(items)!=1: raise StageError('Expected exactly one EU Windows Retail record')
    return items[0]

def local_info(path):
    path=Path(path)
    if path.name!='.build.info' or path.stat().st_size>262144: raise StageError('Select a valid .build.info')
    r=one([r for r in rows(path.read_text(encoding='utf-8-sig')) if r.get('Product')=='wow' and r.get('Active')=='1' and r.get('Branch')=='eu' and 'Windows' in r.get('Tags','') and 'x86_64' in r.get('Tags','')])
    return {'version':r['Version'],'build':r['Build Key'],'installation':path.resolve().parent}

class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, url):
        u=urllib.parse.urlsplit(url)
        if u.scheme!='https' or not (u.hostname or '').endswith('.blizzard.com'): raise StageError('Unsafe CDN redirect')
        return super().redirect_request(req,fp,code,msg,headers,url)

def get(url,limit):
    opener=urllib.request.build_opener(Redirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    with opener.open(urllib.request.Request(url,headers={'User-Agent':'WoW-Retail-Stage/0.2','Cache-Control':'no-cache'}),timeout=40) as r:
        data=r.read(limit+1)
    if len(data)>limit: raise StageError('Metadata exceeds limit')
    return data

def discover():
    r=one([r for r in rows(get(META+'versions',262144).decode('utf-8-sig')) if r.get('Region')=='eu'])
    if not re.fullmatch(r'\d+\.\d+\.\d+\.\d+',r['VersionsName']) or r['VersionsName'].split('.')[-1]!=r['BuildId']: raise StageError('Invalid published version')
    if not HEX.fullmatch(r['BuildConfig']) or not HEX.fullmatch(r['CDNConfig']): raise StageError('Invalid published hashes')
    cdn=one([r for r in rows(get(META+'cdns',262144).decode('utf-8-sig')) if r.get('Name')=='eu'])
    if cdn['Path']!='tpr/wow': raise StageError('Unexpected product path')
    servers=[]
    for raw in cdn['Servers'].split():
        u=urllib.parse.urlsplit(raw)
        if u.scheme=='https' and u.hostname and u.hostname.endswith('.blizzard.com') and u.port in (None,443):
            servers.append('https://'+u.hostname)
    if not servers: raise StageError('No supported official HTTPS CDN')
    return {'version':r['VersionsName'],'build':r['BuildConfig'].lower(),'cdn':r['CDNConfig'].lower(),'servers':list(dict.fromkeys(servers))}

def cdn_bytes(target,kind,key,limit):
    if kind not in ('data','config') or not HEX.fullmatch(key): raise StageError('Invalid CDN object')
    for server in target['servers']:
        try: return get(f'{server}/tpr/wow/{kind}/{key[:2]}/{key[2:4]}/{key}',limit)
        except Exception: pass
    raise StageError('Official CDN download failed (Internet/DNS/TLS or unavailable object)')

def decode_blte(data,max_output=MAX_MANIFEST):
    if len(data)<9 or data[:4]!=b'BLTE': raise StageError('Invalid BLTE magic')
    hs=int.from_bytes(data[4:8],'big')
    def block(b,expected=None):
        if not b: raise StageError('Empty BLTE chunk')
        if b[:1]==b'N': result=b[1:]
        elif b[:1]==b'Z':
            d=zlib.decompressobj(); result=d.decompress(b[1:],max_output+1)
            if len(result)>max_output or d.unconsumed_tail or not d.eof or d.unused_data: raise StageError('Invalid or oversized compressed chunk')
        else: raise StageError('Encrypted/unsupported manifest; no bypass attempted')
        if len(result)>max_output or (expected is not None and len(result)!=expected): raise StageError('BLTE size mismatch')
        return result
    if hs==0: return block(data[8:])
    if len(data)<12 or data[8]!=15: raise StageError('Invalid chunk table')
    count=int.from_bytes(data[9:12],'big')
    if count<1 or hs!=12+24*count or hs>len(data): raise StageError('Invalid BLTE header size')
    pos=hs; output=bytearray()
    for i in range(count):
        off=12+24*i; cs,ds=struct.unpack_from('>II',data,off)
        if cs<1 or pos+cs>len(data) or len(output)+ds>max_output: raise StageError('BLTE chunk exceeds limit')
        b=data[pos:pos+cs]
        if hashlib.md5(b).digest()!=data[off+8:off+24]: raise StageError('BLTE chunk checksum mismatch')
        output.extend(block(b,ds));pos+=cs
    if pos!=len(data): raise StageError('Unexpected BLTE trailing bytes')
    return bytes(output)

def install_entries(data):
    if len(data)<10 or data[:2]!=b'IN' or data[2]!=1 or data[3]!=16: raise StageError('Unsupported install manifest')
    nt,ne=struct.unpack_from('>HI',data,4)
    if nt>1000 or ne>100000: raise StageError('Install manifest exceeds limits')
    pos=10; tags=[];width=(ne+7)//8
    def text():
        nonlocal pos
        end=data.find(b'\x00',pos)
        if end<pos or end-pos>2048: raise StageError('Invalid manifest name')
        try: s=data[pos:end].decode('utf-8')
        except UnicodeError: raise StageError('Invalid manifest text')
        pos=end+1;return s
    for _ in range(nt):
        name=text()
        if pos+2+width>len(data): raise StageError('Truncated install tag')
        kind=int.from_bytes(data[pos:pos+2],'big');pos+=2
        mask=data[pos:pos+width];pos+=width;tags.append((name,kind,mask))
    entries=[]
    for i in range(ne):
        name=text().replace('\\','/')
        if pos+20>len(data): raise StageError('Truncated install entry')
        key=data[pos:pos+16].hex();size=int.from_bytes(data[pos+16:pos+20],'big');pos+=20
        selected=[f'{kind}={label}' for label,kind,mask in tags if mask[i//8]&(1<<(7-i%8))]
        entries.append({'name':name,'ckey':key,'size':size,'tags':selected})
    if pos!=len(data): raise StageError('Unexpected install trailing bytes')
    return entries

def sample_plan(target):
    config=cdn_bytes(target,'config',target['build'],4*1024*1024)
    if md5(config)!=target['build']: raise StageError('Build config checksum mismatch')
    cfg={}
    for line in config.decode('utf-8').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            k,v=line.split('=',1);cfg[k.strip()]=v.split()
    if cfg.get('build-uid')!=['wow'] or not cfg.get('build-name',[''])[0].startswith('WOW-'+target['version'].split('.')[-1]): raise StageError('Build identity mismatch')
    keys=cfg.get('install',[]); sizes=cfg.get('install-size',[])
    if len(keys)!=2 or len(sizes)!=2 or not all(HEX.fullmatch(x) for x in keys): raise StageError('Unsupported install config')
    encoded=cdn_bytes(target,'data',keys[1],MAX_MANIFEST)
    if len(encoded)!=int(sizes[1]): raise StageError('Encoded manifest size mismatch')
    decoded=decode_blte(encoded)
    if len(decoded)!=int(sizes[0]) or md5(decoded)!=keys[0]: raise StageError('Install manifest checksum mismatch')
    candidates=[e for e in install_entries(decoded) if e['name'].lower()=='wow.exe']
    # Select the Windows x64 entry, never blindly select an alternative regional/platform executable.
    candidates=[e for e in candidates if any(t.split('=',1)[1].lower()=='windows' for t in e['tags']) and any(t.split('=',1)[1].lower() in ('x86_64','64bit','x64') for t in e['tags'])]
    candidates=[e for e in candidates if '4=EU' in e['tags']]
    entry=one(candidates)
    regional=[t.split('=',1)[1].upper() for t in entry['tags'] if t.startswith('4=')]
    if regional and 'EU' not in regional and 'US' not in regional: raise StageError('Unsupported regional executable')
    if entry['size']<1024 or entry['size']>200*1024*1024: raise StageError('Unexpected sample size')
    return entry,config,decoded

def sha_file(path,algorithm='sha256'):
    h=hashlib.new(algorithm)
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def stage_directory(destination,installation):
    dest=Path(destination).resolve();install=Path(installation).resolve()
    if dest==install or dest.is_relative_to(install) or install.is_relative_to(dest): raise StageError('Staging must be separate from the installation')
    if shutil.disk_usage(dest).free<2*1024**3: raise StageError('At least 2 GiB free staging space required')
    run=dest/('Retail-stage-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex())
    run.mkdir();return run

def extract(tool,run,target,entry,cancel,notify,expected_tool_hash):
    if sha_file(tool)!=expected_tool_hash: raise StageError('Bundled TACTTool checksum mismatch')
    candidate=run/'candidate-Wow.exe'
    cmd=[str(Path(tool).resolve()),'-p','wow','-r','eu','-l','enUS','-b',target['build'],'-c',target['cdn'],'-m','ckey','-i',entry['ckey'],'-o',str(candidate)]
    # No --basedir: tool never receives the installed game's path.
    flags=getattr(subprocess,'CREATE_NO_WINDOW',0) if os.name=='nt' else 0
    with (run/'TACTTool-private.log').open('w',encoding='utf-8') as log:
        proc=subprocess.Popen(cmd,cwd=run,stdout=log,stderr=subprocess.STDOUT,creationflags=flags)
        start=time.monotonic()
        try:
            while proc.poll() is None:
                if cancel.is_set() or time.monotonic()-start>1200:
                    proc.terminate()
                    try: proc.wait(timeout=10)
                    except subprocess.TimeoutExpired: proc.kill();proc.wait()
                    raise StageError('Cancelled or 20-minute timeout. Partial files remain in staging only.')
                time.sleep(.3)
        finally:
            if proc.poll() is None: proc.kill();proc.wait()
    # Upstream may print an extraction failure and still exit 0. Do not trust exit status alone.
    if proc.returncode!=0 or not candidate.is_file(): raise StageError('TACTTool did not produce the sample')
    if candidate.stat().st_size!=entry['size'] or sha_file(candidate,'md5')!=entry['ckey']: raise StageError('Sample size/content hash verification failed. DO NOT USE this file.')
    with candidate.open('rb') as f:
        if f.read(2)!=b'MZ': raise StageError('Sample is not a PE executable')
    sample=run/'verified-Wow.exe.bin'
    candidate.rename(sample)
    return {'name':sample.name,'size':entry['size'],'content_md5_verified':True,'sha256':sha_file(sample),'executed':False}
