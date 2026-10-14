# Metadata/BLTE helpers from the previous staging prototype; no native extraction engine.

import hashlib, re, ssl, struct, urllib.parse, urllib.request, zlib

from pathlib import Path

META='https://eu.version.battle.net/v2/products/wow/'

MAX_MANIFEST=4*1024*1024

HEX=re.compile(r'^[0-9a-fA-F]{32}$')

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
