import hashlib,re

from pathlib import Path

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
