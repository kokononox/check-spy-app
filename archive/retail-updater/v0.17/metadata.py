from pathlib import Path

import common as c

import indexes as ix

from encoding import EncodingError,decode_stream,digest_file,MAX_BYTES

class ContentError(Exception):pass

def fields(data):
 out={}
 for line in data.decode('utf-8-sig').splitlines():
  if '=' in line and not line.lstrip().startswith('#'):
   k,v=line.split('=',1);out[k.strip()]=v.split()
 return out

def config(path,key):
 if not path.is_file() or path.stat().st_size>4*1024*1024:raise ContentError('Required build configuration missing/oversized; no download was attempted')
 b=path.read_bytes()
 if c.md5(b)!=key.lower():raise ContentError('Build configuration content hash mismatch')
 result=fields(b)
 if result.get('build-uid')!=['wow']:raise ContentError('Not a Retail WoW build configuration')
 keys=result.get('encoding',[]);sizes=result.get('encoding-size',[])
 if len(keys)!=2 or len(sizes)!=2 or not all(c.HEX.fullmatch(k) for k in keys):raise ContentError('Unsupported Encoding configuration')
 sizes=list(map(int,sizes))
 if not all(0<x<=MAX_BYTES for x in sizes):raise ContentError('Encoding metadata exceeds supported size')
 return {'ckey':keys[0].lower(),'ekey':keys[1].lower(),'decoded':sizes[0],'encoded':sizes[1]}

def valid_decoded(path,spec,cancel):
 if path.stat().st_size!=spec['decoded']:raise EncodingError('Cached Encoding size mismatch')
 before=ix.fingerprint(path)
 if digest_file(path,cancel)!=spec['ckey']:raise EncodingError('Cached Encoding CKey mismatch')
 if ix.fingerprint(path)!=before:raise EncodingError('Encoding file changed during hash verification')
 return path

def metadata(stage,spec,label,output,cancel,notify,installation=None,journal_snapshots=None):
 cache=stage/'cache/tpr/wow/data';decoded=cache/(spec['ekey']+'.decoded');encoded=cache/spec['ekey'];failures=0
 if decoded.is_file():
  try:return valid_decoded(decoded,spec,cancel),'verified_existing_decoded_cache'
  except EncodingError:
   if cancel.is_set():raise
   failures+=1
 if encoded.is_file() and encoded.stat().st_size==spec['encoded']:
  try:
   before=ix.fingerprint(encoded)
   with encoded.open('rb') as src:
    dest=decode_stream(src,spec['encoded'],spec['decoded'],spec['ckey'],spec['ekey'],output/(label+'-encoding.decoded'),cancel,notify)
   if ix.fingerprint(encoded)!=before:raise EncodingError('Encoded metadata cache changed during read')
   return dest,'verified_existing_encoded_cache'
  except EncodingError:
   if cancel.is_set():raise
   failures+=1
 if installation is None:
  raise ContentError('Verified target Encoding metadata is unavailable in the v0.2 cache. No network download was attempted.')
 key=bytes.fromhex(spec['ekey'])[:9];attempts=0
 notify('Locating installed Encoding metadata in local CASC archives…')
 for path,before in journal_snapshots.items():
  if cancel.is_set():raise ContentError('Cancelled')
  bucket=int(path.name[:2],16)
  try:records=ix.parse_idx(path.read_bytes(),bucket)
  except ix.PlanError:continue
  for prefix,archive,offset,total in records:
   if prefix!=key or total-30!=spec['encoded']:continue
   attempts+=1
   if attempts>64:raise ContentError('Too many ambiguous Encoding metadata locations')
   archive_path=installation/'Data/data'/('data.'+str(archive).zfill(3))
   try:
    old=ix.fingerprint(archive_path)
    if offset+total>old[0]:continue
    with archive_path.open('rb') as src:
     src.seek(offset+30)
     dest=decode_stream(src,spec['encoded'],spec['decoded'],spec['ckey'],spec['ekey'],output/(label+'-encoding.decoded'),cancel,notify)
    if ix.fingerprint(archive_path)!=old:raise EncodingError('Local metadata archive changed during read')
    if ix.fingerprint(path)!=before:raise EncodingError('Local journal changed during metadata lookup')
    return dest,'verified_local_archive_metadata'
   except (OSError,EncodingError):
    if cancel.is_set():raise ContentError('Cancelled')
    failures+=1
 raise ContentError('Installed Encoding metadata could not be located and fully hash-verified. No game data was downloaded.')
