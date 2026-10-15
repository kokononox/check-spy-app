"""Read/reverify existing staged representations only; no asset outputs."""
import hashlib
from pathlib import Path
import indexes
from payload import verify,PayloadError,MAX_ENCODED
MAX_FILES=5000
class StagingError(Exception):pass

def identify(path,cancel):
 size=path.stat().st_size
 if size>MAX_ENCODED:raise StagingError('size_limit')
 with path.open('rb') as f:
  head=f.read(8)
  if head[:4]==b'BLTE' and len(head)==8:
   hs=int.from_bytes(head[4:],'big')
   if hs:
    if hs<12 or hs>min(size,16*1024*1024):raise StagingError('invalid_header')
    tail=f.read(hs-8)
    if len(tail)!=hs-8:raise StagingError('truncated_header')
    return hashlib.md5(head+tail).digest(),'blte'
  f.seek(0);h=hashlib.md5()
  for b in iter(lambda:f.read(1024*1024),b''):
   if cancel.is_set():raise StagingError('cancelled')
   h.update(b)
 return h.digest(),'blte' if head[:4]==b'BLTE' else 'raw_or_decoded'

def discover(stage):
 result=set()
 patterns=['CDN-Batch-*/Sample-*/verified-target-range-sample.blte','CDN-Range-*/verified-target-range-sample.blte','CDN-Pilot-*/verified-target-sample.blte']
 for pat in patterns:
  for p in stage.glob(pat):result.add(p)
 for p in stage.rglob('verified-Wow.exe.bin'):
  result.add(p)
  if len(result)>MAX_FILES:break
 cache=stage/'cache/tpr/wow/data'
 if cache.is_dir():
  for p in cache.iterdir():
   if p.is_file() and len(p.name)==32 and all(c in '0123456789abcdefABCDEF' for c in p.name):result.add(p)
   if len(result)>MAX_FILES:break
 return sorted(result)

def scan(db,stage,cancel,notify):
 files=discover(stage);stats={'files_discovered':len(files),'files_examined':0,'scan_limit_reached':len(files)>MAX_FILES,'oversized_files_not_checked':0,'unreadable_files':0,'outside_stage_files_skipped':0,'candidate_validation_failures':0,'duplicate_verified_representations':0,'decoded_only_matches_are_not_subtracted':True};snapshots={}
 for i,p in enumerate(files[:MAX_FILES]):
  if cancel.is_set():raise StagingError('cancelled')
  if not p.resolve().is_relative_to(stage):stats['outside_stage_files_skipped']+=1;continue
  notify('Rechecking existing staged/cache file '+str(i+1)+' / '+str(min(len(files),MAX_FILES)))
  try:
   before=indexes.fingerprint(p);key,kind=identify(p,cancel);stats['files_examined']+=1
   row=db.execute('SELECT bytes,ckey,decoded_size FROM candidate WHERE ekey=? AND metadata_status="mapped"',(key,)).fetchone()
   if row and row[1] is not None:
    size,ck,decoded=row
    if before[0]!=size:stats['candidate_validation_failures']+=1;continue
    try:
     with p.open('rb') as f:proof=verify(f,size,decoded,ck,key,cancel)
     if indexes.fingerprint(p)!=before:raise StagingError('staged_file_changed')
     if db.execute('SELECT 1 FROM staged_exact WHERE ekey=?',(key,)).fetchone():stats['duplicate_verified_representations']+=1
     else:db.execute('INSERT INTO staged_exact VALUES (?,?,?,?,?)',(key,str(p.resolve()),size,proof['status'],int(proof['decoded_ckey_verified'])))
     snapshots[p]=before
    except PayloadError as exc:
     if exc.kind=='cancelled':raise StagingError('cancelled')
     if exc.kind=='not_checked_size_limit':stats['oversized_files_not_checked']+=1
     else:stats['candidate_validation_failures']+=1
   elif kind=='raw_or_decoded':
    # A decoded file with matching CKey is useful evidence, NOT an exact target EKey.
    for ek,decoded in db.execute('SELECT ekey,decoded_size FROM candidate WHERE ckey=? AND decoded_size=? AND metadata_status="mapped"',(key,before[0])):
     db.execute('INSERT OR IGNORE INTO staged_decoded VALUES (?,?,?)',(ek,str(p.resolve()),decoded));snapshots[p]=before
   if indexes.fingerprint(p)!=before:raise StagingError('staged_file_changed')
  except StagingError as exc:
   if str(exc) in ('cancelled','staged_file_changed'):raise
   if str(exc)=='size_limit':stats['oversized_files_not_checked']+=1
   else:stats['candidate_validation_failures']+=1
  except OSError:stats['unreadable_files']+=1
 db.commit();return stats,snapshots,files
