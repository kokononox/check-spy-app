"""Offline, checksum-verified Encoding metadata readers. No game update writer."""
import hashlib,mmap,struct,zlib
from pathlib import Path
class EncodingError(Exception):pass
MAX_BYTES=512*1024*1024

def digest_file(path,cancel=None):
 h=hashlib.md5()
 with open(path,'rb') as src:
  for b in iter(lambda:src.read(1024*1024),b''):
   if cancel is not None and cancel.is_set():raise EncodingError('Cancelled')
   h.update(b)
 return h.hexdigest()

def decode_stream(src,encoded_size,decoded_size,ckey,ekey,destination,cancel,notify):
 if not 0<encoded_size<=MAX_BYTES or not 0<decoded_size<=MAX_BYTES:raise EncodingError('Encoding metadata exceeds supported size')
 part=Path(str(destination)+'.part');read=0;written=0;whole_encoded=hashlib.md5();decoded_hash=hashlib.md5()
 def take(n):
  nonlocal read
  if cancel.is_set():raise EncodingError('Cancelled')
  if n<0 or read+n>encoded_size:raise EncodingError('Encoded metadata bounds exceeded')
  b=src.read(n)
  if len(b)!=n:raise EncodingError('Incomplete encoded metadata')
  read+=n;whole_encoded.update(b);return b
 header=take(8)
 if header[:4]!=b'BLTE':raise EncodingError('Local metadata is not BLTE')
 hs=int.from_bytes(header[4:8],'big');chunks=[]
 if hs:
  if hs<12 or hs>min(encoded_size,16*1024*1024):raise EncodingError('Invalid BLTE header size')
  header+=take(hs-8)
  count=int.from_bytes(header[9:12],'big')
  if header[8]!=15 or count<1 or hs!=12+24*count:raise EncodingError('Invalid BLTE chunk table')
  if hashlib.md5(header).hexdigest()!=ekey.lower():raise EncodingError('Full Encoding EKey header checksum mismatch')
  for i in range(count):
   off=12+24*i;cs,ds=struct.unpack_from('>II',header,off);chunks.append((cs,ds,header[off+8:off+24]))
  if sum(x[0] for x in chunks)+hs!=encoded_size or sum(x[1] for x in chunks)!=decoded_size:raise EncodingError('BLTE metadata size mismatch')
 else:chunks=[(encoded_size-8,decoded_size,None)]
 with part.open('wb') as out:
  def emit(b):
   nonlocal written
   if written+len(b)>decoded_size:raise EncodingError('Decoded metadata exceeded expected size')
   out.write(b);decoded_hash.update(b);written+=len(b)
  for i,(cs,ds,checksum) in enumerate(chunks):
   if cs<1:raise EncodingError('Empty BLTE metadata chunk')
   begin=written;chunk_hash=hashlib.md5();mode=take(1);chunk_hash.update(mode);left=cs-1
   if mode not in (b'N',b'Z'):raise EncodingError('Encrypted or unsupported Encoding metadata; no bypass attempted')
   dec=zlib.decompressobj() if mode==b'Z' else None
   while left:
    b=take(min(65536,left));left-=len(b);chunk_hash.update(b)
    if dec is None:emit(b)
    else:
     pending=b
     while pending:
      piece=dec.decompress(pending,1024*1024);emit(piece);pending=dec.unconsumed_tail
      if dec.unused_data:raise EncodingError('Unexpected compressed metadata trailing bytes')
      if cancel.is_set():raise EncodingError('Cancelled')
   if dec is not None:
    emit(dec.flush())
    if not dec.eof or dec.unused_data:raise EncodingError('Incomplete compressed metadata')
   if written-begin!=ds:raise EncodingError('Decoded chunk size mismatch')
   if checksum is not None and chunk_hash.digest()!=checksum:raise EncodingError('Encoding chunk checksum mismatch')
   notify('Verified metadata chunk '+str(i+1)+' / '+str(len(chunks)))
 if read!=encoded_size or written!=decoded_size or decoded_hash.hexdigest()!=ckey.lower():raise EncodingError('Decoded Encoding metadata CKey mismatch')
 if not hs and whole_encoded.hexdigest()!=ekey.lower():raise EncodingError('Encoding EKey checksum mismatch')
 part.replace(destination);return Path(destination)

class EncodingTable:
 def __init__(self,path):
  self.file=open(path,'rb');self.map=mmap.mmap(self.file.fileno(),0,access=mmap.ACCESS_READ);d=self.map
  try:
   if len(d)<22 or d[:5]!=b'EN\x01\x10\x10' or d[17]!=0:raise EncodingError('Unsupported Encoding table header')
   self.cps=int.from_bytes(d[5:7],'big')*1024;self.eps=int.from_bytes(d[7:9],'big')*1024
   self.cn=int.from_bytes(d[9:13],'big');self.en=int.from_bytes(d[13:17],'big');espec=int.from_bytes(d[18:22],'big')
   if not 1024<=self.cps<=65536 or not 1024<=self.eps<=65536 or self.cn>500000 or self.en>500000:raise EncodingError('Unsupported Encoding table bounds')
   self.cindex=22+espec;self.cpages=self.cindex+32*self.cn;self.eindex=self.cpages+self.cps*self.cn;self.epages=self.eindex+32*self.en
   if self.epages+self.eps*self.en>len(d):raise EncodingError('Truncated Encoding page tables')
  except Exception:self.close();raise
 def close(self):self.map.close();self.file.close()
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
 def c_records(self,cancel,notify):
  d=self.map;last=None
  for i in range(self.cn):
   if cancel.is_set():raise EncodingError('Cancelled')
   start=self.cpages+i*self.cps;page=d[start:start+self.cps];index=d[self.cindex+32*i:self.cindex+32*i+32]
   if hashlib.md5(page).digest()!=index[16:]:raise EncodingError('CKey page checksum mismatch')
   pos=0;first=True
   while pos<len(page):
    count=page[pos]
    if count==0:
     if any(page[pos:]):raise EncodingError('Unexpected CKey page padding')
     break
    end=pos+22+16*count
    if end>len(page):raise EncodingError('CKey record crosses page boundary')
    size=int.from_bytes(page[pos+1:pos+6],'big');ck=page[pos+6:pos+22]
    if first and ck!=index[:16]:raise EncodingError('CKey page index mismatch')
    if last is not None and ck<=last:raise EncodingError('CKeys are not strictly ordered')
    first=False;last=ck
    yield ck,size,[page[at:at+16] for at in range(pos+22,end,16)]
    pos=end
   if i%500==0:notify('Reading CKey pages '+str(i+1)+' / '+str(self.cn))
 def e_sizes(self,wanted,cancel,notify):
  found={};d=self.map;last=None
  for i in range(self.en):
   if cancel.is_set():raise EncodingError('Cancelled')
   start=self.epages+i*self.eps;page=d[start:start+self.eps];index=d[self.eindex+32*i:self.eindex+32*i+32];first=True
   if hashlib.md5(page).digest()!=index[16:]:raise EncodingError('EKey page checksum mismatch')
   consumed=0
   for pos in range(0,len(page)-24,25):
    ek=page[pos:pos+16]
    if ek==b'\0'*16:
     # Verified official tables use a zero EKey, ESpec index -1 and size 0
     # as an end marker. Accept only that marker or wholly zero padding.
     if page[pos+16:pos+20] not in (b'\0'*4,b'\xff'*4) or any(page[pos+20:]):
      raise EncodingError('Unexpected EKey page terminator')
     consumed=len(page)
     break
    if first and ek!=index[:16]:raise EncodingError('EKey page index mismatch')
    if last is not None and ek<=last:raise EncodingError('EKeys are not strictly ordered')
    last=ek
    first=False
    if ek in wanted:found[ek]=int.from_bytes(page[pos+20:pos+25],'big')
    consumed=pos+25
   if any(page[consumed:]):raise EncodingError('Unexpected EKey page trailing bytes')
   if i%500==0:notify('Reading EKey pages '+str(i+1)+' / '+str(self.en))
  return found
