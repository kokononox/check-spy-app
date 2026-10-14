"""Hash-only BLTE verification. Decoded assets are NEVER saved or executed."""
import hashlib,struct,zlib
class PayloadError(Exception):
 def __init__(self,reason,kind='validation_failed'):super().__init__(reason);self.reason=reason;self.kind=kind
MAX_ENCODED=512*1024*1024
MAX_DECODED=2*1024*1024*1024

def verify(src,encoded_size,decoded_size,ckey,ekey,cancel):
 if not 0<=encoded_size<=MAX_ENCODED or not 0<=decoded_size<=MAX_DECODED:raise PayloadError('size_limit','not_checked_size_limit')
 consumed=0;decoded_total=0;encoded_hash=hashlib.md5();decoded_hash=hashlib.md5();unsupported=set();unknown_chunks=0
 def take(n):
  nonlocal consumed
  if cancel.is_set():raise PayloadError('cancelled','cancelled')
  if n<0 or consumed+n>encoded_size:raise PayloadError('encoded_bounds')
  b=src.read(n)
  if len(b)!=n:raise PayloadError('truncated_payload')
  consumed+=n;encoded_hash.update(b);return b
 if ekey==ckey and encoded_size==decoded_size:
  remaining=encoded_size
  while remaining:
   b=take(min(65536,remaining));remaining-=len(b)
  if encoded_hash.digest()!=ckey:raise PayloadError('unencoded_content_hash_mismatch')
  return {'status':'content_verified','reason':'full_unencoded_content_hash_verified','encoded_integrity_verified':True,'decoded_ckey_verified':True,'unsupported_modes_hex':[]}
 header=take(8)
 if header[:4]!=b'BLTE':raise PayloadError('not_blte')
 hs=int.from_bytes(header[4:8],'big')
 if hs:
  if hs<12 or hs>min(encoded_size,16*1024*1024):raise PayloadError('invalid_blte_header')
  header+=take(hs-8);count=int.from_bytes(header[9:12],'big')
  if header[8]!=15 or count<1 or hs!=12+24*count:raise PayloadError('invalid_chunk_table')
  if hashlib.md5(header).hexdigest()!=ekey.hex():raise PayloadError('full_ekey_header_mismatch')
  chunks=[]
  for i in range(count):
   off=12+24*i;cs,ds=struct.unpack_from('>II',header,off);chunks.append((cs,ds,header[off+8:off+24]))
  if sum(x[0] for x in chunks)+hs!=encoded_size or sum(x[1] for x in chunks)!=decoded_size:raise PayloadError('declared_size_mismatch')
 else:chunks=[(encoded_size-8,decoded_size,None)]
 for cs,ds,checksum in chunks:
  if cs<1:raise PayloadError('empty_chunk')
  chunk_hash=hashlib.md5();mode=take(1);chunk_hash.update(mode);remaining=cs-1;chunk_decoded=0
  def emit(b):
   nonlocal chunk_decoded,decoded_total
   chunk_decoded+=len(b);decoded_total+=len(b)
   if chunk_decoded>ds or decoded_total>decoded_size:raise PayloadError('decoded_bounds')
   decoded_hash.update(b)
  decoder=zlib.decompressobj() if mode==b'Z' else None
  supported=mode in (b'N',b'Z')
  if not supported:unsupported.add(mode.hex());unknown_chunks+=1
  while remaining:
   b=take(min(65536,remaining));remaining-=len(b);chunk_hash.update(b)
   if mode==b'N':emit(b)
   elif decoder is not None:
    pending=b
    try:
     while pending:
      part=decoder.decompress(pending,1024*1024);emit(part);pending=decoder.unconsumed_tail
      if decoder.unused_data:raise PayloadError('compressed_trailing_bytes')
      if cancel.is_set():raise PayloadError('cancelled','cancelled')
    except zlib.error:raise PayloadError('decompression_failed')
  if decoder is not None:
   try:emit(decoder.flush())
   except zlib.error:raise PayloadError('decompression_failed')
   if not decoder.eof or decoder.unused_data:raise PayloadError('incomplete_compressed_chunk')
  if supported and chunk_decoded!=ds:raise PayloadError('decoded_chunk_size_mismatch')
  if checksum is not None and chunk_hash.digest()!=checksum:raise PayloadError('encoded_chunk_checksum_mismatch')
 if consumed!=encoded_size:raise PayloadError('encoded_size_mismatch')
 if not hs and encoded_hash.hexdigest()!=ekey.hex():raise PayloadError('full_ekey_mismatch')
 if unknown_chunks:
  return {'status':'encoded_integrity_only','reason':'encrypted_mode' if '45' in unsupported else 'unsupported_compression_mode','encoded_integrity_verified':True,'decoded_ckey_verified':False,'unsupported_modes_hex':sorted(unsupported)}
 if decoded_total!=decoded_size or decoded_hash.digest()!=ckey:raise PayloadError('decoded_ckey_mismatch')
 return {'status':'content_verified','reason':'full_ckey_and_encoding_verified','encoded_integrity_verified':True,'decoded_ckey_verified':True,'unsupported_modes_hex':[]}
