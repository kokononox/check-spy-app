"""Conservative v1 TACT CDN index verifier (normal offsets 4, group offsets 6)."""
import hashlib,bisect
class IndexError(Exception):pass
def locate(data,key,wanted,expected_size,archives=None,cancel=None):
 # Normal and generated group indexes observed with hashBytes=8, 16-byte keys.
 if len(data)<28:raise IndexError('short_index')
 footer=data[-28:];base=footer[8:];rev,f0,f1,bkb,ob,sb,kb,hb=base[:8]
 if (rev,f0,f1,sb,kb,hb)!=(1,0,0,4,16,8) or ob not in (4,6) or not 1<=bkb<=64:raise IndexError('unsupported_index_footer')
 if archives is None and ob!=4:raise IndexError('expected_normal_archive_index')
 if archives is not None and ob!=6:raise IndexError('expected_generated_group_index')
 if hashlib.md5(footer).hexdigest()!=key:raise IndexError('index_name_footer_hash_mismatch')
 if hashlib.md5(base[:12]+bytes(8)).digest()[:8]!=base[12:]:raise IndexError('index_footer_checksum_mismatch')
 n=int.from_bytes(base[8:12],'little');bs=bkb*1024;entry=kb+sb+ob;epb=bs//entry
 if not 0<n<=20000000:raise IndexError('unsupported_element_count')
 blocks=(n+epb-1)//epb;toc_start=blocks*bs
 if len(data)!=toc_start+blocks*(kb+hb)+28:raise IndexError('index_length_mismatch')
 toc=data[toc_start:-28]
 if hashlib.md5(toc).digest()[:8]!=footer[:8]:raise IndexError('index_toc_checksum_mismatch')
 ends=[];last=None
 for i in range(blocks):
  if cancel and cancel.is_set():raise IndexError('cancelled')
  block=data[i*bs:(i+1)*bs];count=min(epb,n-i*epb);end=toc[i*16:(i+1)*16]
  if hashlib.md5(block).digest()[:8]!=toc[blocks*16+i*8:blocks*16+(i+1)*8]:raise IndexError('index_block_checksum_mismatch')
  if block[(count-1)*entry:(count-1)*entry+16]!=end:raise IndexError('index_toc_last_key_mismatch')
  if last is not None and end<last:raise IndexError('index_toc_not_sorted')
  if any(block[count*entry:]):raise IndexError('index_nonzero_padding')
  last=end;ends.append(end)
 # Examine exact-key blocks; grouped indexes can contain duplicate keys.
 i=bisect.bisect_left(ends,wanted);found=[]
 while i<blocks:
  block=data[i*bs:(i+1)*bs];count=min(epb,n-i*epb);last=None;past=False
  for j in range(count):
   off=j*entry;ek=block[off:off+16]
   if ek==bytes(16) or (last is not None and ek<last):raise IndexError('used_index_block_not_sorted')
   last=ek
   if ek>wanted:past=True
   if ek!=wanted:continue
   size=int.from_bytes(block[off+16:off+20],'big');loc=block[off+20:off+entry]
   if size!=expected_size:continue
   if ob==6:
    ai=int.from_bytes(loc[:2],'big');offset=int.from_bytes(loc[2:],'big')
    if ai>=len(archives):raise IndexError('archive_reference_out_of_bounds')
    archive=archives[ai]
   else:archive=key;offset=int.from_bytes(loc,'big')
   if offset+size>2**32:raise IndexError('archive_range_overflow')
   found.append({'archive':archive,'offset':offset,'size':size})
  if past:break
  i+=1
 return found,{'footer_name_hash_verified':True,'footer_checksum_verified':True,'toc_checksum_verified':True,'all_index_block_checksums_verified':True,'used_blocks_order_checked':True,'index_elements':n,'offset_bytes':ob}
