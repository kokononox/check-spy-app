"""Full conservative checksum+order validation of cached TACT v1 indexes."""
import hashlib
class CatalogError(Exception):pass

def matches(data,key,wanted,kind='archive',archives=None,cancel=None):
 if len(data)<28:raise CatalogError('short_index')
 footer=data[-28:];base=footer[8:];rev,f0,f1,bkb,ob,sb,kb,hb=base[:8]
 expected={'archive':4,'group':6,'loose':0}.get(kind)
 if expected is None or (rev,f0,f1,sb,kb,hb)!=(1,0,0,4,16,8) or ob!=expected or not 1<=bkb<=64:raise CatalogError('unsupported_index_footer')
 if hashlib.md5(footer).hexdigest()!=key:raise CatalogError('index_name_footer_hash_mismatch')
 if hashlib.md5(base[:12]+bytes(8)).digest()[:8]!=base[12:]:raise CatalogError('index_footer_checksum_mismatch')
 n=int.from_bytes(base[8:12],'little');bs=bkb*1024;entry=kb+sb+ob;epb=bs//entry
 if not 0<n<=20000000:raise CatalogError('unsupported_element_count')
 blocks=(n+epb-1)//epb;toc_start=blocks*bs
 if len(data)!=toc_start+blocks*(kb+hb)+28:raise CatalogError('index_length_mismatch')
 toc=data[toc_start:-28]
 if hashlib.md5(toc).digest()[:8]!=footer[:8]:raise CatalogError('index_toc_checksum_mismatch')
 found=[];last=None;size_conflicts=0
 for i in range(blocks):
  if cancel and cancel.is_set():raise CatalogError('cancelled')
  block=data[i*bs:(i+1)*bs];count=min(epb,n-i*epb);end=toc[i*16:(i+1)*16]
  if hashlib.md5(block).digest()[:8]!=toc[blocks*16+i*8:blocks*16+(i+1)*8]:raise CatalogError('index_block_checksum_mismatch')
  if block[(count-1)*entry:(count-1)*entry+16]!=end:raise CatalogError('index_toc_last_key_mismatch')
  if any(block[count*entry:]):raise CatalogError('index_nonzero_padding')
  for j in range(count):
   at=j*entry;ek=block[at:at+16];size=int.from_bytes(block[at+16:at+20],'big')
   if ek==bytes(16) or (last is not None and ek<last):raise CatalogError('index_keys_not_sorted')
   last=ek
   if kind=='loose':archive='';offset=-1;route='advertised_direct'
   else:
    loc=block[at+20:at+entry];route='archive_range'
    if kind=='group':
     ai=int.from_bytes(loc[:2],'big')
     if archives is None or ai>=len(archives):raise CatalogError('archive_reference_out_of_bounds')
     archive=archives[ai];offset=int.from_bytes(loc[2:],'big')
    else:archive=key;offset=int.from_bytes(loc,'big')
    if offset+size>2**32:raise CatalogError('archive_range_overflow')
   if ek not in wanted:continue
   if size!=wanted[ek]:size_conflicts+=1;continue
   found.append((ek,route,archive,offset,size))
   if len(found)>1000000:raise CatalogError('matching_location_limit')
 return found,{'full_footer_name_checksum_verified':True,'footer_checksum_verified':True,'toc_checksum_verified':True,'all_block_checksums_verified':True,'all_record_order_and_bounds_checked':True,'index_records':n,'target_size_conflicts':size_conflicts}
