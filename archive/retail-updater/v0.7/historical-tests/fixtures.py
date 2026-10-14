import hashlib,struct,zlib

def table(records,encoded_sizes,marker=True):
 cpage=bytearray();epage=bytearray();records=sorted(records)
 for ck,size,keys in records:cpage.extend(bytes([len(keys)])+size.to_bytes(5,'big')+ck+b''.join(keys))
 cpage.extend(b'\0'*(1024-len(cpage)))
 sizes=sorted(encoded_sizes.items())
 for ek,size in sizes:epage.extend(ek+b'\0'*4+size.to_bytes(5,'big'))
 if marker:epage.extend(b'\0'*16+b'\xff'*4+b'\0'*5)
 epage.extend(b'\0'*(1024-len(epage)))
 head=b'EN\1\x10\x10'+struct.pack('>HHII',1,1,1,1)+b'\0'+struct.pack('>I',2)
 return head+b'z\0'+(records[0][0] if records else b'\0'*16)+hashlib.md5(cpage).digest()+cpage+(sizes[0][0] if sizes else b'\0'*16)+hashlib.md5(epage).digest()+epage

def blte(body,mode=b'N',chunked=False):
 b=mode+(zlib.compress(body) if mode==b'Z' else body)
 if chunked:return b'BLTE'+struct.pack('>I',36)+b'\x0f\0\0\1'+struct.pack('>II',len(b),len(body))+hashlib.md5(b).digest()+b
 return b'BLTE'+b'\0'*4+b

def spec(body,encoded):
 hs=int.from_bytes(encoded[4:8],'big')
 return {'ckey':hashlib.md5(body).hexdigest(),'ekey':hashlib.md5(encoded[:hs] if hs else encoded).hexdigest(),'decoded':len(body),'encoded':len(encoded)}

def idx(entries):
 b=bytearray(40);struct.pack_into('<I',b,0,16);struct.pack_into('<H',b,8,7);b[12:16]=bytes((4,5,9,30));struct.pack_into('<I',b,32,18*len(entries))
 for key,offset,total in entries:b.extend(key[:9]+offset.to_bytes(5,'big')+total.to_bytes(4,'little'))
 return b
