"""Owned synthetic loopback client, no user programs or external endpoints."""
import ctypes,ctypes.wintypes as w,time,pathlib,sys,json
ready=pathlib.Path(sys.argv[1]);port=int(sys.argv[2]);deadline=time.monotonic()+45
while not ready.exists() and time.monotonic()<deadline:time.sleep(.1)
if not ready.exists():raise RuntimeError('fixture start timed out')
d=ctypes.WinDLL('winhttp',use_last_error=True);P=ctypes.c_void_p;D=w.DWORD
for name,restype,args in [
 ('WinHttpOpen',P,[w.LPCWSTR,D,w.LPCWSTR,w.LPCWSTR,D]),
 ('WinHttpConnect',P,[P,w.LPCWSTR,w.WORD,D]),
 ('WinHttpOpenRequest',P,[P,w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,w.LPCWSTR,P,D]),
 ('WinHttpSendRequest',w.BOOL,[P,w.LPCWSTR,D,P,D,D,P]),
 ('WinHttpWriteData',w.BOOL,[P,P,D,ctypes.POINTER(D)]),
 ('WinHttpReceiveResponse',w.BOOL,[P,P]),
 ('WinHttpCloseHandle',w.BOOL,[P])]:
 f=getattr(d,name);f.restype=restype;f.argtypes=args
s=d.WinHttpOpen('OwnedCaptureFixture',1,None,None,0);assert s
c=d.WinHttpConnect(s,'127.0.0.1',port,0);assert c
for split in [False,True]:
 body=json.dumps({'cpu_brand':'SYNTHETIC_CPU','gpu_name':'SYNTHETIC_GPU','memoryCPU':16,'auth_token':'SYNTHETIC_SECRET'}).encode();buf=ctypes.create_string_buffer(body)
 r=d.WinHttpOpenRequest(c,'POST','/split' if split else '/probe?token=SYNTHETIC_SECRET',None,None,None,0);assert r
 h='Content-Type: application/json\r\n'
 assert d.WinHttpSendRequest(r,h,len(h),None if split else buf,0 if split else len(body),len(body),None)
 if split:
  mid=len(body)//2
  for part in [body[:mid],body[mid:]]:
   b=ctypes.create_string_buffer(part);n=D();assert d.WinHttpWriteData(r,b,len(part),ctypes.byref(n));assert n.value==len(part)
 assert d.WinHttpReceiveResponse(r,None)
 d.WinHttpCloseHandle(r)
d.WinHttpCloseHandle(c);d.WinHttpCloseHandle(s)
time.sleep(1)
