using System;
using System.Runtime.InteropServices;
using System.Text;
class Fixture {
 [StructLayout(LayoutKind.Sequential)] struct Buffer { public uint Size, Type; public IntPtr Data; }
 [StructLayout(LayoutKind.Sequential)] struct Desc { public uint Version, Count; public IntPtr Buffers; }
 [DllImport("secur32.dll", ExactSpelling=true)] static extern int EncryptMessage(IntPtr context,uint qop,IntPtr message,uint sequence);
 static int Main(string[] args){
  if(IntPtr.Size!=8) return 3;
  // Deliberately INVALID context. No credentials, TLS handshake, socket or network send.
  byte[] data=Encoding.ASCII.GetBytes("POST https://fixture.invalid/private?token=DUMMY HTTP/1.1\r\nHost: fixture.invalid\r\nContent-Length: 4\r\n\r\nTEST");
  IntPtr ctx=Marshal.AllocHGlobal(16),payload=Marshal.AllocHGlobal(data.Length),buf=Marshal.AllocHGlobal(16),desc=Marshal.AllocHGlobal(16);
  try {
   Marshal.WriteInt64(ctx,0,0); Marshal.WriteInt64(ctx,8,0); Marshal.Copy(data,0,payload,data.Length);
   Marshal.StructureToPtr(new Buffer{Size=(uint)data.Length,Type=1,Data=payload},buf,false);
   Marshal.StructureToPtr(new Desc{Version=0,Count=1,Buffers=buf},desc,false);
   int status=EncryptMessage(ctx,0,desc,0);
   Console.WriteLine("FIXTURE: invalid-context ABI call only; no TLS or network. Status="+status.ToString("X8"));
   if(args.Length>0 && args[0]=="hold")System.Threading.Thread.Sleep(60000);
   return status==0 ? 4 : 0;
  }finally{Marshal.FreeHGlobal(desc);Marshal.FreeHGlobal(buf);Marshal.FreeHGlobal(payload);Marshal.FreeHGlobal(ctx);}
 }
}
