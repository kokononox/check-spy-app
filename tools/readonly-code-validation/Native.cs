using System;
using System.IO;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
namespace HardwareSnapshot {
 public sealed class ReadFailure : Exception {
  public string Reason; public int ErrorCode;
  public ReadFailure(string reason,int code):base(reason){Reason=reason;ErrorCode=code;}
 }
 public static class Native {
  [StructLayout(LayoutKind.Sequential)]
  public struct MBI {
   public IntPtr BaseAddress,AllocationBase;
   public uint AllocationProtect,Padding1;
   public UIntPtr RegionSize;
   public uint State,Protect,Type,Padding2;
  }
  [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr address,out MBI info,UIntPtr size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadProcessMemory(IntPtr h,IntPtr address,[Out] byte[] data,UIntPtr size,out UIntPtr read);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint size);
  public static string ImagePath(IntPtr h) {
   StringBuilder s=new StringBuilder(32768);uint n=32768;
   if(!QueryFullProcessImageName(h,0,s,ref n))throw new ReadFailure("ImageIdentityQueryFailed",Marshal.GetLastWin32Error());
   return s.ToString();
  }
  public static byte[] Read(IntPtr h,ulong address,int size,bool requireExecutable) {
   if(size<1||size>8192||address>0x00007fffffffffffUL||(ulong)size>0x00007fffffffffffUL-address)throw new ReadFailure("ReadLimit",0);
   ulong cursor=address,end=address+(ulong)size;
   while(cursor<end) {
    MBI m;
    if(VirtualQueryEx(h,new IntPtr((long)cursor),out m,new UIntPtr((uint)Marshal.SizeOf(typeof(MBI)))).ToUInt64()==0)
     throw new ReadFailure("RegionQueryFailed",Marshal.GetLastWin32Error());
    ulong regionBase=(ulong)m.BaseAddress.ToInt64(),regionSize=m.RegionSize.ToUInt64();
    if(regionSize==0||regionBase>cursor||regionSize>ulong.MaxValue-regionBase||regionBase+regionSize<=cursor)throw new ReadFailure("InvalidRegion",0);
    if(m.State!=0x1000||(m.Protect&0x100)!=0||(m.Protect&0xff)==1)throw new ReadFailure("GuardOrUnreadablePage",0);
    uint prot=m.Protect&0xff;
    if(requireExecutable&&prot!=0x10&&prot!=0x20&&prot!=0x40&&prot!=0x80)throw new ReadFailure("NotExecutableAtSnapshot",0);
    cursor=Math.Min(end,regionBase+regionSize);
   }
   byte[] b=new byte[size];UIntPtr got;
   if(!ReadProcessMemory(h,new IntPtr((long)address),b,new UIntPtr((uint)size),out got))
    throw new ReadFailure("MemoryReadDeniedOrFailed",Marshal.GetLastWin32Error());
   if(got.ToUInt64()!=(ulong)size)throw new ReadFailure("PartialRead",0);
   return b;
  }
 }
 public sealed class Section {public uint RVA,VirtualBytes,RawOffset,RawBytes,Flags;}
 public sealed class PE {
  public string Path; public uint ImageBytes; public List<Section> Sections=new List<Section>();
  byte[] runtimeFunctions=new byte[0];
  static ushort U16(byte[] b,int i){return BitConverter.ToUInt16(b,i);}
  static uint U32(byte[] b,int i){return BitConverter.ToUInt32(b,i);}
  byte[] FileRead(long offset,int count) {
   if(offset<0||count<0||count>4*1024*1024)throw new InvalidDataException("FileReadLimit");
   using(FileStream f=File.OpenRead(Path)){
    if(offset>f.Length||count>f.Length-offset)throw new InvalidDataException("FileRange");
    f.Position=offset;byte[] b=new byte[count];int done=0;
    while(done<count){int n=f.Read(b,done,count-done);if(n==0)throw new EndOfStreamException();done+=n;}return b;
   }
  }
  public PE(string path) {
   Path=path;byte[] dos=FileRead(0,64);if(U16(dos,0)!=0x5a4d)throw new InvalidDataException("DOS");
   uint nt=U32(dos,60);if(nt>1048576)throw new InvalidDataException("PEOffset");
   byte[] header=FileRead(nt,24);if(U32(header,0)!=0x4550||U16(header,4)!=0x8664)throw new InvalidDataException("NotX64PE");
   int nsec=U16(header,6),opts=U16(header,20);if(nsec<1||nsec>96||opts<240||opts>4096)throw new InvalidDataException("PEBounds");
   byte[] op=FileRead(nt+24,opts);if(U16(op,0)!=0x20b)throw new InvalidDataException("OptionalHeader");
   ImageBytes=U32(op,56);if(ImageBytes<4096)throw new InvalidDataException("ImageSize");
   byte[] sec=FileRead(nt+24+opts,nsec*40);
   for(int i=0;i<nsec;i++){int a=i*40;Section s=new Section();s.VirtualBytes=U32(sec,a+8);s.RVA=U32(sec,a+12);s.RawBytes=U32(sec,a+16);s.RawOffset=U32(sec,a+20);s.Flags=U32(sec,a+36);Sections.Add(s);}
   uint er=U32(op,112+3*8),en=U32(op,112+3*8+4);
   if(en>4*1024*1024||en%12!=0)throw new InvalidDataException("ExceptionDirectoryBounds");
   if(en!=0)runtimeFunctions=ReadRVA(er,(int)en);
  }
  public bool ExecutableRange(uint rva,int n) {
   if(n<1)return false;
   foreach(Section s in Sections) {
    ulong extent=Math.Max(s.VirtualBytes,s.RawBytes);
    if((s.Flags&0x20000000)!=0&&rva>=s.RVA&&(ulong)rva+(uint)n<=(ulong)s.RVA+extent&&(ulong)rva+(uint)n<=ImageBytes)return true;
   }return false;
  }
  public byte[] ReadRVA(uint rva,int count) {
   foreach(Section s in Sections) {
    if(rva>=s.RVA&&(ulong)rva+(uint)count<=(ulong)s.RVA+s.RawBytes)return FileRead((long)s.RawOffset+rva-s.RVA,count);
   }throw new InvalidDataException("RVAWithoutFileBytes");
  }
  public int ExactFunctionBytes(uint rva) {
   int lo=0,hi=runtimeFunctions.Length/12-1;
   while(lo<=hi){int mid=lo+(hi-lo)/2;uint st=U32(runtimeFunctions,mid*12);
    if(st==rva){uint en=U32(runtimeFunctions,mid*12+4);if(en<=st||en-st>1048576)return 0;return (int)(en-st);}
    if(st<rva)lo=mid+1;else hi=mid-1;
   }return 0;
  }
 }
}