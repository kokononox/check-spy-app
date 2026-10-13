using System;
using System.Runtime.InteropServices;
using System.Text;
namespace PageStateOnly {
 public sealed class QueryFailure : Exception {
  public string Reason; public int Code;
  public QueryFailure(string reason,int code):base(reason){Reason=reason;Code=code;}
 }
 public sealed class ModuleInfo {public ulong Base;public uint Bytes;}
 public sealed class RegionInfo {
  public ulong Base,Bytes,AllocationBase;
  public uint State,Protect,Type,AllocationProtect;
  public int ReturnedStructureBytes,ExpectedStructureBytes;
 }
 public static class Native {
  [StructLayout(LayoutKind.Sequential)] struct MBI {
   public IntPtr BaseAddress,AllocationBase;
   public uint AllocationProtect,Padding1;
   public UIntPtr RegionSize;
   public uint State,Protect,Type,Padding2;
  }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct MODULEENTRY {
   public uint Size,ModuleID,ProcessID,GlobalUsage,ProcessUsage;
   public IntPtr Base;public uint Bytes;public IntPtr Module;
   [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string Name;
   [MarshalAs(UnmanagedType.ByValTStr,SizeConst=260)] public string Path;
  }
  [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
  [DllImport("kernel32.dll",SetLastError=true)] public static extern bool CloseHandle(IntPtr handle);
  [DllImport("kernel32.dll",SetLastError=true)] static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr address,out MBI info,UIntPtr bytes);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags,uint pid);
  [DllImport("kernel32.dll",EntryPoint="Module32FirstW",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ModuleFirst(IntPtr snapshot,ref MODULEENTRY entry);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr h,out uint code);
  public static string ImagePath(IntPtr h) {
   StringBuilder s=new StringBuilder(32768);uint n=32768;
   if(!QueryFullProcessImageName(h,0,s,ref n))throw new QueryFailure("ImagePathQueryFailed",Marshal.GetLastWin32Error());
   return s.ToString();
  }
  public static bool IsActive(IntPtr h) {
   uint code;if(!GetExitCodeProcess(h,out code))throw new QueryFailure("ProcessStateQueryFailed",Marshal.GetLastWin32Error());
   return code==259;
  }
  public static ModuleInfo MainModule(int pid,string expectedName) {
   IntPtr s=CreateToolhelp32Snapshot(0x18,(uint)pid);
   if(s==new IntPtr(-1))throw new QueryFailure("ModuleSnapshotFailed",Marshal.GetLastWin32Error());
   try {
    MODULEENTRY e=new MODULEENTRY();e.Size=(uint)Marshal.SizeOf(typeof(MODULEENTRY));
    if(!ModuleFirst(s,ref e))throw new QueryFailure("MainModuleQueryFailed",Marshal.GetLastWin32Error());
    if(!String.Equals(e.Name,expectedName,StringComparison.OrdinalIgnoreCase))throw new QueryFailure("MainModuleNameMismatch",0);
    ModuleInfo m=new ModuleInfo();m.Base=(ulong)e.Base.ToInt64();m.Bytes=e.Bytes;return m;
   }finally{CloseHandle(s);}
  }
  public static RegionInfo Query(IntPtr h,ulong address) {
   if(address>0x00007fffffffffffUL)throw new QueryFailure("AddressRange",0);
   MBI m;int expected=Marshal.SizeOf(typeof(MBI));
   ulong got=VirtualQueryEx(h,new IntPtr((long)address),out m,new UIntPtr((uint)expected)).ToUInt64();
   if(got==0)throw new QueryFailure("RegionQueryFailed",Marshal.GetLastWin32Error());
   if(got!=(ulong)expected)throw new QueryFailure("StructureSizeMismatch",0);
   ulong b=(ulong)m.BaseAddress.ToInt64(),n=m.RegionSize.ToUInt64();
   if(n==0||b>address||n>ulong.MaxValue-b||b+n<=address)throw new QueryFailure("InvalidRegionRange",0);
   RegionInfo r=new RegionInfo();r.Base=b;r.Bytes=n;r.AllocationBase=(ulong)m.AllocationBase.ToInt64();
   r.State=m.State;r.Protect=m.Protect;r.Type=m.Type;r.AllocationProtect=m.AllocationProtect;
   r.ReturnedStructureBytes=(int)got;r.ExpectedStructureBytes=expected;return r;
  }
 }
}