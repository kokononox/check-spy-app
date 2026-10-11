# Separate helper process; never connects the UI host to another console.
# Stops only the recorded CDB generation in a console shared with this helper and nobody else.
# No force-kill of CDB or target. On failure, leave state explicit for manual recovery.
param([Parameter(Mandatory=$true)][string]$SessionPath)
$ErrorActionPreference='Stop';. (Join-Path $PSScriptRoot 'Session-UI-Core.ps1')
$folder=Split-Path -Parent $SessionPath;$resultPath=Join-Path $folder 'stop-result.json'
$ok=$false;$reason='NotStarted';$attached=$false
try{
 $d=Get-Content -LiteralPath $SessionPath -Raw|ConvertFrom-Json
 $p=Get-Process -Id $d.DebuggerId -ErrorAction Stop
 if([IO.Path]::GetFileName($p.MainModule.FileName) -ine 'cdb.exe'){throw 'Not CDB'}
 if($p.StartTime.ToUniversalTime().ToString('o') -ne $d.DebuggerStart -or ![string]::Equals($p.MainModule.FileName,$d.CdbPath,[StringComparison]::OrdinalIgnoreCase)){throw 'Debugger generation/path mismatch'}
 if((Get-FileHash -LiteralPath $p.MainModule.FileName -Algorithm SHA256).Hash -ne $d.CdbSHA256){throw 'Debugger file changed'}
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RMConsoleStop02 {
 [StructLayout(LayoutKind.Explicit,CharSet=CharSet.Unicode,Size=20)] public struct Input {
  [FieldOffset(0)] public ushort EventType;
  [FieldOffset(4)] public int KeyDown;
  [FieldOffset(8)] public ushort Repeat;
  [FieldOffset(10)] public ushort VirtualKey;
  [FieldOffset(12)] public ushort Scan;
  [FieldOffset(14)] public char Character;
  [FieldOffset(16)] public uint Control;
 }
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool FreeConsole();
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool AttachConsole(uint processId);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint GetConsoleProcessList([Out] uint[] ids,uint count);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool SetConsoleCtrlHandler(IntPtr handler,bool add);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint code,uint group);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string name,uint access,uint sharing,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WriteConsoleInputW(IntPtr handle,Input[] input,uint length,out uint written);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public static bool WriteDetachCommands(){
  IntPtr h=CreateFileW("CONIN$",0xc0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);
  if(h==new IntPtr(-1))return false;
  try{
   string cmd="bc *; .logclose; .detach; q\r";
   Input[] events=new Input[cmd.Length*2];
   for(int i=0;i<cmd.Length;i++){
    Input k=new Input();k.EventType=1;k.KeyDown=1;k.Repeat=1;k.Character=cmd[i];k.VirtualKey=(ushort)(cmd[i]=='\r'?13:0);
    events[2*i]=k;k.KeyDown=0;events[2*i+1]=k;
   }
   uint written;return WriteConsoleInputW(h,events,(uint)events.Length,out written)&&written==events.Length;
  }finally{CloseHandle(h);}
 }
}
'@
 [void][RMConsoleStop02]::FreeConsole()
 if(![RMConsoleStop02]::AttachConsole([uint32]$d.DebuggerId)){throw 'Cannot attach to own CDB console'};$attached=$true
 [uint32[]]$ids=New-Object uint32[] 32;$count=[RMConsoleStop02]::GetConsoleProcessList($ids,32)
 if(!$count -or $count -gt 32){throw 'Console scope unavailable'}
 $consoleIds=@($ids[0..([int]$count-1)]|ForEach-Object {[int]$_})
 if(!(Test-RMStopConsoleScope $consoleIds ([int]$d.DebuggerId) $PID)){throw 'Console contains unexpected processes; no interrupt sent'}
 $current=Get-Process -Id $d.DebuggerId
 if($current.StartTime.ToUniversalTime().ToString('o') -ne $d.DebuggerStart){throw 'Debugger generation changed'}
 [void][RMConsoleStop02]::SetConsoleCtrlHandler([IntPtr]::Zero,$true)
 if(![RMConsoleStop02]::GenerateConsoleCtrlEvent(0,0)){throw 'Debugger interrupt not delivered'}
 Start-Sleep -Milliseconds 1200
 if(![RMConsoleStop02]::WriteDetachCommands()){throw 'Detach commands not queued'}
 if(!$p.WaitForExit(12000)){throw 'Debugger exit not confirmed; manual detach required'}
 $ok=$true;$reason='DebuggerExitedAfterDetachCommands'
}catch{
 # Codes only; never export a raw exception that may contain private paths.
 $reason='StopNotConfirmedManualDetachRequired'
}finally{
 if($attached){[void][RMConsoleStop02]::FreeConsole()}
 [pscustomobject]@{StopConfirmed=$ok;Reason=$reason;TargetTerminationRequested=$false}|ConvertTo-Json|Set-Content -LiteralPath $resultPath -Encoding UTF8
}
