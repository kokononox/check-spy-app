# Separate helper process; never connects the UI host to another console.
# Queues bounded read-only .lastevent/.exr after observed first-chance AV; never interrupts/resumes.
# No force-kill of CDB or target. On failure, leave state explicit for manual recovery.
param([Parameter(Mandatory=$true)][string]$SessionPath)
$ErrorActionPreference='Stop';. (Join-Path $PSScriptRoot 'Session-UI-Core.ps1')
. (Join-Path $PSScriptRoot 'Diagnostic-Core.ps1')
$folder=Split-Path -Parent $SessionPath;$resultPath=Join-Path $folder 'fault-snapshot-result.json'
$ok=$false;$reason='NotStarted';$attached=$false;$stage='IdentityCheck';$snapshotAccepted=$false;$lock=$null
try{
 $d=Get-Content -LiteralPath $SessionPath -Raw|ConvertFrom-Json
 $lock=[IO.File]::Open((Join-Path $folder 'fault-snapshot.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 $stage='ValidateFaultState'
 if(![string]::Equals([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($d.LogPath)),[IO.Path]::GetFullPath($folder),[StringComparison]::OrdinalIgnoreCase)){throw 'Log outside session'}
 $diagnostic=Get-RMDiagnostics (Read-RMLiveLog $d.LogPath)
 if(!$diagnostic.ExceptionPausePossible -or $diagnostic.LastExceptionClass -ne 'AccessViolation' -or $diagnostic.LastExceptionChance -ne 'first' -or !$diagnostic.UserInitialContinueMarker){throw 'Fault state not eligible; no command sent'}
 $snapshotAccepted=$true
 $target=Get-Process -Id $d.TargetId -ErrorAction Stop
 if($target.StartTime.ToUniversalTime().ToString('o') -ne $d.TargetStart){throw 'Target generation changed'}
 $stage='IdentityCheck'
 $p=Get-Process -Id $d.DebuggerId -ErrorAction Stop
 if([IO.Path]::GetFileName($p.MainModule.FileName) -ine 'cdb.exe'){throw 'Not CDB'}
 if($p.StartTime.ToUniversalTime().ToString('o') -ne $d.DebuggerStart -or ![string]::Equals($p.MainModule.FileName,$d.CdbPath,[StringComparison]::OrdinalIgnoreCase)){throw 'Debugger generation/path mismatch'}
 if((Get-FileHash -LiteralPath $p.MainModule.FileName -Algorithm SHA256).Hash -ne $d.CdbSHA256){throw 'Debugger file changed'}
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RMConsoleFault05 {
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
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string name,uint access,uint sharing,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WriteConsoleInputW(IntPtr handle,Input[] input,uint length,out uint written);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 public static bool WriteFaultSnapshot(){
  IntPtr h=CreateFileW("CONIN$",0xc0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);
  if(h==new IntPtr(-1))return false;
  try{
   string cmd=".echo RM_FAULT_RECORD_BEGIN; .lastevent; .exr -1; .echo RM_FAULT_RECORD_END\r";
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
 [void][RMConsoleFault05]::FreeConsole()
 $stage='AttachOwnConsole'
 if(![RMConsoleFault05]::AttachConsole([uint32]$d.DebuggerId)){throw 'Cannot attach to own CDB console'};$attached=$true
 [uint32[]]$ids=New-Object uint32[] 32;$count=[RMConsoleFault05]::GetConsoleProcessList($ids,32)
 if(!$count -or $count -gt 32){throw 'Console scope unavailable'}
 $stage='VerifyConsoleScope'
 $consoleIds=@($ids[0..([int]$count-1)]|ForEach-Object {[int]$_})
 if(!(Test-RMStopConsoleScope $consoleIds ([int]$d.DebuggerId) $PID)){throw 'Console contains unexpected processes; no interrupt sent'}
 $current=Get-Process -Id $d.DebuggerId
 if($current.StartTime.ToUniversalTime().ToString('o') -ne $d.DebuggerStart){throw 'Debugger generation changed'}
 $stage='RevalidateFaultState'
 $latest=Get-RMDiagnostics (Read-RMLiveLog $d.LogPath)
 if(!$latest.ExceptionPausePossible -or $latest.LastExceptionClass -ne 'AccessViolation' -or $latest.LastExceptionChance -ne 'first' -or !$latest.UserInitialContinueMarker){throw 'Fault state changed; no command sent'}
 $stage='QueueReadOnlySnapshot'
 if(![RMConsoleFault05]::WriteFaultSnapshot()){throw 'Fault snapshot not queued'}
 $ok=$true;$reason='ReadOnlySnapshotCommandsQueued'
}catch{
 # Codes only; never export a raw exception that may contain private paths.
 $reason='FaultSnapshotNotConfirmedNoRetry'
}finally{
 if($attached){[void][RMConsoleFault05]::FreeConsole()}
 if($lock){$lock.Dispose()}
 [pscustomobject]@{SnapshotCommandsQueued=$ok;FaultStateAccepted=$snapshotAccepted;Reason=$reason;FailureStage=$(if($ok){'None'}else{$stage});TargetTerminationRequested=$false}|ConvertTo-Json|Set-Content -LiteralPath $resultPath -Encoding UTF8
}
