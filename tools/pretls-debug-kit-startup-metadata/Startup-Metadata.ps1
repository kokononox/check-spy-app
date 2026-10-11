# Read-only metadata for the recorded target, plus bounded read-only CDB stack commands.
# Never interrupts, resumes, changes a gate, patches memory or terminates any process.
param([Parameter(Mandatory=$true)][string]$SessionPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Session-UI-Core.ps1')
. (Join-Path $PSScriptRoot 'Diagnostic-Core.ps1')
. (Join-Path $PSScriptRoot 'Startup-Metadata-Core.ps1')
$folder=Split-Path -Parent $SessionPath;$stage='ValidateState';$lock=$null;$attached=$false
$safe=[pscustomobject]@{Collection='NotConfirmed';FailureStage='ValidateState';MainExecutable=$null;Loader=$null;SystemNtdll=$null;EventThreadQuery='NotEstablished';EventThreadStartClass='NotEstablished';SystemNtdllFileMatchToHelper=$false;SystemNtdllSignatureVerified=$false;ContextCommandsQueued=$false;DiskHashesAreNotMemoryIdentity=$true;BreakpointOrigin='NotEstablished';ContinuationAuthorized=$false}
$private=[ordered]@{ModuleFiles=@();EventThreadId=$null;ThreadStartAddress=$null;ThreadCreationUTC=$null}
function Test-StartupState($Session){
 if(![string]::Equals([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Session.LogPath)),[IO.Path]::GetFullPath($folder),[StringComparison]::OrdinalIgnoreCase)){throw 'Log outside session'}
 $text=Read-RMLiveLog $Session.LogPath;$diag=Get-RMDiagnostics $text;$ev=Get-RMInitialEventIdentity $text
 if(!$diag.InitialWaiting -or $diag.UserInitialContinueMarker -or $diag.PromptContinueCommands -gt 0 -or $diag.InitialGate -notin @('ExpectedInitialBreakAwaitingUser','InitialBreakLocationUnverified') -or !$ev.Complete -or $ev.Code -ne '80000003' -or $ev.Chance -ne 'first' -or $ev.ProcessId -ne [uint32]$Session.TargetId -or !$ev.ThreadId){throw 'Expected initial snapshot not available'}
 return $ev
}
function Get-LocalFileFingerprint([string]$Path){
 if(!$Path -or $Path.StartsWith('\\')){throw 'Network path not hashed'}
 $root=[IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path));$drive=New-Object IO.DriveInfo($root)
 if($drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable,[IO.DriveType]::Ram)){throw 'Nonlocal drive'}
 $f=Get-Item -LiteralPath $Path
 return [pscustomobject]@{SHA256=(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant();FileBytes=$f.Length}
}
try{
 if($env:OS -ne 'Windows_NT' -or ![Environment]::Is64BitProcess){throw 'Windows x64 required'}
 $session=Get-Content -LiteralPath $SessionPath -Raw|ConvertFrom-Json
 $lock=[IO.File]::Open((Join-Path $folder 'startup-metadata.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 $event=Test-StartupState $session;$private.EventThreadId=$event.ThreadId
 $stage='TargetIdentity';$target=Get-Process -Id $session.TargetId
 if($target.StartTime.ToUniversalTime().ToString('o') -ne $session.TargetStart){throw 'Target generation mismatch'}
 $stage='DebuggerIdentity';$cdb=Get-Process -Id $session.DebuggerId
 if([IO.Path]::GetFileName($cdb.MainModule.FileName) -ine 'cdb.exe' -or $cdb.StartTime.ToUniversalTime().ToString('o') -ne $session.DebuggerStart -or ![string]::Equals($cdb.MainModule.FileName,$session.CdbPath,[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash -LiteralPath $cdb.MainModule.FileName -Algorithm SHA256).Hash -ne $session.CdbSHA256){throw 'CDB identity mismatch'}
 $stage='EnumerateModules';$modules=@($target.Modules);$ranges=@();$loader=$null;$ntdll=$null
 foreach($m in $modules){
  $kind=if($m.BaseAddress -eq $target.MainModule.BaseAddress){'MainExecutable'}elseif($m.ModuleName -ieq 'wow_loader.dll'){'Loader'}elseif($m.ModuleName -ieq 'ntdll.dll'){'SystemNtdll'}else{'Other'}
  $ranges+=[pscustomobject]@{Kind=$kind;Base=[uint64]$m.BaseAddress.ToInt64();Size=[uint64]$m.ModuleMemorySize}
  if($kind -eq 'Loader'){$loader=$m};if($kind -eq 'SystemNtdll'){$ntdll=$m}
 }
 $baseline=$null;$baselinePath=Join-Path $PSScriptRoot 'OfflineBaseline-safe.json'
 if(Test-Path -LiteralPath $baselinePath){try{if((Get-Item $baselinePath).Length -le 4096){$baseline=Get-Content $baselinePath -Raw|ConvertFrom-Json}}catch{}}
 $stage='HashModuleFiles'
 foreach($entry in @(@('MainExecutable',$target.MainModule),@('Loader',$loader),@('SystemNtdll',$ntdll))){
  $kind=$entry[0];$module=$entry[1];$item=[pscustomobject]@{Present=($null -ne $module);SHA256=$null;FileBytes=$null;MatchesSuppliedBaseline=$null}
  if($module){try{
   $fp=Get-LocalFileFingerprint $module.FileName;$item.SHA256=$fp.SHA256;$item.FileBytes=$fp.FileBytes
   $expected=if($kind -eq 'Loader'){$baseline.LoaderSHA256}elseif($kind -eq 'MainExecutable'){$baseline.MainSHA256}else{$null}
   if($expected -is [string] -and $expected -cmatch '^[0-9A-Fa-f]{64}$'){$item.MatchesSuppliedBaseline=($item.SHA256 -ieq $expected)}
   $private.ModuleFiles+=@{Kind=$kind;Path=$module.FileName;BaseAddress=('0x'+$module.BaseAddress.ToInt64().ToString('x'));FileSHA256=$fp.SHA256}
  }catch{}}
  $safe.$kind=$item
 }
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RMStartupRead06 {
 [StructLayout(LayoutKind.Sequential)] public struct FT { public uint Low,High; }
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenThread(uint access,bool inherit,uint tid);
 [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessIdOfThread(IntPtr thread);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetThreadTimes(IntPtr thread,out FT creation,out FT exit,out FT kernel,out FT user);
 [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr thread,int info,out IntPtr value,uint length,out uint returned);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr GetModuleHandleW(string name);
 [DllImport("kernel32.dll",CharSet=CharSet.Ansi,ExactSpelling=true)] public static extern IntPtr GetProcAddress(IntPtr module,string name);
 public static string ReadThreadStart(uint tid,uint expectedPid,out ulong address,out long creation){
  address=0;creation=0;IntPtr h=OpenThread(0x0040,false,tid);if(h==IntPtr.Zero)return "OpenThreadUnavailable";
  try{
   if(GetProcessIdOfThread(h)!=expectedPid)return "OwnerMismatch";
   FT c,e,k,u;if(!GetThreadTimes(h,out c,out e,out k,out u))return "ThreadTimesUnavailable";
   creation=(long)(((ulong)c.High<<32)|c.Low);
   IntPtr value;uint length;int status=NtQueryInformationThread(h,9,out value,(uint)IntPtr.Size,out length);
   if(status!=0 || length!=(uint)IntPtr.Size || value==IntPtr.Zero)return "NativeQueryUnavailable";
   address=(ulong)value.ToInt64();return "Success";
  }finally{CloseHandle(h);}
 }
 [StructLayout(LayoutKind.Explicit,CharSet=CharSet.Unicode,Size=20)] public struct Input {
  [FieldOffset(0)] public ushort EventType;[FieldOffset(4)] public int KeyDown;[FieldOffset(8)] public ushort Repeat;
  [FieldOffset(10)] public ushort VirtualKey;[FieldOffset(12)] public ushort Scan;[FieldOffset(14)] public char Character;[FieldOffset(16)] public uint Control;
 }
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool FreeConsole();
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool AttachConsole(uint processId);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint GetConsoleProcessList([Out] uint[] ids,uint count);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WriteConsoleInputW(IntPtr handle,Input[] input,uint length,out uint written);
 public static bool QueueContext(){
  string cmd=".echo RM_CONTEXT_BEGIN; .lastevent; ~.; kv 0x8; .echo RM_CONTEXT_END\r";
  IntPtr h=CreateFileW("CONIN$",0xc0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);if(h==new IntPtr(-1))return false;
  try{Input[] events=new Input[cmd.Length*2];for(int i=0;i<cmd.Length;i++){Input k=new Input();k.EventType=1;k.KeyDown=1;k.Repeat=1;k.Character=cmd[i];k.VirtualKey=(ushort)(cmd[i]=='\r'?13:0);events[2*i]=k;k.KeyDown=0;events[2*i+1]=k;}uint n;return WriteConsoleInputW(h,events,(uint)events.Length,out n)&&n==events.Length;}finally{CloseHandle(h);}
 }
}
'@
 $stage='QueryEventThread';[uint64]$startAddress=0;[long]$creation=0
 $safe.EventThreadQuery=[RMStartupRead06]::ReadThreadStart([uint32]$event.ThreadId,[uint32]$session.TargetId,[ref]$startAddress,[ref]$creation)
 if($safe.EventThreadQuery -eq 'Success'){
  $threadTime=[datetime]::FromFileTimeUtc($creation)
  if($threadTime -lt $target.StartTime.ToUniversalTime() -or $threadTime -gt [datetime]::UtcNow){$safe.EventThreadQuery='ThreadGenerationUnverified'}else{
   $private.ThreadStartAddress=('0x'+$startAddress.ToString('x'));$private.ThreadCreationUTC=$threadTime.ToString('o')
   $expectedAddress=$null
   if($ntdll -and $safe.SystemNtdll.SHA256){try{
    $selfNtdll=@((Get-Process -Id $PID).Modules|Where-Object {$_.ModuleName -ieq 'ntdll.dll'})|Select-Object -First 1
    $selfFp=Get-LocalFileFingerprint $selfNtdll.FileName
    $safe.SystemNtdllFileMatchToHelper=($selfFp.SHA256 -eq $safe.SystemNtdll.SHA256)
    $signature=Get-AuthenticodeSignature -FilePath $selfNtdll.FileName
    $safe.SystemNtdllSignatureVerified=($signature.Status -eq 'Valid' -and $signature.SignerCertificate.Subject -match '(?:^|,\s*)O=Microsoft Corporation(?:,|$)')
    $h=[RMStartupRead06]::GetModuleHandleW('ntdll.dll');$proc=[RMStartupRead06]::GetProcAddress($h,'DbgUiRemoteBreakin')
    if($h -ne [IntPtr]::Zero -and $proc -ne [IntPtr]::Zero -and $safe.SystemNtdllFileMatchToHelper -and $safe.SystemNtdllSignatureVerified){$expectedAddress=[uint64]($ntdll.BaseAddress.ToInt64()+($proc.ToInt64()-$h.ToInt64()))}
   }catch{}}
   $safe.EventThreadStartClass=Get-RMThreadStartClass $startAddress $ranges $expectedAddress ($safe.SystemNtdllFileMatchToHelper -and $safe.SystemNtdllSignatureVerified)
  }
 }
 $stage='RevalidateState';$latest=Test-StartupState $session
 if($latest.ThreadId -ne $event.ThreadId -or (Get-Process -Id $session.TargetId).StartTime.ToUniversalTime().ToString('o') -ne $session.TargetStart -or (Get-Process -Id $session.DebuggerId).StartTime.ToUniversalTime().ToString('o') -ne $session.DebuggerStart){throw 'Generation/event changed'}
 [void][RMStartupRead06]::FreeConsole();$stage='AttachOwnConsole'
 if(![RMStartupRead06]::AttachConsole([uint32]$session.DebuggerId)){throw 'Console unavailable'};$attached=$true
 [uint32[]]$ids=New-Object uint32[] 32;$count=[RMStartupRead06]::GetConsoleProcessList($ids,32);$stage='VerifyConsoleScope'
 if(!$count -or $count -gt 32 -or !(Test-RMStopConsoleScope @($ids[0..([int]$count-1)]|ForEach-Object {[int]$_}) ([int]$session.DebuggerId) $PID)){throw 'Console scope changed'}
 $latest=Test-StartupState $session;if($latest.ThreadId -ne $event.ThreadId){throw 'Event changed before queue'}
 $stage='QueueContext';if(![RMStartupRead06]::QueueContext()){throw 'Read-only context not queued'}
 $safe.ContextCommandsQueued=$true;$safe.Collection='Collected';$safe.FailureStage='None'
}catch{$safe.Collection='NotConfirmed';$safe.FailureStage=$stage}finally{
 if($attached){[void][RMStartupRead06]::FreeConsole()};if($lock){$lock.Dispose()}
 $private|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $folder 'PRIVATE-startup-metadata.json') -Encoding UTF8
 $safe|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $folder 'startup-metadata-safe.json') -Encoding UTF8
}
