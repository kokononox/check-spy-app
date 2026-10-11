# Independent saved-site code comparison, only while eligible initial break remains paused.
# No callback/frame1/slot dependency. No target interrupt, resume, register write or patch.
param([Parameter(Mandatory=$true)][string]$SessionPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Session-UI-Core.ps1');. (Join-Path $PSScriptRoot 'Diagnostic-Core.ps1');. (Join-Path $PSScriptRoot 'Code-Window-Core.ps1')
$folder=Split-Path -Parent $SessionPath;$stage='ValidateState';$queued=$false;$attached=$false;$lock=$null
function Get-EligibleCodeState($Session){
 if(![string]::Equals([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Session.LogPath)),[IO.Path]::GetFullPath($folder),[StringComparison]::OrdinalIgnoreCase)){throw 'LogOutsideSession'}
 $text=Read-RMLiveLog $Session.LogPath;$diag=Get-RMDiagnostics $text;$ev=Get-RMInitialEventIdentity $text;$ctx=Get-RMContextIndicators $text
 if(!(Test-RMCodeReadEligibility $diag $ev ([uint32]$Session.TargetId)) -or !$ctx.Complete -or !$ctx.CurrentContextMatchesLastEventThread){throw 'InitialSnapshotNotEligible'}
 $inside=$false;$address=$null;$buffer=$false
 foreach($line in ($text -split '\r\n|\r|\n')){if($line.Trim() -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($line.Trim() -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue};if($line.Trim() -eq 'RM_INITIAL_EVENT_BEGIN'){$inside=$true;$address=$null};if($line.Trim() -eq 'RM_INITIAL_EVENT_END'){$inside=$false};if($inside -and $line.Trim() -match '^ExceptionAddress:\s*([0-9a-f`]{8,17})(?:\s|$)'){$address=Convert-RMSlotHex $matches[1]}}
 if(!$address){throw 'InitialAddressUnavailable'}
 return [pscustomobject]@{Event=$ev;ExceptionAddress=$address}
}
try{
 if($env:OS -ne 'Windows_NT' -or ![Environment]::Is64BitProcess){throw 'WindowsX64Required'}
 $session=Get-Content -LiteralPath $SessionPath -Raw|ConvertFrom-Json
 $lock=[IO.File]::Open((Join-Path $folder 'code-windows.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 $state=Get-EligibleCodeState $session
 $stage='Configuration';$config=Get-RMCallbackConfig (Join-Path $PSScriptRoot 'CallbackTarget-local.json');if(!$config.EntryRVA){throw 'CodeEntryNotConfigured'}
 $stage='TargetIdentity';$target=Get-Process -Id $session.TargetId;if($target.StartTime.ToUniversalTime().ToString('o') -ne $session.TargetStart){throw 'TargetGenerationMismatch'}
 $stage='DebuggerIdentity';$cdb=Get-Process -Id $session.DebuggerId
 if([IO.Path]::GetFileName($cdb.MainModule.FileName) -ine 'cdb.exe' -or $cdb.StartTime.ToUniversalTime().ToString('o') -ne $session.DebuggerStart -or ![string]::Equals($cdb.MainModule.FileName,$session.CdbPath,[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash -LiteralPath $cdb.MainModule.FileName -Algorithm SHA256).Hash -ne $session.CdbSHA256){throw 'DebuggerIdentityMismatch'}
 $stage='ModuleIdentity';$loaders=@($target.Modules|Where-Object {$_.ModuleName -ieq 'wow_loader.dll'});if($loaders.Count -ne 1){throw 'LoaderNotUnique'};$loader=$loaders[0]
 if($loader.FileName.StartsWith('\')){throw 'NetworkLoaderPathRefused'}
 $drive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($loader.FileName)))
 if($drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable,[IO.DriveType]::Ram)){throw 'NonlocalLoaderDrive'}
 if((Get-FileHash -LiteralPath $loader.FileName -Algorithm SHA256).Hash -ine $config.LoaderSHA256 -or $config.EntryRVA+32 -gt $loader.ModuleMemorySize -or $config.ExceptionRVA+16 -gt $loader.ModuleMemorySize){throw 'LoaderHashOrWindowRangeMismatch'}
 $entryBytes=Read-RMStaticCodeWindow $loader.FileName $config.EntryRVA 32;$siteBytes=Read-RMStaticCodeWindow $loader.FileName $config.ExceptionRVA 16
 if((Get-FileHash -LiteralPath $loader.FileName -Algorithm SHA256).Hash -ine $config.LoaderSHA256){throw 'DiskChangedDuringRead'}
 $entryAddress=[uint64]$loader.BaseAddress.ToInt64()+$config.EntryRVA;$siteAddress=[uint64]$loader.BaseAddress.ToInt64()+$config.ExceptionRVA
 @{Entry=@{Address=('0x'+$entryAddress.ToString('x'));DiskHex=([BitConverter]::ToString($entryBytes)).Replace('-','')};Exception=@{Address=('0x'+$siteAddress.ToString('x'));DiskHex=([BitConverter]::ToString($siteBytes)).Replace('-','')}}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $folder 'PRIVATE-code-windows.json') -Encoding UTF8
 $cmd=New-RMIndependentCodeCommands ([uint32]$state.Event.ThreadId) ([uint64]$state.ExceptionAddress) $entryAddress $siteAddress
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RMCodeConsole083 {
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 [StructLayout(LayoutKind.Explicit,CharSet=CharSet.Unicode,Size=20)] public struct Input {
  [FieldOffset(0)] public ushort EventType;[FieldOffset(4)] public int KeyDown;[FieldOffset(8)] public ushort Repeat;
  [FieldOffset(10)] public ushort VirtualKey;[FieldOffset(12)] public ushort Scan;[FieldOffset(14)] public char Character;[FieldOffset(16)] public uint Control;
 }
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool FreeConsole();
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool AttachConsole(uint processId);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint GetConsoleProcessList([Out] uint[] ids,uint count);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string name,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool WriteConsoleInputW(IntPtr handle,Input[] input,uint length,out uint written);
 public static bool QueueReadOnly(string cmd){
  IntPtr h=CreateFileW("CONIN$",0xc0000000,3,IntPtr.Zero,3,0,IntPtr.Zero);if(h==new IntPtr(-1))return false;
  try{Input[] events=new Input[cmd.Length*2];for(int i=0;i<cmd.Length;i++){Input k=new Input();k.EventType=1;k.KeyDown=1;k.Repeat=1;k.Character=cmd[i];k.VirtualKey=(ushort)(cmd[i]=='\r'?13:0);events[2*i]=k;k.KeyDown=0;events[2*i+1]=k;}uint n;return WriteConsoleInputW(h,events,(uint)events.Length,out n)&&n==events.Length;}finally{CloseHandle(h);}
 }
}
'@
 $stage='RevalidateState';$latest=Get-EligibleCodeState $session
 if($latest.Event.ThreadId -ne $state.Event.ThreadId -or $latest.ExceptionAddress -ne $state.ExceptionAddress -or (Get-Process -Id $session.TargetId).StartTime.ToUniversalTime().ToString('o') -ne $session.TargetStart -or (Get-Process -Id $session.DebuggerId).StartTime.ToUniversalTime().ToString('o') -ne $session.DebuggerStart){throw 'StateChanged'}
 [void][RMCodeConsole083]::FreeConsole();$stage='AttachOwnConsole';if(![RMCodeConsole083]::AttachConsole([uint32]$session.DebuggerId)){throw 'ConsoleUnavailable'};$attached=$true
 [uint32[]]$ids=New-Object uint32[] 32;$count=[RMCodeConsole083]::GetConsoleProcessList($ids,32);$stage='VerifyConsoleScope'
 if(!$count -or $count -gt 32 -or !(Test-RMStopConsoleScope @($ids[0..([int]$count-1)]|ForEach-Object {[int]$_}) ([int]$session.DebuggerId) $PID)){throw 'ConsoleScopeChanged'}
 $latest=Get-EligibleCodeState $session
 if($latest.Event.ThreadId -ne $state.Event.ThreadId -or $latest.ExceptionAddress -ne $state.ExceptionAddress){throw 'EventChangedBeforeQueue'}
 $stage='QueueReadOnlyCommands';if(![RMCodeConsole083]::QueueReadOnly($cmd)){throw 'ReadCommandsNotQueued'};$queued=$true
}catch{}finally{
 if($attached){[void][RMCodeConsole083]::FreeConsole()};if($lock){$lock.Dispose()}
 [pscustomobject]@{CommandsQueued=$queued;FailureStage=$(if($queued){'None'}else{$stage});IndependentOfCallback=$true;ContinuationAuthorized=$false;TargetTerminationRequested=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $folder 'code-windows-result.json') -Encoding UTF8
}
