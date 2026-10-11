# Own-console bounded candidate-slot read. Never interrupts, resumes, patches or terminates target.
param([Parameter(Mandatory=$true)][string]$SessionPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Session-UI-Core.ps1');. (Join-Path $PSScriptRoot 'Diagnostic-Core.ps1');. (Join-Path $PSScriptRoot 'Callback-Slot-Core.ps1');. (Join-Path $PSScriptRoot 'Code-Window-Core.ps1')
$folder=Split-Path -Parent $SessionPath;$stage='ValidateState';$queued=$false;$attached=$false;$lock=$null
function Get-EligibleSlotState($Session){
 if(![string]::Equals([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($Session.LogPath)),[IO.Path]::GetFullPath($folder),[StringComparison]::OrdinalIgnoreCase)){throw 'LogOutsideSession'}
 $text=Read-RMLiveLog $Session.LogPath;$d=Get-RMDiagnostics $text;$e=Get-RMInitialEventIdentity $text;$f=Get-RMRecordedCallbackFrame $text
 if(!$e.Complete -or $e.ProcessId -ne $Session.TargetId -or !$e.ThreadId -or $e.Code -ne '80000003' -or $e.RecordCode -ne $e.Code -or $e.Chance -ne 'first' -or !$d.InitialWaiting -or $d.UserInitialContinueMarker -or $d.PromptContinueCommands -gt 0 -or $d.InitialGate -ne 'InitialBreakLocationUnverified' -or !$f -or !$f.CallerStackPointer){throw 'InitialSnapshotNotEligible'}
 $inside=$false;$address=$null;$buffer=$false
 foreach($line in ($text -split '\r\n|\r|\n')){if($line.Trim() -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($line.Trim() -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue};if($line.Trim() -eq 'RM_INITIAL_EVENT_BEGIN'){$inside=$true;$address=$null};if($line.Trim() -eq 'RM_INITIAL_EVENT_END'){$inside=$false};if($inside -and $line.Trim() -match '^ExceptionAddress:\s*([0-9a-f`]{8,17})(?:\s|$)'){$address=Convert-RMSlotHex $matches[1]}}
 if(!$address){throw 'NoExceptionAddress'}
 return [pscustomobject]@{Event=$e;Frame=$f;ExceptionAddress=$address}
}
try{
 if($env:OS -ne 'Windows_NT' -or ![Environment]::Is64BitProcess){throw 'WindowsX64Required'}
 $session=Get-Content -LiteralPath $SessionPath -Raw|ConvertFrom-Json
 $lock=[IO.File]::Open((Join-Path $folder 'callback-slot.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 $state=Get-EligibleSlotState $session
 $stage='Configuration';$config=Get-RMCallbackConfig (Join-Path $PSScriptRoot 'CallbackTarget-local.json')
 $stage='TargetIdentity';$target=Get-Process -Id $session.TargetId
 if($target.StartTime.ToUniversalTime().ToString('o') -ne $session.TargetStart){throw 'TargetGenerationMismatch'}
 $stage='DebuggerIdentity';$cdb=Get-Process -Id $session.DebuggerId
 if([IO.Path]::GetFileName($cdb.MainModule.FileName) -ine 'cdb.exe' -or $cdb.StartTime.ToUniversalTime().ToString('o') -ne $session.DebuggerStart -or ![string]::Equals($cdb.MainModule.FileName,$session.CdbPath,[StringComparison]::OrdinalIgnoreCase) -or (Get-FileHash -LiteralPath $cdb.MainModule.FileName -Algorithm SHA256).Hash -ne $session.CdbSHA256){throw 'DebuggerIdentityMismatch'}
 $stage='ModuleIdentity';$modules=@($target.Modules);$loaders=@($modules|Where-Object {$_.ModuleName -ieq 'wow_loader.dll'})
 if($loaders.Count -ne 1){throw 'LoaderNotUnique'};$loader=$loaders[0]
 if($loader.FileName.StartsWith('\\')){throw 'NetworkLoaderPathRefused'}
 $localDrive=New-Object IO.DriveInfo([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($loader.FileName)))
 if($localDrive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable,[IO.DriveType]::Ram)){throw 'NonLocalLoaderDrive'}
 if((Get-FileHash -LiteralPath $loader.FileName -Algorithm SHA256).Hash -ine $config.LoaderSHA256 -or $config.ExceptionRVA -ge $loader.ModuleMemorySize -or $config.CallerReturnRVA -ge $loader.ModuleMemorySize){throw 'LoaderHashOrRangeMismatch'}
 $exception=[uint64]$loader.BaseAddress.ToInt64()+$config.ExceptionRVA;$return=[uint64]$loader.BaseAddress.ToInt64()+$config.CallerReturnRVA
 if($state.ExceptionAddress -ne $exception -or $state.Frame.TopReturnAddress -ne $return){throw 'ObservedAddressesDoNotMatchConfiguration'}
 $ranges=@();foreach($m in $modules){$kind=if($m.BaseAddress -eq $target.MainModule.BaseAddress){'MainExecutable'}elseif($m.ModuleName -ieq 'wow_loader.dll'){'Loader'}elseif($m.ModuleName -ieq 'ntdll.dll'){'SystemNtdll'}else{$null};if($kind){$ranges+=[pscustomobject]@{Kind=$kind;Base=('0x'+$m.BaseAddress.ToInt64().ToString('x'));Size=$m.ModuleMemorySize}}}
 $sp=[uint64]$state.Frame.CallerStackPointer
 if($sp -gt 0x00007ffffffff000 -or $sp%8 -ne 0){throw 'UnsupportedCallerStackPointer'}
 [pscustomobject]@{SlotAddress=('0x'+($sp+$config.SlotOffset).ToString('x'));Ranges=$ranges}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $folder 'PRIVATE-callback-slot.json') -Encoding UTF8
 $entryAddress=[uint64]0
 if($config.EntryRVA){
  if($config.EntryRVA+32 -gt $loader.ModuleMemorySize -or $config.ExceptionRVA+16 -gt $loader.ModuleMemorySize){throw 'CodeWindowOutsideLoader'}
  $entryBytes=Read-RMStaticCodeWindow $loader.FileName $config.EntryRVA 32;$exceptionBytes=Read-RMStaticCodeWindow $loader.FileName $config.ExceptionRVA 16
  if((Get-FileHash -LiteralPath $loader.FileName -Algorithm SHA256).Hash -ine $config.LoaderSHA256){throw 'DiskChangedDuringCodeRead'}
  $entryAddress=[uint64]$loader.BaseAddress.ToInt64()+$config.EntryRVA
  @{Entry=@{Address=('0x'+$entryAddress.ToString('x'));DiskHex=([BitConverter]::ToString($entryBytes)).Replace('-','')};Exception=@{Address=('0x'+$exception.ToString('x'));DiskHex=([BitConverter]::ToString($exceptionBytes)).Replace('-','')}}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $folder 'PRIVATE-code-windows.json') -Encoding UTF8
 }
 $cmd=New-RMCallbackSlotCommands ([uint32]$state.Event.ThreadId) $exception $return $sp $config.SlotOffset $entryAddress
 Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class RMCallbackConsole08 {
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
 $stage='RevalidateState';$latest=Get-EligibleSlotState $session
 if($latest.Event.ThreadId -ne $state.Event.ThreadId -or $latest.ExceptionAddress -ne $exception -or $latest.Frame.TopReturnAddress -ne $return -or $latest.Frame.CallerStackPointer -ne $sp -or (Get-Process -Id $session.TargetId).StartTime.ToUniversalTime().ToString('o') -ne $session.TargetStart -or (Get-Process -Id $session.DebuggerId).StartTime.ToUniversalTime().ToString('o') -ne $session.DebuggerStart){throw 'StateChanged'}
 [void][RMCallbackConsole08]::FreeConsole();$stage='AttachOwnConsole'
 if(![RMCallbackConsole08]::AttachConsole([uint32]$session.DebuggerId)){throw 'ConsoleUnavailable'};$attached=$true
 [uint32[]]$ids=New-Object uint32[] 32;$count=[RMCallbackConsole08]::GetConsoleProcessList($ids,32);$stage='VerifyConsoleScope'
 if(!$count -or $count -gt 32 -or !(Test-RMStopConsoleScope @($ids[0..([int]$count-1)]|ForEach-Object {[int]$_}) ([int]$session.DebuggerId) $PID)){throw 'ConsoleScopeChanged'}
 $latest=Get-EligibleSlotState $session
 if($latest.Event.ThreadId -ne $state.Event.ThreadId -or $latest.ExceptionAddress -ne $exception -or $latest.Frame.TopReturnAddress -ne $return -or $latest.Frame.CallerStackPointer -ne $sp){throw 'SnapshotChangedBeforeQueue'}
 $stage='QueueReadOnlyCommands';if(![RMCallbackConsole08]::QueueReadOnly($cmd)){throw 'CommandsNotQueued'};$queued=$true
}catch{}finally{
 if($attached){[void][RMCallbackConsole08]::FreeConsole()};if($lock){$lock.Dispose()}
 [pscustomobject]@{CommandsQueued=$queued;Reason=$(if($queued){'ReadOnlyCommandsQueued'}else{'ReadNotConfirmedNoRetry'});FailureStage=$(if($queued){'None'}else{$stage});TargetTerminationRequested=$false;ContinuationAuthorized=$false}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $folder 'callback-slot-result.json') -Encoding UTF8
}
