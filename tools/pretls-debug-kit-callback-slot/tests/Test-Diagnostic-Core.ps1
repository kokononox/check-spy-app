$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Diagnostic-Core.ps1')
. (Join-Path $base 'Debugger-Core.ps1')
$n=0
function Assert($value,$label){if(!$value){throw $label};$script:n++}
$t=@'
(123.456): Break instruction exception - code 80000003 (first chance)
RM_OBSERVER_EXPERIMENTAL_X64
RM_BREAKPOINT_REQUESTED
RM_BP_STATE_BEGIN
 0 e Disable Clear 00007fff`12345678 0001 (0001) 0:**** sspicli!EncryptMessage "dummy"
RM_BP_STATE_END
0:054> g
(123.789): Access violation - code c0000005 (first chance)
First chance exceptions are reported before any exception handling.
0:000>
'@
$d=Get-RMDiagnostics $t
Assert ($d.ObserverInitialized) 'Initialization marker'
Assert ($d.BreakpointRequested) 'Requested marker'
Assert ($d.BreakpointListingObserved) 'Listing evidence'
Assert ($d.BreakpointListingState -eq 'EnabledListedNotExecutionProof') 'Listing is not execution proof'
Assert ($d.BreakpointResolution -eq 'NotEstablished') 'Do not overclaim symbol resolution'
Assert ($d.TargetExceptionSummaries -eq 1) 'Initial debugger break not target fault'
Assert ($d.FirstChanceAccessViolations -eq 1) 'First chance AV'
Assert ($d.ExceptionPausePossible) 'Do not confuse paused session with no traffic'
Assert ($d.StartupAutoGoPolicy -eq 'DisabledInV04') 'No startup automatic go policy'
Assert ($d.ObservationState -eq 'ExceptionObservedPausePossible') 'Pause classification'
$deferred=Get-RMDiagnostics ($t.Replace('0 e Disable','0 eu Disable'))
Assert ($deferred.BreakpointListingObserved -and $deferred.BreakpointListingState -eq 'EnabledDeferredAtListing') 'Real CDB deferred eu listing'
$hit=Get-RMDiagnostics ($t+"`nRM_API_ENTRY`n")
Assert ($hit.APIEntryMarkers -eq 1) 'API handler entry distinct from captured bytes'
$r=Get-RMDiagnostics ($t+"`n0:000> g`n")
Assert (!$r.ExceptionPausePossible) 'Explicit resume observation'
$r=Get-RMDiagnostics ($t.Replace('(first chance)','(second chance)'))
Assert ($r.SecondChanceAccessViolations -eq 1) 'Second chance diagnostic'
$r=Get-RMDiagnostics '0:000> bu sspicli!EncryptMessage ".echo RM_OBSERVER_EXPERIMENTAL_X64; .echo RM_BREAKPOINT_REQUESTED"'
Assert (!$r.ObserverInitialized -and !$r.BreakpointRequested) 'Echoed command is not marker'
$r=Get-RMDiagnostics "RM_BEGIN ctx=0/0 declared=0 captured=0`n(123.789): Access violation - code c0000005 (first chance)`nRM_END"
Assert ($r.TargetExceptionSummaries -eq 0) 'Captured data cannot generate diagnostics'
$r=Get-RMDiagnostics 'Syntax error at dummy'
Assert ($r.DebuggerCommandErrorObserved) 'Debugger command failure'
$r=Get-RMDiagnostics 'private https://fixture.invalid/?token=SECRET_AUTH C:\private\account'
Assert (($r|ConvertTo-Json) -notmatch 'SECRET_AUTH|fixture.invalid|account|C:\\private') 'No raw data export'
$dir=Join-Path ([IO.Path]::GetTempPath()) ('RM-diag-own-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
try{
 $e=Get-RMEndEvidence $dir
 Assert ($e.DetachSuccess -eq 'NotEstablished' -and !$e.DebuggerExitedAfterDetachRequest) 'No exit evidence is not success'
 @{StopConfirmed=$true;Reason='private SECRET_AUTH';TargetAliveAfterDebuggerExit=$true}|ConvertTo-Json|Set-Content (Join-Path $dir 'stop-result.json') -Encoding UTF8
 $e=Get-RMEndEvidence $dir
 Assert ($e.DebuggerExitedAfterDetachRequest -and $e.TargetAliveAfterDebuggerExit) 'Safe helper end evidence'
 Assert ($e.DetachSuccess -eq 'NotEstablished') 'Exit and survival are not proof of every detach instruction'
 Assert (($e|ConvertTo-Json) -notmatch 'SECRET_AUTH') 'Reason text not exported'
 @{StopConfirmed=$false}|ConvertTo-Json|Set-Content (Join-Path $dir 'stop-result.json') -Encoding UTF8
 $e=Get-RMEndEvidence $dir
 Assert ($e.StopHelperEvidence -eq 'StopNotConfirmedManualRecoveryRequired') 'Failure reported explicitly'
}finally{Remove-Item $dir -Recurse -Force}
$initial=@'
(123.456): Break instruction exception - code 80000003 (first chance)
RM_OBSERVER_EXPERIMENTAL_X64
RM_INITIAL_EVENT_BEGIN
ExceptionAddress: 00007fff`12345678 (ntdll!DbgBreakPoint)
ExceptionCode: 80000003 (Break instruction exception)
RM_INITIAL_EVENT_END
RM_INITIAL_WAITING_NO_AUTO_GO
'@
$d=Get-RMDiagnostics $initial
Assert ($d.InitialContinueAllowed -and $d.InitialGate -eq 'ExpectedInitialBreakAwaitingUser') 'Expected first break waits for user'
Assert ($d.ExceptionPausePossible) 'Initial stop is still paused'
$d=Get-RMDiagnostics ($initial.Replace('80000003','c0000005'))
Assert (!$d.InitialContinueAllowed) 'Access violation blocks continuation'
$d=Get-RMDiagnostics ($initial.Replace('ntdll!DbgBreakPoint','private!OtherBreak'))
Assert (!$d.InitialContinueAllowed) 'Unknown address blocks continuation'
$d=Get-RMDiagnostics ($initial.Replace('first chance','second chance'))
Assert (!$d.InitialContinueAllowed) 'Second chance blocks initial go'
$d=Get-RMDiagnostics ($initial+"`n(123.789): Break instruction exception - code 80000003 (first chance)`n")
Assert ($d.BreakInstructionsAfterInitialization -eq 1 -and $d.ExceptionPausePossible -and !$d.InitialContinueAllowed) 'Later break not ignored'
$d=Get-RMDiagnostics ("(123.789): Access violation - code c0000005 (first chance)`n"+$initial)
Assert (!$d.InitialContinueAllowed) 'Earlier fault blocks even if later initial breakpoint'
$d=Get-RMDiagnostics ($initial+"`nRM_INITIAL_CONTINUE_USER_REQUESTED`n")
Assert (!$d.InitialContinueAllowed -and $d.UserInitialContinueMarker -and !$d.ExceptionPausePossible) 'One request, no duplicate go'
$d=Get-RMDiagnostics "(123.789): Access violation - code c0000005 (first chance)`nRM_OBSERVER_EXPERIMENTAL_X64`n0:000> g`n(123.456): Break instruction exception - code 80000003 (first chance)"
Assert ($d.ContinuationAfterFaultObserved -and $d.ExceptionPausePossible -and $d.BreakInstructionsAfterInitialization -eq 1) 'Replay old startup-fault then go then break pattern'
$cmd=New-RMCdbCommands
Assert (($cmd -split '\r\n|\r|\n') -notcontains 'g') 'No unconditional startup go'
Assert ($cmd -match 'RM_INITIAL_WAITING_NO_AUTO_GO') 'Snapshot marker required'
Assert (!(Get-RMDiagnostics '').InitialContinueAllowed) 'Unknown/missing log fail closed'
$fault=@'
RM_FAULT_RECORD_BEGIN
ExceptionAddress: 00007fff`00012345 (private!Sensitive)
ExceptionCode: c0000005 (Access violation)
Parameter[0]: 00000000`00000008
Parameter[1]: 01234567`89abcdef
RM_FAULT_RECORD_END
'@
$d=Get-RMDiagnostics $fault
Assert ($d.FaultRecordComplete -and $d.FaultRecordExceptionClass -eq 'AccessViolation' -and $d.FaultAccessKind -eq 'Execute') 'Snapshot execute operation'
Assert (($d|ConvertTo-Json) -notmatch 'Sensitive|01234567|89abcdef|00012345') 'No fault address/parameter leak'
$d=Get-RMDiagnostics ($fault.Replace('00000000`00000008','00000000`00000000'))
Assert ($d.FaultAccessKind -eq 'Read') 'Read operation'
$d=Get-RMDiagnostics ($fault.Replace('00000000`00000008','00000000`00000001'))
Assert ($d.FaultAccessKind -eq 'Write') 'Write operation'
$d=Get-RMDiagnostics ($fault.Replace('c0000005','80000003'))
Assert ($d.FaultAccessKind -eq 'NotEstablished') 'Non-AV parameters not access type'
$d=Get-RMDiagnostics ($fault.Replace('RM_FAULT_RECORD_END',''))
Assert (!$d.FaultRecordComplete -and $d.FaultAccessKind -eq 'NotEstablished') 'Incomplete snapshot not interpreted'
$d=Get-RMDiagnostics ("RM_BEGIN ctx=0/0 declared=0 captured=0`n"+$fault+"`nRM_END")
Assert (!$d.FaultRecordComplete) 'Payload cannot spoof exception record'
$helper=[IO.File]::ReadAllText((Join-Path $base 'Fault-Snapshot.ps1'))
Assert ($helper -match 'string cmd="\.echo RM_FAULT_RECORD_BEGIN; \.lastevent; \.exr -1; \.echo RM_FAULT_RECORD_END\\r";') 'Fault helper fixed read-only commands'
Assert ($helper -notmatch 'GenerateConsoleCtrlEvent|WriteInitialGo|WriteDetachCommands') 'No interrupt/resume/stop in fault helper'
Write-Host ('PASS: '+$n+' synthetic diagnostic/privacy/end-evidence assertions. No real game/network tested.')
