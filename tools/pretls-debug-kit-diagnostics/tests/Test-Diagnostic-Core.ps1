$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Diagnostic-Core.ps1')
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
Assert (!$d.AutomaticExceptionResume) 'Never automatically resume exceptions'
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
Write-Host ('PASS: '+$n+' synthetic diagnostic/privacy/end-evidence assertions. No real game/network tested.')
