# Only bounded diagnostics and enumerated status leave this module; never raw lines, paths or payload.
function Read-RMLiveLog([string]$Path){
 if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return ''}
 $fs=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 try{if($fs.Length -gt 8388608){throw 'Diagnostic log exceeds limit'};$sr=New-Object IO.StreamReader($fs);try{return $sr.ReadToEnd()}finally{$sr.Dispose()}}finally{$fs.Dispose()}
}
function Get-RMDiagnostics([string]$Text){
 if($Text.Length -gt 8388608){throw 'Diagnostic log exceeds limit'}
 $initialized=$false;$requested=$false;$listing=$false;$listingMode=$false;$exceptionCount=0;$firstAV=0;$secondAV=0;$pausePossible=$false;$commandError=$false;$lastCode='None';$insideBuffer=$false
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim()
  # Do not interpret bytes within captured payload as debugger diagnostics.
  if($l -match '^RM_BEGIN ctx='){$insideBuffer=$true;continue}
  if($l -eq 'RM_END'){$insideBuffer=$false;continue}
  if($insideBuffer){continue}
  if($l -eq 'RM_OBSERVER_EXPERIMENTAL_X64'){$initialized=$true}
  if($l -eq 'RM_BREAKPOINT_REQUESTED'){$requested=$true}
  if($l -eq 'RM_BP_STATE_BEGIN'){$listingMode=$true;continue}
  if($l -eq 'RM_BP_STATE_END'){$listingMode=$false;continue}
  if($listingMode -and $l -match '^\d+\s+[ed]\s+.*(?:sspicli|secur32)!EncryptMessage'){$listing=$true}
  # Actual CDB exception summary lines only. Prompt command echoes are not events.
  if($l -match '^\([0-9a-f]+\.[0-9a-f]+\):\s+.*?\bcode\s+([0-9a-f]{8})\s+\((first|second) chance\)\s*$'){
   $code=$matches[1].ToLowerInvariant();$chance=$matches[2]
   # The debugger's initial attach breakpoint is expected, not a target fault.
   if($code -eq '80000003'){continue}
   $exceptionCount++;$pausePossible=$true
   $lastCode=if($code -eq 'c0000005'){'AccessViolation'}else{'OtherException'}
   if($code -eq 'c0000005'){if($chance -eq 'first'){$firstAV++}else{$secondAV++}}
  }
  if($l -match '^\d+:\d+>\s*(?:g|gh|gn)\s*$'){$pausePossible=$false}
  if($l -match '^(?:Syntax error|Unable to resolve breakpoint|Couldn.t resolve|No runnable debuggees|Command error|Unable to insert breakpoint)\b'){$commandError=$true}
 }
 $state=if($commandError){'DebuggerCommandError'}elseif($pausePossible){'ExceptionObservedPausePossible'}elseif(!$initialized){'ObserverInitializationNotObserved'}else{'NoFaultPauseObserved'}
 return [pscustomobject]@{ObserverInitialized=$initialized;BreakpointRequested=$requested;BreakpointListingObserved=$listing;BreakpointResolution='NotEstablished';TargetExceptionSummaries=$exceptionCount;FirstChanceAccessViolations=$firstAV;SecondChanceAccessViolations=$secondAV;LastExceptionClass=$lastCode;ExceptionPausePossible=$pausePossible;DebuggerCommandErrorObserved=$commandError;ObservationState=$state;AutomaticExceptionResume=$false}
}
function Get-RMEndEvidence([string]$Folder){
 $d=[pscustomobject]@{StopHelperEvidence='NotAvailable';FailureStage='NotAvailable';DebuggerExitedAfterDetachRequest=$false;TargetAliveAfterDebuggerExit=$null;DetachSuccess='NotEstablished';TargetTerminationRequested=$false}
 $path=Join-Path $Folder 'stop-result.json'
 if(!(Test-Path -LiteralPath $path)){return $d}
 try{
  if((Get-Item -LiteralPath $path).Length -gt 4096){return $d}
  $r=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
  if($r.FailureStage -in @('None','IdentityCheck','AttachOwnConsole','VerifyConsoleScope','InterruptOwnDebugger','QueueDetachCommands','WaitDebuggerExit')){$d.FailureStage=$r.FailureStage}
  if($r.StopConfirmed -is [bool] -and $r.StopConfirmed){$d.StopHelperEvidence='DebuggerExitedAfterDetachCommands';$d.DebuggerExitedAfterDetachRequest=$true}
  elseif($r.StopConfirmed -is [bool]){$d.StopHelperEvidence='StopNotConfirmedManualRecoveryRequired'}
  if($r.TargetAliveAfterDebuggerExit -is [bool]){$d.TargetAliveAfterDebuggerExit=$r.TargetAliveAfterDebuggerExit}
  # Even debugger exit plus surviving target is not proof that every detach instruction succeeded.
 }catch{}
 return $d
}
