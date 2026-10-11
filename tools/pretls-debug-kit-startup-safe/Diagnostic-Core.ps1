# Only bounded diagnostics and enumerated status leave this module; never raw lines, paths or payload.
function Read-RMLiveLog([string]$Path){
 if(!(Test-Path -LiteralPath $Path -PathType Leaf)){return ''}
 $fs=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 try{if($fs.Length -gt 8388608){throw 'Diagnostic log exceeds limit'};$sr=New-Object IO.StreamReader($fs);try{return $sr.ReadToEnd()}finally{$sr.Dispose()}}finally{$fs.Dispose()}
}
function Get-RMDiagnostics([string]$Text){
 if($Text.Length -gt 8388608){throw 'Diagnostic log exceeds limit'}
 $initialized=$false;$requested=$false;$listing=$false;$listingState='NotObserved';$apiHits=0;$listingMode=$false;$exceptionCount=0;$firstAV=0;$secondAV=0;$pausePossible=$false;$commandError=$false;$lastCode='None';$insideBuffer=$false
 $lastEventCode='Unknown';$lastChance='Unknown';$breaksBefore=0;$breaksAfter=0;$goCommands=0;$userContinue=$false;$goAfterFault=$false;$initialMode=$false;$initialRecordCode='Unknown';$initialSymbol='Unknown';$initialComplete=$false;$waiting=$false;$eventAfterSnapshot=$false
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim()
  if($l -match '^RM_BEGIN ctx='){$insideBuffer=$true;continue}
  if($l -eq 'RM_END'){$insideBuffer=$false;continue}
  if($insideBuffer){continue}
  if($l -eq 'RM_API_ENTRY'){$apiHits++}
  if($l -eq 'RM_OBSERVER_EXPERIMENTAL_X64'){$initialized=$true}
  if($l -eq 'RM_BREAKPOINT_REQUESTED'){$requested=$true}
  if($l -eq 'RM_BP_STATE_BEGIN'){$listingMode=$true;continue}
  if($l -eq 'RM_BP_STATE_END'){$listingMode=$false;continue}
  if($listingMode -and $l -match '^\d+\s+([ed])(u)?\s+.*(?:sspicli|secur32)!EncryptMessage'){$listing=$true;$listingState=if($matches[1] -eq 'd'){'DisabledListed'}elseif($matches[2]){'EnabledDeferredAtListing'}else{'EnabledListedNotExecutionProof'}}
  if($l -eq 'RM_INITIAL_EVENT_BEGIN'){$initialMode=$true;continue}
  if($l -eq 'RM_INITIAL_EVENT_END'){$initialMode=$false;$initialComplete=$true;continue}
  if($initialMode){
   if($l -match '^ExceptionCode:\s*([0-9a-f]{8})\b'){$initialRecordCode=$matches[1].ToLowerInvariant()}
   if($l -match '^ExceptionAddress:\s*[0-9a-f`]+\s+\((ntdll!DbgBreakPoint|ntdll!LdrpDoDebuggerBreak)(?:\+0x[0-9a-f]+)?\)\s*$'){$initialSymbol=$matches[1]}
  }
  if($l -eq 'RM_INITIAL_WAITING_NO_AUTO_GO'){$waiting=$true}
  if($l -eq 'RM_INITIAL_CONTINUE_USER_REQUESTED'){$userContinue=$true;$waiting=$false;$pausePossible=$false}
  if($l -match '^\([0-9a-f]+\.[0-9a-f]+\):\s+.*?\bcode\s+([0-9a-f]{8})\s+\((first|second) chance\)\s*$'){
   $code=$matches[1].ToLowerInvariant();$chance=$matches[2];$lastEventCode=$code;$lastChance=$chance;$pausePossible=$true
   if($initialComplete){$eventAfterSnapshot=$true}
   if($code -eq '80000003'){
    if($initialized){$breaksAfter++}else{$breaksBefore++}
    $lastCode='BreakInstruction';continue
   }
   $exceptionCount++;$lastCode=if($code -eq 'c0000005'){'AccessViolation'}else{'OtherException'}
   if($code -eq 'c0000005'){if($chance -eq 'first'){$firstAV++}else{$secondAV++}}
  }
  if($l -match '^\d+:\d+>\s*(?:g|gh|gn)\s*$'){
   $goCommands++;if($lastEventCode -notin @('Unknown','80000003')){$goAfterFault=$true};$pausePossible=$false;$waiting=$false
  }
  if($l -match '^(?:Syntax error|Unable to resolve breakpoint|Couldn.t resolve|No runnable debuggees|Command error|Unable to insert breakpoint)\b'){$commandError=$true}
 }
 $gate=if(!$initialComplete -or !$waiting){'WaitingSnapshotNotEstablished'}elseif($commandError){'DebuggerCommandError'}elseif($eventAfterSnapshot){'EventChangedAfterSnapshot'}elseif($initialRecordCode -ne '80000003' -or $lastEventCode -ne '80000003' -or $lastChance -ne 'first'){'InitialEventNotExpectedBreak'}elseif($initialSymbol -eq 'Unknown'){'InitialBreakLocationUnverified'}elseif($exceptionCount -gt 0){'FaultObservedBeforeStart'}elseif($breaksAfter -gt 0){'AdditionalBreakObserved'}elseif($goCommands -gt 0 -or $userContinue){'InitialContinuationAlreadyObserved'}else{'ExpectedInitialBreakAwaitingUser'}
 $state=if($commandError){'DebuggerCommandError'}elseif($goAfterFault){'ContinuationObservedAfterFault'}elseif($pausePossible){if($lastCode -eq 'BreakInstruction'){'BreakInstructionPausePossible'}else{'ExceptionObservedPausePossible'}}elseif(!$initialized){'ObserverInitializationNotObserved'}elseif($userContinue){'InitialContinueRequestedRunningNotEstablished'}else{'NoPauseEvidenceInLogNotProofOfRunning'}
 return [pscustomobject]@{ObserverInitialized=$initialized;BreakpointRequested=$requested;BreakpointListingObserved=$listing;BreakpointListingState=$listingState;APIEntryMarkers=$apiHits;BreakpointResolution='NotEstablished';TargetExceptionSummaries=$exceptionCount;FirstChanceAccessViolations=$firstAV;SecondChanceAccessViolations=$secondAV;BreakInstructionsBeforeInitialization=$breaksBefore;BreakInstructionsAfterInitialization=$breaksAfter;LastExceptionClass=$lastCode;ExceptionPausePossible=$pausePossible;DebuggerCommandErrorObserved=$commandError;ObservationState=$state;InitialGate=$gate;InitialContinueAllowed=($gate -eq 'ExpectedInitialBreakAwaitingUser');InitialWaiting=$waiting;UserInitialContinueMarker=$userContinue;PromptContinueCommands=$goCommands;ContinuationAfterFaultObserved=$goAfterFault;StartupAutoGoPolicy='DisabledInV04';ExceptionAutoResumePolicy='NoExceptionHandlersAdded';ResumeOriginForOtherPromptCommands='NotEstablished'}
}
function Get-RMEndEvidence([string]$Folder){
 $d=[pscustomobject]@{StopHelperEvidence='NotAvailable';FailureStage='NotAvailable';DebuggerExitedAfterDetachRequest=$false;TargetAliveAfterDebuggerExit=$null;DetachSuccess='NotEstablished';TargetTerminationRequested=$false;InitialGoRequestEvidence='NotAvailable'}
  $continuePath=Join-Path $Folder 'continue-result.json'
 if(Test-Path -LiteralPath $continuePath){try{if((Get-Item -LiteralPath $continuePath).Length -le 4096){$c=Get-Content -LiteralPath $continuePath -Raw|ConvertFrom-Json;if($c.ContinueCommandQueued -is [bool]){$d.InitialGoRequestEvidence=if($c.ContinueCommandQueued){'QueuedByUserRequestedHelperNotProofOfExecution'}else{'NotConfirmedDoNotRetry'}}}}catch{}}
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
