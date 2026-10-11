# Pure bounded parsing/classification. No native query, console command or process control here.
function Get-RMInitialEventIdentity([string]$Text){
 if($Text.Length -gt 8388608){throw 'Log exceeds limit'}
 $inside=$false;$buffer=$false;$pidValue=$null;$tidValue=$null;$code='Unknown';$recordCode='Unknown';$chance='Unknown';$complete=$false
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim()
  if($l -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($l -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue}
  if($l -eq 'RM_INITIAL_EVENT_BEGIN'){$inside=$true;$complete=$false;$pidValue=$null;$tidValue=$null;$code='Unknown';$recordCode='Unknown';$chance='Unknown';continue}
  if($l -eq 'RM_INITIAL_EVENT_END'){$inside=$false;$complete=$true;continue}
  if($inside -and $l -match '^ExceptionCode:\s*([0-9a-f]{8})\b'){$recordCode=$matches[1].ToLowerInvariant()}
  if($inside -and $l -match '^Last event:\s*([0-9a-f]+)\.([0-9a-f]+):\s+.*?\bcode\s+([0-9a-f]{8})\s+\((first|second) chance\)\s*$'){
   try{$pidValue=[Convert]::ToUInt32($matches[1],16);$tidValue=[Convert]::ToUInt32($matches[2],16);$code=$matches[3].ToLowerInvariant();$chance=$matches[4]}catch{$pidValue=$null;$tidValue=$null}
  }
 }
 return [pscustomobject]@{Complete=$complete;ProcessId=$pidValue;ThreadId=$tidValue;Code=$code;RecordCode=$recordCode;Chance=$chance}
}
function Get-RMContextIndicators([string]$Text){
 if($Text.Length -gt 8388608){throw 'Log exceeds limit'}
 $inside=$false;$buffer=$false;$complete=$false;$lastPid=$null;$lastTid=$null;$currentPid=$null;$currentTid=$null
 $frames=0;$remote=$false;$breakSymbol=$false;$threadStart=$false
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim()
  if($l -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($l -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue}
  if($l -eq 'RM_CONTEXT_BEGIN'){$inside=$true;$complete=$false;$lastPid=$null;$lastTid=$null;$currentPid=$null;$currentTid=$null;$frames=0;$remote=$false;$breakSymbol=$false;$threadStart=$false;continue}
  if($l -eq 'RM_CONTEXT_END'){$inside=$false;$complete=$true;continue}
  if(!$inside){continue}
  if($l -match '^Last event:\s*([0-9a-f]+)\.([0-9a-f]+):'){
   try{$lastPid=[Convert]::ToUInt32($matches[1],16);$lastTid=[Convert]::ToUInt32($matches[2],16)}catch{}
  }
  if($l -match '^(?:\.|#)?\s*\d+\s+Id:\s*([0-9a-f]+)\.([0-9a-f]+)\s'){
   try{$currentPid=[Convert]::ToUInt32($matches[1],16);$currentTid=[Convert]::ToUInt32($matches[2],16)}catch{}
  }
  # Count CDB stack rows, not arbitrary text or prompt command echoes.
  if($l -match '^(?:[0-9a-f]{1,3}\s+)?[0-9a-f`]{8,17}\s+[0-9a-f`]{8,17}\s+'){
   $frames++
   if($l -match '\bntdll!DbgUiRemoteBreakin\b'){$remote=$true}
   if($l -match '\bntdll!DbgBreakPoint\b'){$breakSymbol=$true}
   if($l -match '\b(?:ntdll!RtlUserThreadStart|kernel32!BaseThreadInitThunk)\b'){$threadStart=$true}
  }
 }
 $same=$null;if($complete -and $lastPid -and $lastTid -and $currentPid -and $currentTid){$same=($lastPid -eq $currentPid -and $lastTid -eq $currentTid)}
 return [pscustomobject]@{Complete=$complete;CurrentContextMatchesLastEventThread=$same;StackFrameRowsObserved=$frames;RemoteBreakinSymbolTextObserved=$remote;DbgBreakPointSymbolTextObserved=$breakSymbol;ThreadStartSymbolTextObserved=$threadStart;StackSymbolsAreTextEvidenceNotProof=$true;Origin='NotEstablished'}
}
function Get-RMThreadStartClass([uint64]$Address,$Ranges,[Nullable[uint64]]$ExpectedRemoteBreakin,[bool]$SystemFileVerified){
 if(!$Address){return 'NotEstablished'}
 if($SystemFileVerified -and $null -ne $ExpectedRemoteBreakin -and $Address -eq $ExpectedRemoteBreakin){return 'NtdllRemoteBreakinAddressMatchNotOriginProof'}
 foreach($r in $Ranges){if($Address -ge [uint64]$r.Base -and $Address-[uint64]$r.Base -lt [uint64]$r.Size){
  return $(switch($r.Kind){'SystemNtdll'{'OtherNtdllAddress'};'Loader'{'LoaderAddress'};'MainExecutable'{'MainExecutableAddress'};default{'OtherMappedModuleAddress'}})
 }}
 return 'NotInEnumeratedModuleRanges'
}
function Get-RMSafeStartupMetadata([string]$Folder){
 $out=[pscustomobject]@{Collection='NotAvailable';FailureStage='NotAvailable';MainExecutable=$null;Loader=$null;SystemNtdll=$null;EventThreadQuery='NotEstablished';EventThreadStartClass='NotEstablished';SystemNtdllFileMatchToHelper=$false;SystemNtdllSignatureVerified=$false;ContextCommandsQueued=$false;DiskHashesAreNotMemoryIdentity=$true;BreakpointOrigin='NotEstablished';ContinuationAuthorized=$false}
 $p=Join-Path $Folder 'startup-metadata-safe.json';if(!(Test-Path -LiteralPath $p)){return $out}
 try{
  if((Get-Item $p).Length -gt 16384){return $out};$r=Get-Content $p -Raw|ConvertFrom-Json
  if($r.Collection -in @('Collected','NotConfirmed')){$out.Collection=$r.Collection}
  if($r.FailureStage -in @('None','ValidateState','TargetIdentity','DebuggerIdentity','EnumerateModules','HashModuleFiles','QueryEventThread','RevalidateState','AttachOwnConsole','VerifyConsoleScope','QueueContext')){$out.FailureStage=$r.FailureStage}
  foreach($kind in @('MainExecutable','Loader','SystemNtdll')){
   $m=$r.$kind;if($null -eq $m){continue}
   $item=[pscustomobject]@{Present=($m.Present -is [bool] -and $m.Present);SHA256=$null;FileBytes=$null;MatchesSuppliedBaseline=$null}
   if($m.SHA256 -is [string] -and $m.SHA256 -cmatch '^[0-9A-Fa-f]{64}$'){$item.SHA256=$m.SHA256.ToLowerInvariant()}
   if($m.FileBytes -is [long] -or $m.FileBytes -is [int]){if($m.FileBytes -ge 0){$item.FileBytes=$m.FileBytes}}
   if($m.MatchesSuppliedBaseline -is [bool]){$item.MatchesSuppliedBaseline=$m.MatchesSuppliedBaseline}
   $out.$kind=$item
  }
  if($r.EventThreadQuery -in @('Success','OpenThreadUnavailable','OwnerMismatch','NativeQueryUnavailable','ThreadTimesUnavailable','ThreadGenerationUnverified','NotEstablished')){$out.EventThreadQuery=$r.EventThreadQuery}
  if($r.EventThreadStartClass -in @('NtdllRemoteBreakinAddressMatchNotOriginProof','OtherNtdllAddress','LoaderAddress','MainExecutableAddress','OtherMappedModuleAddress','NotInEnumeratedModuleRanges','NotEstablished')){$out.EventThreadStartClass=$r.EventThreadStartClass}
  foreach($name in @('SystemNtdllFileMatchToHelper','SystemNtdllSignatureVerified','ContextCommandsQueued')){if($r.$name -is [bool]){$out.$name=$r.$name}}
 }catch{}
 return $out
}

# Read-only eligibility is separate from continuation eligibility. Never grants permission to resume.
function Test-RMStartupReadState($Diag,$Event,[uint32]$TargetId){
 if(!$Diag.InitialWaiting -or $Diag.UserInitialContinueMarker -or $Diag.PromptContinueCommands -gt 0 -or !$Event.Complete -or $Event.ProcessId -ne $TargetId -or !$Event.ThreadId -or $Event.Chance -ne 'first' -or $Event.Code -ne $Event.RecordCode){return $false}
 if($Event.Code -eq '80000003'){return ($Diag.InitialGate -in @('ExpectedInitialBreakAwaitingUser','InitialBreakLocationUnverified'))}
 if($Event.Code -eq 'c0000005'){return ($Diag.InitialGate -eq 'InitialEventNotExpectedBreak' -and !$Diag.InitialContinueAllowed -and $Diag.ExceptionPausePossible -and $Diag.LastExceptionClass -eq 'AccessViolation' -and $Diag.LastExceptionChance -eq 'first')}
 return $false
}
