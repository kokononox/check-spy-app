# Bounded parsing + numeric command generation only; no process control.
. (Join-Path $PSScriptRoot 'Startup-Metadata-Core.ps1')
function Convert-RMSlotHex($V){if($V -isnot [string] -or $V -cnotmatch '^(?:0x)?[0-9A-Fa-f`]{1,18}$'){return $null};try{return [Convert]::ToUInt64(($V -replace '^0x','').Replace('`',''),16)}catch{return $null}}
function Get-RMCallbackConfig([string]$Path){
 if(!(Test-Path -LiteralPath $Path) -or (Get-Item $Path).Length -gt 4096){throw 'ConfigUnavailable'}
 $r=Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
 if($r.LoaderSHA256 -isnot [string] -or $r.LoaderSHA256 -cnotmatch '^[0-9a-fA-F]{64}$'){throw 'InvalidConfigHash'}
 foreach($k in @('ExceptionRVA','CallerReturnRVA','SlotOffset')){if($r.$k -isnot [int] -and $r.$k -isnot [long]){throw 'InvalidConfigNumber'};if($r.$k -lt 0 -or $r.$k -gt 2147483647){throw 'InvalidConfigRange'}}
 if(!$r.ExceptionRVA -or !$r.CallerReturnRVA -or $r.SlotOffset -gt 256 -or $r.SlotOffset%8 -ne 0){throw 'UnsupportedConfig'}
 return [pscustomobject]@{LoaderSHA256=$r.LoaderSHA256.ToLowerInvariant();ExceptionRVA=[uint64]$r.ExceptionRVA;CallerReturnRVA=[uint64]$r.CallerReturnRVA;SlotOffset=[uint64]$r.SlotOffset}
}
function Get-RMRecordedCallbackFrame([string]$Text){
 if($Text.Length -gt 8388608){throw 'LogTooLarge'}
 $inside=$false;$buffer=$false;$rows=@();$complete=$false
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim();if($l -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($l -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue}
  if($l -eq 'RM_CONTEXT_BEGIN'){$inside=$true;$rows=@();$complete=$false;continue};if($l -eq 'RM_CONTEXT_END'){$complete=$inside;$inside=$false;continue};if(!$inside){continue}
  if($l -match '^(?:[0-9a-f]{1,3}\s+)?([0-9a-f`]{8,17})\s+([0-9a-f`]{8,17})(?:\s|$)'){
   if($rows.Count -lt 8){$rows+=[pscustomobject]@{StackPointer=(Convert-RMSlotHex $matches[1]);ReturnAddress=(Convert-RMSlotHex $matches[2])}}
  }
 }
 $ctx=Get-RMContextIndicators $Text
 if(!$complete -or !$ctx.CurrentContextMatchesLastEventThread -or $rows.Count -lt 2){return $null}
 return [pscustomobject]@{TopReturnAddress=$rows[0].ReturnAddress;CallerStackPointer=$rows[1].StackPointer}
}
function New-RMCallbackSlotCommands([uint32]$ThreadId,[uint64]$ExceptionAddress,[uint64]$ReturnAddress,[uint64]$CallerSP,[uint64]$Offset){
 if(!$ThreadId -or !$ExceptionAddress -or !$ReturnAddress -or !$CallerSP -or $Offset -gt 256 -or $Offset%8 -ne 0){throw 'InvalidNumericCommandInput'}
 # .frame /c changes debugger LOCAL override context, not target registers. Restore frame 0 even on inner rejection.
 return ('.echo RM_SLOT_ATTEMPT; .lastevent; ~.; .frame /c 0x0; .if ((@$tid == 0x{0}) and (@rip == 0x{1})) {{ .frame /c /r 0x1; .if ((@rip == 0x{2}) and (@rsp == 0x{3})) {{ .echo RM_SLOT_BEGIN; dq @rsp+0x{4} L0x1; .echo RM_SLOT_END }} .else {{ .echo RM_SLOT_GUARD_REJECTED }}; .frame /c 0x0; .echo RM_SLOT_CONTEXT_RESTORED }} .else {{ .echo RM_SLOT_GUARD_REJECTED }}; .echo RM_SLOT_DONE' -f $ThreadId.ToString('x'),$ExceptionAddress.ToString('x'),$ReturnAddress.ToString('x'),$CallerSP.ToString('x'),$Offset.ToString('x'))+"`r"
}
function Get-RMCallbackSlotResult([string]$Text,[uint64]$ExpectedSlot,$Ranges){
 if($Text.Length -gt 8388608){throw 'LogTooLarge'}
 $inside=$false;$buffer=$false;$complete=$false;$count=0;$pointer=$null;$address=$null;$rejected=$false;$restored=$false;$done=$false
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim();if($l -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($l -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue}
  if($l -eq 'RM_SLOT_BEGIN'){$inside=$true;$complete=$false;$count=0;$pointer=$null;$address=$null;continue}
  if($l -eq 'RM_SLOT_END'){$complete=$inside;$inside=$false;continue}
  if($l -eq 'RM_SLOT_GUARD_REJECTED'){$rejected=$true};if($l -eq 'RM_SLOT_CONTEXT_RESTORED'){$restored=$true};if($l -eq 'RM_SLOT_DONE'){$done=$true}
  if($inside -and $l -match '^([0-9a-f`]{8,17})\s+([0-9a-f`]{8,17})\s*$'){$count++;$address=Convert-RMSlotHex $matches[1];$pointer=Convert-RMSlotHex $matches[2]}
 }
 $state='NotEstablished';$point=$null
 if($rejected){$state='GuardRejected'}elseif($complete -and $done -and $restored -and $count -eq 1 -and $address -eq $ExpectedSlot -and $null -ne $pointer){
  $state='OneSlotReadNotActualCallProof'
  $hits=@($Ranges|Where-Object {$pointer -ge $_.Base -and $pointer-$_.Base -lt $_.Size})
  if($pointer -and $hits.Count -eq 1 -and $hits[0].Kind -in @('Loader','MainExecutable','SystemNtdll')){$point=[pscustomobject]@{ModuleKind=$hits[0].Kind;RVA=('0x'+($pointer-$hits[0].Base).ToString('x'))}}
 }
 return [pscustomobject]@{ReadState=$state;CandidatePoint=$point;LocalContextRestoreMarkerObserved=$restored;DoneMarkerObserved=$done;SlotIsCandidateNotProvenCallTarget=$true;UnwindAccuracy='NotEstablished';BreakpointOrigin='NotEstablished';ContinuationAuthorized=$false;AbsoluteAddressesExported=$false}
}
function Get-RMSafeCallbackSlot([string]$Folder,[string]$Text){
 $empty=Get-RMCallbackSlotResult '' 0 @();$receipt=Join-Path $Folder 'callback-slot-result.json';$privatePath=Join-Path $Folder 'PRIVATE-callback-slot.json'
 $reason='NotAvailable';$queued=$false;$stage='NotAvailable'
 try{
  if(Test-Path $receipt){if((Get-Item $receipt).Length -le 4096){$r=Get-Content $receipt -Raw|ConvertFrom-Json
   if($r.CommandsQueued -is [bool]){$queued=$r.CommandsQueued}
   if($r.Reason -in @('ReadOnlyCommandsQueued','ReadNotConfirmedNoRetry')){$reason=$r.Reason}
   if($r.FailureStage -in @('None','ValidateState','Configuration','TargetIdentity','DebuggerIdentity','ModuleIdentity','RevalidateState','AttachOwnConsole','VerifyConsoleScope','QueueReadOnlyCommands')){$stage=$r.FailureStage}
  }}
  if($queued -and (Test-Path $privatePath) -and (Get-Item $privatePath).Length -le 16384){
   $p=Get-Content $privatePath -Raw|ConvertFrom-Json;$slot=Convert-RMSlotHex $p.SlotAddress;$ranges=@()
   foreach($m in @($p.Ranges)){if($m.Kind -notin @('Loader','MainExecutable','SystemNtdll')){continue};$b=Convert-RMSlotHex $m.Base;if($null -ne $b -and $m.Size -gt 0 -and $m.Size -le 2147483648){$ranges+=[pscustomobject]@{Kind=$m.Kind;Base=$b;Size=[uint64]$m.Size}}}
   if($null -ne $slot){$empty=Get-RMCallbackSlotResult $Text $slot $ranges}
  }
 }catch{}
 $empty|Add-Member -NotePropertyName CommandsQueued -NotePropertyValue $queued
 $empty|Add-Member -NotePropertyName RequestReason -NotePropertyValue $reason
 $empty|Add-Member -NotePropertyName FailureStage -NotePropertyValue $stage
 return $empty
}
