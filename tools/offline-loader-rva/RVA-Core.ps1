# Offline bounded relative-address extraction. Never executes targets or debugger commands.
. (Join-Path $PSScriptRoot 'Startup-Metadata-Core.ps1')
function Convert-RMRecordedHex($Value){
 if($Value -isnot [string] -or $Value -cnotmatch '^(?:0x)?[0-9a-fA-F`]{1,18}$'){return $null}
 try{return [Convert]::ToUInt64(($Value -replace '^0x','').Replace('`',''),16)}catch{return $null}
}
function Convert-RMAddressToSafeRVA([uint64]$Address,$Mappings){
 if(!$Address){return $null}
 $hits=@($Mappings|Where-Object {$Address -ge $_.Base -and $Address-$_.Base -lt $_.ImageBytes})
 if($hits.Count -ne 1){return $null}
 $m=$hits[0]
 if($m.Kind -notin @('MainExecutable','Loader','SystemNtdll')){return $null}
 return [pscustomobject]@{ModuleKind=$m.Kind;RVA=('0x'+($Address-$m.Base).ToString('x'))}
}
function Get-RMExceptionRelativePoint([string]$Text,$Mappings){
 if($Text.Length -gt 8388608){throw 'LogTooLarge'}
 $inside=$false;$buffer=$false;$complete=$false;$address=$null;$code='Unknown'
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim()
  if($l -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($l -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue}
  if($l -eq 'RM_INITIAL_EVENT_BEGIN'){$inside=$true;$complete=$false;$address=$null;$code='Unknown';continue}
  if($l -eq 'RM_INITIAL_EVENT_END'){$complete=$inside;$inside=$false;continue}
  if(!$inside){continue}
  if($l -match '^ExceptionAddress:\s*([0-9a-f`]{8,17})(?:\s|$)'){$address=Convert-RMRecordedHex $matches[1]}
  if($l -match '^ExceptionCode:\s*([0-9a-f]{8})\b'){$code=$matches[1].ToLowerInvariant()}
 }
 $point=$null;if($complete -and $null -ne $address){$point=Convert-RMAddressToSafeRVA $address $Mappings}
 return [pscustomobject]@{Complete=$complete;ExceptionClass=$(switch($code){'80000003'{'BreakInstruction'};'c0000005'{'AccessViolation'};default{'OtherOrUnknown'}});Point=$point}
}
function Get-RMStackRelativeReturns([string]$Text,$Mappings){
 if($Text.Length -gt 8388608){throw 'LogTooLarge'}
 $inside=$false;$buffer=$false;$complete=$false;$rows=@();$rowIndex=0
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim()
  if($l -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($l -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue}
  if($l -eq 'RM_CONTEXT_BEGIN'){$inside=$true;$complete=$false;$rows=@();$rowIndex=0;continue}
  if($l -eq 'RM_CONTEXT_END'){$complete=$inside;$inside=$false;continue}
  if(!$inside){continue}
  if($l -match '^(?:[0-9a-f]{1,3}\s+)?[0-9a-f`]{8,17}\s+([0-9a-f`]{8,17})(?:\s|$)'){
   if($rowIndex -lt 8){
    $a=Convert-RMRecordedHex $matches[1];$point=$null;if($null -ne $a){$point=Convert-RMAddressToSafeRVA $a $Mappings}
    $rows+= [pscustomobject]@{FrameRowIndex=$rowIndex;ReturnPoint=$point}
   };$rowIndex++
  }
 }
 if(!$complete){$rows=@()}
 return [pscustomobject]@{Complete=$complete;Rows=$rows;ReturnAddressesAreNotExecutedInstructions=$true;UnwindAccuracy='NotEstablished'}
}
function Get-RMOfflineRVAReport([string]$Text,$Private,$Safe,[uint32]$TargetId,$Mappings){
 $ev=Get-RMInitialEventIdentity $Text;$ctx=Get-RMContextIndicators $Text
 $eligible=($Safe.Collection -eq 'Collected' -and $ev.Complete -and $ev.Code -eq $ev.RecordCode -and $ev.Code -in @('80000003','c0000005') -and $ev.Chance -eq 'first' -and $ev.ProcessId -eq $TargetId -and $ev.ThreadId -and $Private.EventThreadId -eq $ev.ThreadId)
 $exception=$null;$thread=$null;$returns=$null
 if($eligible){
  $exception=Get-RMExceptionRelativePoint $Text $Mappings
  if($Safe.EventThreadQuery -eq 'Success'){$start=Convert-RMRecordedHex $Private.ThreadStartAddress;if($null -ne $start){$thread=Convert-RMAddressToSafeRVA $start $Mappings}}
  if($ctx.Complete -and $ctx.CurrentContextMatchesLastEventThread){$returns=Get-RMStackRelativeReturns $Text $Mappings}
 }
 $fingerprints=@()
 foreach($m in $Mappings){if($m.Kind -in @('MainExecutable','Loader','SystemNtdll') -and $m.SHA256 -is [string] -and $m.SHA256 -cmatch '^[0-9a-fA-F]{64}$'){$fingerprints+=[pscustomobject]@{ModuleKind=$m.Kind;SHA256=$m.SHA256.ToLowerInvariant();ImageBytes=$m.ImageBytes;DiskHashMatchesRecordedSnapshot=$true}}}
 return [pscustomobject]@{Version='0.1-offline-rva';ExtractionState=$(if($eligible){'SnapshotAccepted'}else{'SnapshotNotAccepted'});ModuleFingerprints=$fingerprints;InitialException=$exception;RecordedThreadStart=$thread;ContextThreadMatchesLastEvent=$(if($eligible){$ctx.CurrentContextMatchesLastEventThread}else{$null});StackReturnAddresses=$returns;SourceIsSavedLocalSession=$true;DiskHashesAreNotMemoryIdentity=$true;BreakpointOrigin='NotEstablished';ContinuationAuthorized=$false;URLsExported=$false;HeaderValuesExported=$false;BodiesExported=$false;PathsExported=$false;AbsoluteAddressesExported=$false}
}
