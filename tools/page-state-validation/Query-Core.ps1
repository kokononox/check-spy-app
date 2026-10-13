Set-StrictMode -Version 2.0
function Get-RegionClassification {
 param([UInt32]$State,[UInt32]$Protect,[UInt32]$Type)
 $stateName='Unknown'
 if($State -eq 0x1000){$stateName='MEM_COMMIT'}
 elseif($State -eq 0x2000){$stateName='MEM_RESERVE'}
 elseif($State -eq 0x10000){$stateName='MEM_FREE'}
 $committed=($State -eq 0x1000)
 $guard=$null;$noAccess=$null;$protection=$null;$executable=$null
 $flags=@()
 if($committed) {
  $guard=(($Protect -band 0x100) -ne 0)
  $basic=$Protect -band 0xff;$noAccess=($basic -eq 1)
  $map=@{1='PAGE_NOACCESS';2='PAGE_READONLY';4='PAGE_READWRITE';8='PAGE_WRITECOPY';
   16='PAGE_EXECUTE';32='PAGE_EXECUTE_READ';64='PAGE_EXECUTE_READWRITE';128='PAGE_EXECUTE_WRITECOPY'}
  if($map.ContainsKey([int]$basic)){$protection=$map[[int]$basic]}else{$protection='UnspecifiedOrUnknown'}
  $executable=(@(16,32,64,128) -contains [int]$basic)
  if($guard){$flags+='PAGE_GUARD'}
  if(($Protect -band 0x200) -ne 0){$flags+='PAGE_NOCACHE'}
  if(($Protect -band 0x400) -ne 0){$flags+='PAGE_WRITECOMBINE'}
 }
 $cause=@()
 if(-not $committed){$cause+='NotCommitted'}
 else {
  if($guard){$cause+='GuardFlag'}
  if($noAccess){$cause+='NoAccess'}
 }
 $typeName='Unknown'
 if($State -eq 0x10000){$typeName='NotApplicableForFreeMemory'}
 elseif($Type -eq 0x1000000){$typeName='MEM_IMAGE'}
 elseif($Type -eq 0x40000){$typeName='MEM_MAPPED'}
 elseif($Type -eq 0x20000){$typeName='MEM_PRIVATE'}
 return [pscustomobject]@{State=$stateName;Protection=$protection;ProtectionMeaningful=$committed
  GuardFlag=$guard;NoAccess=$noAccess;ExecutableProtection=$executable;ModifierFlags=$flags
  Type=$typeName;LegacyReadPrecheckWouldBlock=($cause.Count -gt 0);LegacyBlockingReasons=$cause}
}
function Get-SafeQueryFailure {
 param($ErrorRecord)
 $e=$ErrorRecord.Exception.GetBaseException()
 if($e -is [PageStateOnly.QueryFailure]){return @{Reason=$e.Reason;ErrorCode=$e.Code}}
 $allow=@('QueryRangeLimit','InvalidRegionRange','MainImageSizeMismatch','TargetVersionMismatch','ModuleChanged','ProcessExited')
 if($allow -contains $e.Message){return @{Reason=$e.Message;ErrorCode=$null}}
 return @{Reason='QueryOrValidationFailed';ErrorCode=$null}
}
function Invoke-PageStateQuery {
 param($Manifest,[UInt64]$Base,[UInt64]$ImageBytes,[scriptblock]$Query)
 $out=[ordered]@{Version=$Manifest.Version;Status='Starting';SnapshotUTC=[DateTime]::UtcNow.ToString('o')
  TargetDiskFileMatched=$true;ModuleSizeMatched=$false;ModuleStableAfterQuery=$false
  WholeMappedImageIdentity='NotEstablished';MessageMetadataReadInThisTest=$false
  Methods=@();QueriesAttempted=0;CodeBytesCollected=0;HardwarePayloadObserved=$false;ExactOutgoingURLObserved=$false
  Safety=[ordered]@{ExplicitProcessAccessMask='0x0400';VMReadAccessRequested=$false;CodeBytesRead=$false
   ProcessMemoryContentsCollected=$false;ProcessWrites=$false;ProtectionChanged=$false
   DebuggerAttached=$false;BreakpointInserted=$false;PrivilegeEscalationAttempted=$false
   ProcessSuspendedOrTerminated=$false;NetworkRequestsMadeByTool=$false}
  Privacy=[ordered]@{RawCodeExported=$false;AbsoluteAddressesExported=$false;PIDExported=$false
   FilePathsExported=$false;MachineNameExported=$false}}
 try {
  if($ImageBytes -ne [UInt64]$Manifest.MainImageSize){throw 'MainImageSizeMismatch'}
  $out.ModuleSizeMatched=$true
  foreach($m in $Manifest.Methods) {
   $mr=[ordered]@{Slot=$m.Slot;FunctionRVA=('0x'+([UInt32]$m.RVA).ToString('x'));WindowBytes=$m.Bytes;Status='Starting';Regions=@();Failure=$null}
   try {
    $start=[UInt64]$m.RVA;$end=$start+[UInt64]$m.Bytes
    if($m.Bytes -lt 1 -or $m.Bytes -gt 8192 -or $end -gt $ImageBytes -or $Base+$end -gt [UInt64]0x7fffffffffff){throw 'QueryRangeLimit'}
    $cursor=$start;$local=0
    while($cursor -lt $end) {
     if($local -ge $Manifest.MaximumQueriesPerMethod -or $out.QueriesAttempted -ge $Manifest.MaximumQueriesTotal){throw 'QueryRangeLimit'}
     $out.QueriesAttempted++;$local++
     $region=&$Query ($Base+$cursor)
     if($region.Bytes -lt 1 -or $region.Base -gt $Base+$cursor -or $region.Base+$region.Bytes -le $Base+$cursor){throw 'InvalidRegionRange'}
     $next=[Math]::Min($Base+$end,[UInt64]($region.Base+$region.Bytes))
     $c=Get-RegionClassification $region.State $region.Protect $region.Type
     $rr=[ordered]@{QueryRVA=('0x'+$cursor.ToString('x'));CoveredBytesInThisWindow=($next-$Base-$cursor)
      StateValue=('0x'+([UInt32]$region.State).ToString('x'));ProtectValue=$null;TypeValue=$null
      NativeStructureBytes=$region.ReturnedStructureBytes;Classification=$c}
     # Protect is undefined for reserved/free pages: do not falsely call them PAGE_NOACCESS.
     if($region.State -eq 0x1000){$rr.ProtectValue='0x'+([UInt32]$region.Protect).ToString('x')}
     if($region.State -ne 0x10000){$rr.TypeValue='0x'+([UInt32]$region.Type).ToString('x')}
     $mr.Regions+=,[pscustomobject]$rr
     $cursor=$next-$Base
    }
    $mr.Status='Queried'
   } catch {$mr.Status='Stopped';$mr.Failure=Get-SafeQueryFailure $_}
   $out.Methods+=,[pscustomobject]$mr
  }
  if(@($out.Methods|Where-Object {$_.Status -eq 'Queried'}).Count -eq 5){$out.Status='PageStatesCollected'}
  else{$out.Status='PartialOrFailedPageQuery'}
 } catch {$out.Status='Stopped';$out.Failure=Get-SafeQueryFailure $_}
 return [pscustomobject]$out
}