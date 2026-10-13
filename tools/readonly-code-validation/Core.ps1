Set-StrictMode -Version 2.0
function Get-ByteHash {
 param([byte[]]$Bytes)
 $h=[Security.Cryptography.SHA256]::Create()
 try { return ([BitConverter]::ToString($h.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally {$h.Dispose()}
}
function Get-ReadFailure {
 param($ErrorRecord)
 $x=$ErrorRecord.Exception.GetBaseException()
 if($x -is [HardwareSnapshot.ReadFailure]) {return @{Reason=$x.Reason;ErrorCode=$x.ErrorCode}}
 return @{Reason='ReadOrValidationFailed';ErrorCode=$null}
}
function Resolve-ScopedCode {
 param([UInt64]$Address,$Contexts)
 foreach($c in $Contexts) {
  if($Address -ge $c.Base -and ($Address-$c.Base) -lt $c.PE.ImageBytes) {
   $r=[UInt32]($Address-$c.Base)
   if(-not $c.PE.ExecutableRange($r,1)) {return $null}
   return @{Context=$c;RVA=$r}
  }
 }
 return $null
}
function Invoke-ScopedSnapshot {
 param($Manifest,$Contexts,[scriptblock]$ReadBytes)
 $main=@($Contexts|Where-Object {$_.Role -eq 'Main'})[0]
 $base=[UInt64]$main.Base
 $out=[ordered]@{
  Version=$Manifest.Version;Status='Starting';SnapshotUTC=[DateTime]::UtcNow.ToString('o')
  TargetFileMatched=$true;LoadedMainImageMatched=$false;DefaultInstanceVTableMatched=$false
  WholeMappedImageIdentity='NotEstablished';DiskHashesDoNotProveMemoryIdentity=$true
  MetadataStableAfterRead=$false;CodeWindows=@();CodeBytesCollected=0
  HardwarePayloadObserved=$false;ExactOutgoingURLObserved=$false
  Privacy=[ordered]@{
   WholeProcessDumpCreated=$false;HeapOrHardwareValueScanPerformed=$false
   PasswordOrTokenSearchPerformed=$false;NetworkPayloadCapturePerformed=$false
   MachineNameOrFilePathsExported=$false;ProcessIDExported=$false
   RawCodeBytesExported=$true;RuntimeAddressesMayBeEmbeddedInCode=$true
  }
  Safety=[ordered]@{
   ProcessAccessMask='0x1010';ProcessWrites=$false;DebuggerAttached=$false
   BreakpointsInserted=$false;ProcessSuspendedOrTerminated=$false
   GuardPagesSkipped=$true;PrivilegeEscalationAttempted=$false
   CertificatesOrProxyChanged=$false;NetworkRequestsMadeByTool=$false
  }
 }
 try {
  # Validate the live image header before dereferencing any message metadata.
  [byte[]]$dos=&$ReadBytes $base 64 $false
  if([BitConverter]::ToUInt16($dos,0) -ne 0x5a4d) {throw 'LiveDOSMismatch'}
  $nt=[BitConverter]::ToUInt32($dos,60)
  if($nt -gt 1048576 -or $nt+264 -ge $main.PE.ImageBytes) {throw 'LiveHeaderRange'}
  [byte[]]$hdr=&$ReadBytes ($base+$nt) 264 $false
  if([BitConverter]::ToUInt32($hdr,0) -ne 0x4550 -or [BitConverter]::ToUInt16($hdr,4) -ne 0x8664 -or
     [BitConverter]::ToUInt16($hdr,24) -ne 0x20b -or [BitConverter]::ToUInt32($hdr,80) -ne $Manifest.MainImageSize) {throw 'LivePEMismatch'}
  $out.LoadedMainImageMatched=$true
  [byte[]]$def=&$ReadBytes ($base+[UInt64]$Manifest.DefaultInstanceRVA) 8 $false
  if([BitConverter]::ToUInt64($def,0) -ne $base+[UInt64]$Manifest.VTableRVA) {throw 'DefaultVTableMismatch'}
  $out.DefaultInstanceVTableMatched=$true
  [byte[]]$vt=&$ReadBytes ($base+[UInt64]$Manifest.VTableRVA) 40 $false
  $remaining=[int]$Manifest.MaximumTotalCodeBytes
  foreach($method in $Manifest.Methods) {
   $r=[ordered]@{Slot=$method.Slot;Status='Starting';PointerClass='Unknown';ModuleRole=$null;FunctionRVA=$null
    EqualsExpectedDiskLocation=$false;KnownFunctionBytes=$null;RequestedBytes=0;CollectedBytes=0
    WindowKind=$null;TruncatedByLimit=$false;MemoryEqualsDisk=$null;DifferentByteCount=$null
    DiskSHA256=$null;MemorySHA256=$null;CodeBase64=$null;ReadFailure=$null}
   try {
    $addr=[BitConverter]::ToUInt64($vt,[int]$method.Slot*8)
    $resolved=Resolve-ScopedCode $addr $Contexts
    if($null -eq $resolved){$r.PointerClass='OutsideVerifiedExecutableScopes';$r.Status='SkippedUnverifiedPointer'}
    else {
     $ctx=$resolved.Context;$r.ModuleRole=$ctx.Role;$r.FunctionRVA='0x'+$resolved.RVA.ToString('x')
     $r.PointerClass='VerifiedModuleExecutableSection'
     $r.EqualsExpectedDiskLocation=($ctx.Role -eq 'Main' -and $resolved.RVA -eq [UInt32]$method.ExpectedRVA)
     if($r.EqualsExpectedDiskLocation) {$n=[int]$method.KnownDiskRangeBytes;$r.WindowKind='PreviouslyMappedMessageMethod'}
     else {
      $n=$ctx.PE.ExactFunctionBytes($resolved.RVA)
      if($n -gt 0){$r.WindowKind='ExactStartInVerifiedDiskUnwindTable'}else{$n=64;$r.WindowKind='BoundedPrefixWithoutKnownFunctionExtent'}
     }
     $r.KnownFunctionBytes=$n;$take=[Math]::Min($n,[Math]::Min($remaining,[int]$Manifest.MaximumCodeBytesPerMethod))
     if($take -lt 1){$r.Status='SkippedTotalByteLimit'}
     elseif(-not $ctx.PE.ExecutableRange($resolved.RVA,$take)){$r.Status='SkippedSectionBoundary'}
     else {
      $r.TruncatedByLimit=($take -lt $n);$r.RequestedBytes=$take
      # Charge attempted bytes even on failed reads: the total limit cannot be bypassed by retries.
      $remaining-=$take
      [byte[]]$memory=&$ReadBytes $addr $take $true
      if($memory.Length -ne $take){throw 'PartialRead'}
      [byte[]]$disk=$ctx.PE.ReadRVA($resolved.RVA,$take)
      $r.CollectedBytes=$take;$r.MemorySHA256=Get-ByteHash $memory;$r.DiskSHA256=Get-ByteHash $disk
      $diff=0;for($i=0;$i -lt $take;$i++){if($memory[$i] -ne $disk[$i]){$diff++}}
      $r.DifferentByteCount=$diff;$r.MemoryEqualsDisk=($diff -eq 0)
      $r.CodeBase64=[Convert]::ToBase64String($memory);$r.Status='Collected'
      $out.CodeBytesCollected+=$take
     }
    }
   } catch {$r.Status='ReadFailed';$r.ReadFailure=Get-ReadFailure $_}
   $out.CodeWindows+=,[pscustomobject]$r
  }
  [byte[]]$def2=&$ReadBytes ($base+[UInt64]$Manifest.DefaultInstanceRVA) 8 $false
  [byte[]]$vt2=&$ReadBytes ($base+[UInt64]$Manifest.VTableRVA) 40 $false
  $stable=([Convert]::ToBase64String($def) -eq [Convert]::ToBase64String($def2) -and
           [Convert]::ToBase64String($vt) -eq [Convert]::ToBase64String($vt2))
  $out.MetadataStableAfterRead=$stable
  if(-not $stable) {
   foreach($r in $out.CodeWindows){$r.CodeBase64=$null;$r.Status='DiscardedMetadataChanged'}
   $out.CodeBytesCollected=0;$out.Status='MetadataChangedNoUsableSnapshot'
  } elseif($out.CodeBytesCollected -gt 0) {$out.Status='LimitedCodeSnapshotCollected'}else{$out.Status='NoCodeWindowCollected'}
 } catch {
  foreach($r in $out.CodeWindows){$r.CodeBase64=$null}
  $out.CodeBytesCollected=0;$out.Status='StoppedAtValidationOrRead'
  $out.Failure=Get-ReadFailure $_
 }
 return [pscustomobject]$out
}