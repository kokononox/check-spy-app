param([string]$Root=(Split-Path $PSScriptRoot -Parent),[string]$GameFile)
$ErrorActionPreference='Stop'
trap { Write-Output ('::error::Owned fixture failure: '+$_.Exception.Message+'; line='+$_.InvocationInfo.ScriptLineNumber); exit 1 }
Add-Type -Path (Join-Path $Root 'Native.cs')
. (Join-Path $Root 'Core.ps1')
Add-Type @'
public class FixturePE {
 public uint ImageBytes=65536;
 public bool ExecutableRange(uint r,int n){return n>0 && r>=4096 && (ulong)r+(uint)n<=12288;}
 public int ExactFunctionBytes(uint r){return r==8192?32:0;}
 public byte[] ReadRVA(uint r,int n){byte[] b=new byte[n];for(int i=0;i<n;i++)b[i]=0x90;return b;}
}
'@
$script:checks=0
function Check($condition,$label){if(-not $condition){throw ('Test failed: '+$label)};$script:checks++}
$base=[UInt64]0x140000000
$manifest=[pscustomobject]@{
 Version='SyntheticOnly';MainImageSize=65536;DefaultInstanceRVA=24576;VTableRVA=24832
 MaximumCodeBytesPerMethod=8192;MaximumTotalCodeBytes=24576
 Methods=@(0..4|ForEach-Object {[pscustomobject]@{Slot=$_;ExpectedRVA=4096+256*$_;KnownDiskRangeBytes=32}})
}
$contexts=@(@{Role='Main';Base=$base;PE=(New-Object FixturePE)},@{Role='Loader';Base=[UInt64]0x180000000;PE=(New-Object FixturePE)})
$script:mode='Normal';$script:defReads=0;$script:vtReads=0;$script:reads=@()
$reader={
 param([UInt64]$Address,[int]$Count,[bool]$Exec)
 $script:reads+=,@{Address=$Address;Count=$Count;Exec=$Exec}
 if($Address -eq $base) {
  $b=New-Object byte[] 64;$b[0]=0x4d;$b[1]=0x5a
  [Array]::Copy([BitConverter]::GetBytes([UInt32]128),0,$b,60,4)
  if($script:mode -eq 'BadDOS'){$b[0]=0}
  return ,$b
 }
 if($Address -eq $base+128) {
  $b=New-Object byte[] 264
  [Array]::Copy([BitConverter]::GetBytes([UInt32]0x4550),0,$b,0,4)
  [Array]::Copy([BitConverter]::GetBytes([UInt16]0x8664),0,$b,4,2)
  [Array]::Copy([BitConverter]::GetBytes([UInt16]0x20b),0,$b,24,2)
  [Array]::Copy([BitConverter]::GetBytes([UInt32]65536),0,$b,80,4)
  return ,$b
 }
 if($Address -eq $base+24576) {
  $script:defReads++
  $ptr=$base+24832
  if($script:mode -eq 'BadDefault' -or ($script:mode -eq 'ChangedMetadata' -and $script:defReads -gt 1)){$ptr++}
  return ,([BitConverter]::GetBytes([UInt64]$ptr))
 }
 if($Address -eq $base+24832) {
  $script:vtReads++;$b=New-Object byte[] 40
  foreach($m in $manifest.Methods) {
   $ptr=$base+[UInt64]$m.ExpectedRVA
   if($m.Slot -eq 0 -and $script:mode -eq 'Outside'){$ptr=[UInt64]0x7fffdeadbeef}
   if($m.Slot -eq 0 -and $script:mode -eq 'LoaderPointer'){$ptr=[UInt64]0x180002000}
   [Array]::Copy([BitConverter]::GetBytes([UInt64]$ptr),0,$b,[int]$m.Slot*8,8)
  }
  return ,$b
 }
 if(-not $Exec){throw 'Unplanned metadata read'}
 if($script:mode -eq 'Guard'){throw (New-Object HardwareSnapshot.ReadFailure -ArgumentList 'GuardOrUnreadablePage',0)}
 $n=$Count;if($script:mode -eq 'Partial'){$n--}
 $b=New-Object byte[] $n;for($i=0;$i -lt $n;$i++){$b[$i]=0x90}
 if($script:mode -eq 'ChangedCode' -and $Address -eq $base+4608){$b[0]=0xcc}
 return ,$b
}
function Run-Case($name) {
 $script:mode=$name;$script:defReads=0;$script:vtReads=0;$script:reads=@()
 return Invoke-ScopedSnapshot $manifest $contexts $reader
}
$r=Run-Case 'Normal'
Check ($r.Status -eq 'LimitedCodeSnapshotCollected') 'normal success'
Check ($r.CodeWindows.Count -eq 5) 'exactly five slots'
Check ($r.CodeBytesCollected -eq 160) 'exact byte count'
Check ($r.MetadataStableAfterRead) 'stable metadata'
foreach($w in $r.CodeWindows){
 Check ($w.MemoryEqualsDisk) 'equal disk comparison'
 Check ([Convert]::FromBase64String($w.CodeBase64).Length -eq 32) 'code roundtrip'
}
Check (-not $r.HardwarePayloadObserved) 'not upload evidence'
Check (-not $r.ExactOutgoingURLObserved) 'not URL evidence'
Check ($r.Privacy.RuntimeAddressesMayBeEmbeddedInCode) 'code privacy caveat retained'
Check ($script:reads.Count -eq 11) 'bounded reads count'
Check ((($script:reads|Where-Object {-not $_.Exec}|Measure-Object -Property Count -Sum).Sum) -eq 424) 'metadata byte cap'
$r=Run-Case 'BadDOS';Check ($r.Status -eq 'StoppedAtValidationOrRead') 'bad live header stops'
$r=Run-Case 'BadDefault';Check ($r.CodeWindows.Count -eq 0) 'default instance mismatch stops before code'
$r=Run-Case 'ChangedMetadata'
Check ($r.Status -eq 'MetadataChangedNoUsableSnapshot') 'metadata race rejected'
Check ($r.CodeBytesCollected -eq 0) 'race bytes discarded'
Check (@($r.CodeWindows|Where-Object {$null -ne $_.CodeBase64}).Count -eq 0) 'no raced code export'
$r=Run-Case 'Outside'
Check ($r.CodeWindows[0].Status -eq 'SkippedUnverifiedPointer') 'external target not followed'
Check ($r.CodeBytesCollected -eq 128) 'other verified slots collected'
$r=Run-Case 'LoaderPointer'
Check ($r.CodeWindows[0].ModuleRole -eq 'Loader') 'hash-verified loader scope'
Check ($r.CodeWindows[0].WindowKind -eq 'ExactStartInVerifiedDiskUnwindTable') 'new mapped function bounded'
$r=Run-Case 'Guard'
Check ($r.CodeBytesCollected -eq 0) 'guard pages not read'
Check ($r.CodeWindows[0].ReadFailure.Reason -eq 'GuardOrUnreadablePage') 'guard refusal recorded'
$r=Run-Case 'Partial';Check ($r.CodeBytesCollected -eq 0) 'partial reads rejected'
$r=Run-Case 'ChangedCode'
Check ($r.CodeWindows[2].DifferentByteCount -eq 1) 'real code difference counted'
Check (-not $r.CodeWindows[2].MemoryEqualsDisk) 'difference retained'
$manifest.MaximumCodeBytesPerMethod=16;$manifest.MaximumTotalCodeBytes=40
$r=Run-Case 'Normal'
Check ($r.CodeBytesCollected -eq 40) 'total budget'
Check ($r.CodeWindows[0].TruncatedByLimit) 'per-method cap'
Check ($r.CodeWindows[3].Status -eq 'SkippedTotalByteLimit') 'budget exhaustion no retry'
$json=$r|ConvertTo-Json -Depth 12
foreach($label in @('FileName','ProcessID','MachineName','AbsoluteAddress')) {Check (-not ($json -match ('"'+$label+'"\s*:'))) ('no '+$label+' property')}
if($GameFile) {
 $pe=New-Object HardwareSnapshot.PE -ArgumentList $GameFile
 $m=Get-Content -Raw (Join-Path $Root 'manifest.json')|ConvertFrom-Json
 Check ($pe.ImageBytes -eq $m.MainImageSize) 'real PE parser image size'
 foreach($w in $m.Methods){
  Check ($pe.ExecutableRange($w.ExpectedRVA,$w.KnownDiskRangeBytes)) 'real disk section bound'
  Check ($pe.ReadRVA($w.ExpectedRVA,$w.KnownDiskRangeBytes).Length -eq $w.KnownDiskRangeBytes) 'real disk read'
  if($w.Slot -ne 3){Check ($pe.ExactFunctionBytes($w.ExpectedRVA) -eq $w.KnownDiskRangeBytes) 'real disk unwind range'}
 }
}
Write-Output ('SyntheticChecksPassed='+$script:checks+'; LiveWindowsReadTested=False')