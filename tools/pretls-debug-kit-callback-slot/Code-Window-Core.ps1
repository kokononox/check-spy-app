# Compare fixed small code windows. No target execution, raw code or addresses in safe export.
. (Join-Path $PSScriptRoot 'Callback-Slot-Core.ps1')
function Read-RMStaticCodeWindow([string]$Path,[uint64]$RVA,[int]$Count){
 if($Count -notin @(16,32)){throw 'UnsupportedWindowSize'}
 $fs=[IO.File]::OpenRead($Path)
 try{
  $r=New-Object IO.BinaryReader($fs)
  if($fs.Length -lt 256 -or $r.ReadUInt16() -ne 0x5a4d){throw 'NotPE'}
  $fs.Position=0x3c;$pe=$r.ReadUInt32();if($pe -gt $fs.Length-264){throw 'InvalidPEOffset'}
  $fs.Position=$pe;if($r.ReadUInt32() -ne 0x4550 -or $r.ReadUInt16() -ne 0x8664){throw 'NotX64PE'}
  $sections=$r.ReadUInt16();if(!$sections -or $sections -gt 96){throw 'UnsupportedSections'}
  $fs.Position=$pe+20;$opt=$r.ReadUInt16();$table=[uint64]$pe+24+$opt
  if($opt -lt 112 -or $table+40*$sections -gt $fs.Length){throw 'InvalidPEHeaders'}
  $fs.Position=$pe+24;if($r.ReadUInt16() -ne 0x20b){throw 'NotPE32Plus'}
  $hits=@()
  for($i=0;$i -lt $sections;$i++){
   $fs.Position=$table+40*$i+8;$virtual=$r.ReadUInt32();$va=$r.ReadUInt32();$rawSize=$r.ReadUInt32();$rawOffset=$r.ReadUInt32();$fs.Position=$table+40*$i+36;$flags=$r.ReadUInt32()
   if($RVA -ge $va -and $RVA-$va+$Count -le $rawSize -and (!$virtual -or $RVA-$va+$Count -le $virtual) -and ($flags -band 0x20000000)){$hits+=[uint64]$rawOffset+$RVA-$va}
  }
  if($hits.Count -ne 1 -or $hits[0]+$Count -gt $fs.Length){throw 'CodeRangeNotUniqueOrNotFileBacked'}
  $fs.Position=$hits[0];$bytes=$r.ReadBytes($Count);if($bytes.Length -ne $Count){throw 'ShortRead'}
  return ,([byte[]]$bytes)
 }finally{$fs.Dispose()}
}
function Get-RMCodeWindowComparison([string]$Text,[string]$Label,[uint64]$Address,[byte[]]$Expected){
 if($Text.Length -gt 8388608 -or $Label -notin @('ENTRY','EXCEPTION') -or $Expected.Length -notin @(16,32)){throw 'UnsupportedComparison'}
 $inside=$false;$buffer=$false;$complete=$false;$bad=$false;$rejected=$false;$bytes=New-Object 'Collections.Generic.List[byte]'
 foreach($line in ($Text -split '\r\n|\r|\n')){
  $l=$line.Trim();if($l -match '^RM_BEGIN ctx='){$buffer=$true;continue};if($l -eq 'RM_END'){$buffer=$false;continue};if($buffer){continue}
  if($l -eq 'RM_CODE_GUARD_REJECTED'){$rejected=$true}
  if($l -eq ('RM_CODE_'+$Label+'_BEGIN')){$inside=$true;$complete=$false;$bad=$false;$bytes.Clear();continue}
  if($l -eq ('RM_CODE_'+$Label+'_END')){$complete=$inside;$inside=$false;continue};if(!$inside){continue}
  if($l -match '^([0-9a-f`]{8,17})\s+(.*)$'){
   $rowAddress=Convert-RMSlotHex $matches[1];$hex=($matches[2] -split '\s{2,}',2)[0] -replace '-',' ';$tokens=@($hex.Trim() -split '\s+')
   if($rowAddress -ne $Address+$bytes.Count -or $tokens.Count -ne 16 -or @($tokens|Where-Object {$_ -cnotmatch '^[0-9a-fA-F]{2}$'}).Count -or $bytes.Count+$tokens.Count -gt $Expected.Length){$bad=$true;continue}
   foreach($token in $tokens){$bytes.Add([Convert]::ToByte($token,16))}
  }else{$bad=$true}
 }
 $out=[pscustomobject]@{ReadState='NotEstablished';ComparedBytes=0;EqualToDisk=$null;ChangedByteOffsets=@();DiskInt3ByteOffsets=@();MemoryInt3ByteOffsets=@();DiskSHA256=$null;MemorySHA256=$null;RawCodeExported=$false;AbsoluteAddressesExported=$false;DifferenceCause='NotEstablished'}
 if(!$rejected -and $complete -and !$bad -and $bytes.Count -eq $Expected.Length){
  $out.ReadState='CompleteSmallWindow';$out.ComparedBytes=$Expected.Length;$changes=@();$diskCC=@();$memCC=@()
  for($i=0;$i -lt $Expected.Length;$i++){if($Expected[$i] -ne $bytes[$i]){$changes+=$i};if($Expected[$i] -eq 0xcc){$diskCC+=$i};if($bytes[$i] -eq 0xcc){$memCC+=$i}}
  $sha=[Security.Cryptography.SHA256]::Create();try{$out.DiskSHA256=([BitConverter]::ToString($sha.ComputeHash($Expected))).Replace('-','').ToLowerInvariant();$out.MemorySHA256=([BitConverter]::ToString($sha.ComputeHash($bytes.ToArray()))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
  $out.EqualToDisk=($changes.Count -eq 0);$out.ChangedByteOffsets=$changes;$out.DiskInt3ByteOffsets=$diskCC;$out.MemoryInt3ByteOffsets=$memCC
 }
 return $out
}
function Get-RMSafeCodeWindows([string]$Folder,[string]$Text){
 $out=[pscustomobject]@{State='NotAvailable';Entry=$null;Exception=$null;TotalComparedBytes=0;OnlySmallWindowsCompared=$true;WholeMappedImageIdentity='NotEstablished';DifferenceCause='NotEstablished';RawCodeExported=$false;AbsoluteAddressesExported=$false;ContinuationAuthorized=$false}
 try{
  $p=Join-Path $Folder 'PRIVATE-code-windows.json';if(!(Test-Path $p) -or (Get-Item $p).Length -gt 8192){return $out}
  $slot=Get-RMSafeCallbackSlot $Folder $Text
  if($slot.ReadState -ne 'OneSlotReadNotActualCallProof'){return $out}
  $r=Get-Content $p -Raw|ConvertFrom-Json
  foreach($label in @('Entry','Exception')){
   $w=$r.$label;$address=Convert-RMSlotHex $w.Address;$size=if($label -eq 'Entry'){32}else{16}
   if($null -eq $address -or $w.DiskHex -isnot [string] -or $w.DiskHex.Length -ne 2*$size -or $w.DiskHex -cnotmatch '^[0-9a-fA-F]+$'){return $out}
   $expected=New-Object byte[] $size;for($i=0;$i -lt $size;$i++){$expected[$i]=[Convert]::ToByte($w.DiskHex.Substring(2*$i,2),16)}
   $out.$label=Get-RMCodeWindowComparison $Text $label.ToUpperInvariant() $address $expected
  }
  $out.State=if($out.Entry.ReadState -eq 'CompleteSmallWindow' -and $out.Exception.ReadState -eq 'CompleteSmallWindow'){'BothWindowsCompared'}else{'IncompleteOrGuardRejected'}
  $out.TotalComparedBytes=$out.Entry.ComparedBytes+$out.Exception.ComparedBytes
 }catch{$out.State='NotEstablished'}
 return $out
}
