# Read-only, fixed-name target Logs audit. No values, lines, paths or IDs are exported.
function Get-RM27Prefix([string]$Path,[int]$Length=4096){
 $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
 try{$bytes=New-Object byte[] ([Math]::Min($Length,$stream.Length));$at=0;while($at -lt $bytes.Length){$n=$stream.Read($bytes,$at,$bytes.Length-$at);if(!$n){break};$at+=$n};$sha=[Security.Cryptography.SHA256]::Create();try{return [pscustomobject]@{Length=$at;Hash=([BitConverter]::ToString($sha.ComputeHash($bytes,0,$at))).Replace('-','')}}finally{$sha.Dispose()}}finally{$stream.Dispose()}
}
function Get-RM27LogBaseline([string]$TargetPath){
 $dir=Join-Path ([IO.Path]::GetDirectoryName($TargetPath)) 'Logs';$files=@();$safe=$true
 if(Test-Path -LiteralPath $dir){$safe=((Get-Item -LiteralPath $dir).Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0}
 foreach($name in @('cpu.log','gx.log','Client.log','Tact.log','Sound.log','AccountData.log')){
  $path=Join-Path $dir $name;$entry=[ordered]@{Name=$name;Path=$path;Exists=$false;Length=0L;WriteUTC='';PrefixLength=0;PrefixHash='';Readable=$safe}
  if($safe -and (Test-Path -LiteralPath $path -PathType Leaf)){
   try{$f=Get-Item -LiteralPath $path;if($f.Attributes -band [IO.FileAttributes]::ReparsePoint){$entry.Readable=$false}else{$p=Get-RM27Prefix $path;$entry.Exists=$true;$entry.Length=$f.Length;$entry.WriteUTC=$f.LastWriteTimeUtc.ToString('o');$entry.PrefixLength=$p.Length;$entry.PrefixHash=$p.Hash}}catch{$entry.Readable=$false}
  };$files+=([pscustomobject]$entry)
 }
 return [pscustomobject]@{Files=$files;Scope='Fixed known logs in target Logs directory only; no recursive or launcher-wide search'}
}
function Complete-RM27LogAudit($Baseline,[datetime]$StartUTC,[datetime]$EndUTC){
 $results=@();$allCategories=@();$allEvents=@()
 foreach($entry in $Baseline.Files){
  $r=[ordered]@{Log=$entry.Name;Changed=$false;ReadStatus='Missing';ReadBytes=0;Truncated=$false;DatedRowsInWindow=0;UndatedOrOutOfWindowRows=0;LocalFieldCategories=@();RecordedEvents=@()}
  if(!$entry.Readable){$r.ReadStatus='Skipped baseline unreadable or reparse point';$results+=([pscustomobject]$r);continue}
  if(!(Test-Path -LiteralPath $entry.Path -PathType Leaf)){$results+=([pscustomobject]$r);continue}
  try{
   $file=Get-Item -LiteralPath $entry.Path
   if(($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or ((Get-Item -LiteralPath $file.DirectoryName).Attributes -band [IO.FileAttributes]::ReparsePoint)){$r.ReadStatus='Skipped reparse point';$results+=([pscustomobject]$r);continue}
   $r.Changed=(!$entry.Exists -or $file.Length -ne $entry.Length -or $file.LastWriteTimeUtc.ToString('o') -ne $entry.WriteUTC)
   if(!$r.Changed){$r.ReadStatus='Unchanged; old content not read';$results+=([pscustomobject]$r);continue}
   $offset=0L
   if($entry.Exists -and $file.Length -ge $entry.Length -and $entry.PrefixLength -gt 0){$prefix=Get-RM27Prefix $entry.Path $entry.PrefixLength;if($prefix.Hash -eq $entry.PrefixHash){$offset=[long]$entry.Length}}
   $stream=[IO.File]::Open($entry.Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
   try{
    $stream.Position=$offset;$length=[Math]::Min(2097152,[Math]::Max(0,$stream.Length-$offset));$r.Truncated=($stream.Length-$offset -gt $length)
    $bytes=New-Object byte[] $length;$read=0;while($read -lt $length){$n=$stream.Read($bytes,$read,$length-$read);if(!$n){break};$read+=$n};$r.ReadBytes=$read
   }finally{$stream.Dispose()}
   $text=[Text.Encoding]::UTF8.GetString($bytes,0,$read);$bytes=$null;$r.ReadStatus='Changed content read; timestamp-filtered'
   foreach($line in ($text -split '\r?\n')){
    if(!$line){continue}
    $stamp=[regex]::Match($line,'^\s*(\d{1,2})/(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?\s+')
    if(!$stamp.Success){$r.UndatedOrOutOfWindowRows++;continue}
    $valid=$false
    foreach($year in @(($StartUTC.ToLocalTime().Year-1),($StartUTC.ToLocalTime().Year),($StartUTC.ToLocalTime().Year+1))){
     try{$date='{0}/{1}/{2} {3}:{4}:{5}.{6}' -f $stamp.Groups[1].Value,$stamp.Groups[2].Value,$year,$stamp.Groups[3].Value,$stamp.Groups[4].Value,$stamp.Groups[5].Value,$stamp.Groups[6].Value.PadRight(3,'0');$at=[datetime]::SpecifyKind([datetime]::ParseExact($date,'M/d/yyyy HH:mm:ss.fff',[Globalization.CultureInfo]::InvariantCulture),[DateTimeKind]::Local).ToUniversalTime();if($at -ge $StartUTC.AddSeconds(-2) -and $at -le $EndUTC.AddSeconds(2)){$valid=$true;break}}catch{}
    }
    if(!$valid){$r.UndatedOrOutOfWindowRows++;continue};$r.DatedRowsInWindow++
    $body=$line.Substring($stamp.Length)
    # Fixed semantic patterns only. Never persist arbitrary matches or values.
    if($entry.Name -eq 'cpu.log'){
     foreach($pair in @(@('^vendor\s*:','CPUVendor'),@('^branding\s*:','CPUModel'),@('^(sockets|cores|threads)\s*:','CPUCoreTopology'),@('^features\s*:','CPUFeatures'))){if($body -match $pair[0]){$r.LocalFieldCategories+=$pair[1]}}
    }
    if($entry.Name -eq 'gx.log'){
     foreach($pair in @(@('\bWindows\s+\d','OperatingSystem'),@('\bCPU\b','CPUModel'),@('\bMotherboard\s*:','Motherboard'),@('\bBIOS\s*:','BIOS'),@('\bSystem Memory\b','PhysicalMemory'),@('\bAdapter\s+\d+\s*:','GPU'),@('\bdriver_ver\s*:','GPUDriver'),@('\bMonitor\s+\d','Display'))){if($body -match $pair[0]){$r.LocalFieldCategories+=$pair[1]}}
    }
    if($entry.Name -eq 'Sound.log' -and $body -match 'Output drivers detected|Headphones|Speakers'){$r.LocalFieldCategories+='AudioDevices'}
    if($entry.Name -eq 'Client.log' -and $body -match '\bCharacter Login SEND\b'){$r.RecordedEvents+='CharacterLoginSendRecorded'}
    if($entry.Name -eq 'Tact.log' -and $body -match '\bDownloading config with key\b'){$r.RecordedEvents+='ConfigDownloadRecorded'}
    if($entry.Name -eq 'AccountData.log' -and $body -match '\bReceived Server Save Times\b'){$r.RecordedEvents+='AccountSaveTimesReceived'}
   }
   $text=$null;$r.LocalFieldCategories=@($r.LocalFieldCategories|Sort-Object -Unique);$r.RecordedEvents=@($r.RecordedEvents|Sort-Object -Unique)
   $allCategories+=$r.LocalFieldCategories;$allEvents+=$r.RecordedEvents
  }catch{$r.ReadStatus='Read failed; no conclusion'}
  $results+=([pscustomobject]$r)
 }
 return [pscustomobject]@{Scope=$Baseline.Scope;StartUTC=$StartUTC.ToString('o');EndUTC=$EndUTC.ToString('o');Logs=$results;LocalFieldCategories=@($allCategories|Sort-Object -Unique);RecordedEvents=@($allEvents|Sort-Object -Unique);ValuesStored=$false;Assessment='Local log evidence only; not packet content or proof of transmission';Limitations=@('Only changed fixed-name target logs are read, capped at 2 MiB each. Appended content is used when a baseline prefix matches; rewritten files are timestamp-filtered.','Dates assume M/d timestamps in local Windows timezone; undated, out-of-window or unsupported-format lines are excluded.','No independent proof of which process wrote the logs. Reading or locally logging a system field does not prove that value was sent.','Reparse-point directories/files are skipped. Live writes, rotation and truncation can reduce coverage.')}
}
