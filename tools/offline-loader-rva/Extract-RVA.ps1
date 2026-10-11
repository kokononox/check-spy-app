# Reads saved own-tool session files and local PE headers. No process/debugger/network operations.
param([Parameter(Mandatory=$true)][string]$SessionFolder,[Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'RVA-Core.ps1')
function Read-BoundedJson([string]$Path,[long]$Limit){
 if((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'ReparseFileRefused'}
 if((Get-Item -LiteralPath $Path).Length -gt $Limit){throw 'JSONTooLarge'}
 return (Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json)
}
function Read-LocalPEImageSize([string]$Path){
 if(!$Path -or $Path.StartsWith('\')){throw 'NetworkPathRefused'}
 $root=[IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path));$drive=New-Object IO.DriveInfo($root)
 if($drive.DriveType -notin @([IO.DriveType]::Fixed,[IO.DriveType]::Removable,[IO.DriveType]::Ram)){throw 'NonLocalDriveRefused'}
 $file=Get-Item -LiteralPath $Path
 if($file.Attributes -band [IO.FileAttributes]::ReparsePoint -or $file.Length -gt 4294967296){throw 'UnsupportedFile'}
 $fs=[IO.File]::OpenRead($Path)
 try{
  $r=New-Object IO.BinaryReader($fs)
  if($fs.Length -lt 256 -or $r.ReadUInt16() -ne 0x5a4d){throw 'NotPE'}
  $fs.Position=0x3c;$offset=$r.ReadUInt32()
  if($offset -gt $fs.Length-84){throw 'InvalidPEOffset'}
  $fs.Position=$offset
  if($r.ReadUInt32() -ne 0x4550 -or $r.ReadUInt16() -ne 0x8664){throw 'NotX64PE'}
  $fs.Position=$offset+20;$optionalSize=$r.ReadUInt16()
  if($optionalSize -lt 60 -or $offset+24+$optionalSize -gt $fs.Length){throw 'InvalidOptionalHeader'}
  $fs.Position=$offset+24;if($r.ReadUInt16() -ne 0x20b){throw 'NotPE32Plus'}
  $fs.Position=$offset+24+56;$size=$r.ReadUInt32()
  if(!$size -or $size -gt 2147483648){throw 'UnsupportedImageSize'}
  return [uint64]$size
 }finally{$fs.Dispose()}
}
$root=[IO.Path]::GetFullPath((Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor\PreTLS-PRIVATE'))
$folder=[IO.Path]::GetFullPath($SessionFolder)
if(![string]::Equals([IO.Path]::GetDirectoryName($folder),$root,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($folder) -cnotmatch '^[0-9a-fA-F]{32}$'){throw 'SessionFolderOutsideOwnStore'}
foreach($p in @($root,$folder)){if((Get-Item -LiteralPath $p).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'ReparseFolderRefused'}}
$session=Read-BoundedJson (Join-Path $folder 'PRIVATE-ui-session.json') 16384
if(![string]::Equals([IO.Path]::GetFullPath($session.Root),$folder,[StringComparison]::OrdinalIgnoreCase) -or ![string]::Equals([IO.Path]::GetFullPath($session.LogPath),(Join-Path $folder 'PRIVATE-cdb.txt'),[StringComparison]::OrdinalIgnoreCase)){throw 'SessionPathsMismatch'}
$private=Read-BoundedJson (Join-Path $folder 'PRIVATE-startup-metadata.json') 65536
$safe=Get-RMSafeStartupMetadata $folder
$logFile=Get-Item -LiteralPath $session.LogPath
if($logFile.Length -gt 8388608 -or $logFile.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'LogUnsupported'}
$text=[IO.File]::ReadAllText($session.LogPath);$mappings=@();$duplicates=@{}
foreach($m in @($private.ModuleFiles)){
 if($m.Kind -notin @('MainExecutable','Loader','SystemNtdll')){continue}
 if($duplicates.ContainsKey($m.Kind)){throw 'DuplicateModuleRecord'};$duplicates[$m.Kind]=$true
 $base=Convert-RMRecordedHex $m.BaseAddress
 if($null -eq $base -or !$base -or $m.FileSHA256 -isnot [string] -or $m.FileSHA256 -cnotmatch '^[0-9a-fA-F]{64}$'){continue}
 $record=$safe.($m.Kind)
 if(!$record.Present -or $record.SHA256 -ine $m.FileSHA256){continue}
 try{
  $size=Read-LocalPEImageSize $m.Path
  $hash=(Get-FileHash -LiteralPath $m.Path -Algorithm SHA256).Hash
  if($hash -ine $m.FileSHA256){continue}
  $mappings+=[pscustomobject]@{Kind=$m.Kind;Base=$base;ImageBytes=$size;SHA256=$hash}
 }catch{# Missing/changed file leaves relative points unknown; never copy error paths.
 }
}
$report=Get-RMOfflineRVAReport $text $private $safe ([uint32]$session.TargetId) $mappings
$report|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $OutputPath -Encoding UTF8
