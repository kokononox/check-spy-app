#requires -Version 5.1
param([Parameter(Mandatory=$true)][int]$TargetProcessId,[Parameter(Mandatory=$true)][string]$TargetExe,[Parameter(Mandatory=$true)][string]$CdbPath,[ValidateSet('sspicli!EncryptMessage','secur32!EncryptMessage')][string]$Symbol='sspicli!EncryptMessage')
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Debugger-Core.ps1')
if($env:OS -ne 'Windows_NT' -or ![Environment]::Is64BitProcess){throw 'Use x64 Windows PowerShell on an isolated Windows test machine'}
if((Read-Host 'Isolated test machine, own authorized program, no real account/anti-cheat session? Type ISOLATED') -cne 'ISOLATED'){throw 'Not confirmed; nothing attached'}
if((Read-Host 'Capture can contain passwords/tokens/bodies. Keep all raw files private. Type PRIVATE') -cne 'PRIVATE'){throw 'Private capture consent missing; nothing attached'}
function Assert-X64File([string]$Path){
 $s=[IO.File]::OpenRead($Path)
 try{$r=New-Object IO.BinaryReader($s);if($r.ReadUInt16() -ne 0x5a4d){throw 'Not PE'};$s.Position=0x3c;$off=$r.ReadUInt32();$s.Position=$off;if($r.ReadUInt32() -ne 0x4550 -or $r.ReadUInt16() -ne 0x8664){throw 'Not x64 PE'}}finally{$s.Dispose()}
}
$exe=(Resolve-Path -LiteralPath $TargetExe).Path;$cdb=(Resolve-Path -LiteralPath $CdbPath).Path
Assert-X64File $exe;Assert-X64File $cdb
if([IO.Path]::GetFileName($cdb) -ine 'cdb.exe'){throw 'Select Microsoft CDB x64'}
$sig=Get-AuthenticodeSignature -FilePath $cdb
if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'CDB Microsoft signature not verified; stop'}
$process=Get-Process -Id $TargetProcessId -ErrorAction Stop
if(![string]::Equals([IO.Path]::GetFullPath($process.MainModule.FileName),$exe,[StringComparison]::OrdinalIgnoreCase)){throw 'PID does not match selected EXE'}
$start=$process.StartTime.ToUniversalTime();$hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
$root=Join-Path $env:LOCALAPPDATA ('ExeRouteMonitor\PreTLS-PRIVATE\'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($root)
$cmd=Join-Path $root 'observer-commands.txt';$log=Join-Path $root 'PRIVATE-cdb.txt'
[IO.File]::WriteAllText($cmd,(New-RMCdbCommands $Symbol),[Text.Encoding]::ASCII)
# No attach yet: the operator starts the debugger separately after final review.
$launch=Join-Path $root 'Attach-CDB.cmd'
$line='"'+$cdb+'" -pd -p '+$TargetProcessId+' -cf "'+$cmd+'" -logo "'+$log+'"'
# Reject cmd metacharacters/expansions rather than generating an unsafe command file.
if(($cdb+$cmd+$log) -match '[%&|<>^!\r\n]'){throw 'Path cannot safely be used in command launcher'}
# Launch file is ASCII-compatible for cmd.exe; refuse non-ASCII paths instead of mojibake.
if(($cdb+$cmd+$log) -match '[^\x20-\x7e]'){throw 'Use ASCII-only CDB/profile paths for this experimental command launcher'}
$now=Get-Process -Id $TargetProcessId
if($now.StartTime.ToUniversalTime() -ne $start){throw 'Process generation changed; stop'}
@{TargetSHA256=$hash;TargetPID=$TargetProcessId;CreatedUTC=$start.ToString('o');Symbol=$Symbol;AttachPerformed=$false;Warning='Review PID again immediately before starting. No automatic launch or anti-cheat bypass.'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'PRIVATE-session.json') -Encoding UTF8
# Wrapper revalidates process generation in PowerShell before attach; no stale PID-only shortcut.
$gate=Join-Path $root 'Attach-Gate.ps1'
$gateText=@'
$ErrorActionPreference='Stop'
$d=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'PRIVATE-session.json') -Raw|ConvertFrom-Json
$p=Get-Process -Id $d.TargetPID
if($p.StartTime.ToUniversalTime().ToString('o') -ne $d.CreatedUTC){throw 'Stale process generation; stop'}
if((Get-FileHash -LiteralPath $p.MainModule.FileName -Algorithm SHA256).Hash -ne $d.TargetSHA256){throw 'Target EXE changed; stop'}
if((Read-Host 'Final isolated-environment and private-capture confirmation: type ATTACH') -cne 'ATTACH'){return}
$ErrorActionPreference='Continue'
& '__CDB__' -pd -p $d.TargetPID -cf (Join-Path $PSScriptRoot 'observer-commands.txt') -logo (Join-Path $PSScriptRoot 'PRIVATE-cdb.txt')
'@
$gateText=$gateText.Replace('__CDB__',$cdb.Replace("'","''"));[IO.File]::WriteAllText($gate,$gateText,[Text.Encoding]::ASCII)
[IO.File]::WriteAllText($launch,"@echo off`r`ncd /d `"%~dp0`"`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File `"%~dp0Attach-Gate.ps1`"`r`npause`r`n",[Text.Encoding]::ASCII)
Write-Host 'PREPARED ONLY. No debugger attached. Read guide before running Attach-CDB.cmd.'
Write-Host ('Private session directory: '+$root)
