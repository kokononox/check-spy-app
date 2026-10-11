# Reusable validation and setup. No attach unless UI explicitly starts CDB.
. (Join-Path $PSScriptRoot 'Debugger-Core.ps1')
function Assert-RMX64PE([string]$Path){
 $s=[IO.File]::OpenRead($Path)
 try{$r=New-Object IO.BinaryReader($s);if($r.ReadUInt16() -ne 0x5a4d){throw 'Not PE'};$s.Position=0x3c;$off=$r.ReadUInt32();$s.Position=$off;if($r.ReadUInt32() -ne 0x4550 -or $r.ReadUInt16() -ne 0x8664){throw 'Not x64 PE'}}finally{$s.Dispose()}
}
function Test-RMStopConsoleScope([int[]]$ConsoleIds,[int]$DebuggerId,[int]$HelperId){
 $ids=@($ConsoleIds|Sort-Object -Unique)
 return ($DebuggerId -gt 0 -and $HelperId -gt 0 -and $DebuggerId -ne $HelperId -and $ids.Count -eq 2 -and $ids -contains $DebuggerId -and $ids -contains $HelperId)
}
function New-RMPrivateUiSession([string]$TargetExe,[int]$TargetId,[datetime]$ExpectedStart,[string]$CdbPath,[bool]$Isolated,[bool]$PrivateConsent){
 if(!$Isolated -or !$PrivateConsent){throw 'Both safety attestations required'}
 if($env:OS -ne 'Windows_NT' -or ![Environment]::Is64BitProcess){throw 'x64 Windows required'}
 $exe=(Resolve-Path -LiteralPath $TargetExe).Path;$cdb=(Resolve-Path -LiteralPath $CdbPath).Path
 Assert-RMX64PE $exe;Assert-RMX64PE $cdb
 if([IO.Path]::GetFileName($cdb) -ine 'cdb.exe'){throw 'CDB filename not verified'}
 $sig=Get-AuthenticodeSignature -FilePath $cdb
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Microsoft'){throw 'Microsoft CDB signature not verified'}
 $p=Get-Process -Id $TargetId
 if($p.StartTime.ToUniversalTime() -ne $ExpectedStart.ToUniversalTime() -or ![string]::Equals([IO.Path]::GetFullPath($p.MainModule.FileName),$exe,[StringComparison]::OrdinalIgnoreCase)){throw 'Target process generation/path changed'}
 $hash=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
 $root=Join-Path $env:LOCALAPPDATA ('ExeRouteMonitor\PreTLS-PRIVATE\'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($root)
 $cmd=Join-Path $root 'observer-commands.txt';$log=Join-Path $root 'PRIVATE-cdb.txt'
 [IO.File]::WriteAllText($cmd,(New-RMCdbCommands),[Text.Encoding]::ASCII)
 $again=Get-Process -Id $TargetId
 if($again.StartTime.ToUniversalTime() -ne $ExpectedStart.ToUniversalTime() -or (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $hash){throw 'Target changed during preparation'}
 $meta=[pscustomobject]@{TargetId=$TargetId;TargetStart=$ExpectedStart.ToUniversalTime().ToString('o');TargetSHA256=$hash;CdbPath=$cdb;CdbSHA256=(Get-FileHash -LiteralPath $cdb -Algorithm SHA256).Hash;DebuggerId=0;DebuggerStart='';Root=$root;LogPath=$log;CommandPath=$cmd}
 $meta|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $root 'PRIVATE-ui-session.json') -Encoding UTF8
 return $meta
}
