#requires -Version 5.1
param([switch]$RequireCdb)
$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Debugger-Core.ps1')
$cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
if(!(Test-Path -LiteralPath $cdb)){
 if($RequireCdb){throw 'CDB x64 not installed'}
 Write-Host '::notice title=CDB smoke NOT RUN::Microsoft CDB x64 is not installed. Core tests do not validate live breakpoint commands.'
 return
}
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(!(Test-Path -LiteralPath $csc)){throw 'Fixture compiler absent'}
$dir=Join-Path ([IO.Path]::GetTempPath()) ('rm-ABI-fixture-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
try{
 $exe=Join-Path $dir 'OwnSyntheticFixture.exe';$cmd=Join-Path $dir 'commands.txt';$log=Join-Path $dir 'synthetic-only.txt'
 & $csc /nologo /platform:x64 /target:exe ('/out:'+$exe) (Join-Path $PSScriptRoot 'EncryptMessage-ABI-Fixture.cs')
 if($LASTEXITCODE -ne 0){throw 'Fixture build failed'}
 [IO.File]::WriteAllText($cmd,(New-RMCdbCommands),[Text.Encoding]::ASCII)
 $arguments='-G -pd -cf "'+$cmd+'" -logo "'+$log+'" "'+$exe+'"'
 $p=Start-Process -FilePath $cdb -ArgumentList $arguments -PassThru -WindowStyle Hidden
 if(!$p.WaitForExit(60000)){
  $p.Kill();throw 'Own-fixture CDB smoke timed out. No real target was used.'
 }
 if(!(Test-Path -LiteralPath $log)){throw 'No synthetic debugger log'}
 $text=[IO.File]::ReadAllText($log)
 $parsed=Read-RMCdbData $text;$http=Get-RMHttpCandidates $parsed.Records
 if($parsed.ParseErrors -or $http.Candidates.Count -ne 1 -or $http.Candidates[0].URL -ne 'https://fixture.invalid/private?token=DUMMY'){throw 'Live CDB command/ABI fixture failed; no payload log printed'}
 Write-Host 'PASS: CDB breakpoint command and x64 SecBuffer dump on own INVALID-context fixture. No Schannel/TLS/send/game test.'
}finally{if(Test-Path -LiteralPath $dir){Remove-Item -LiteralPath $dir -Recurse -Force}}
