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
 if($parsed.ParseErrors -or $http.Candidates.Count -ne 1 -or $http.Candidates[0].URL -ne 'https://fixture.invalid/private?token=DUMMY'){throw ('Live CDB ABI fixture failed: parsed buffers='+$parsed.Records.Count+'; parse errors='+$parsed.ParseErrors+'; HTTP candidates='+$http.Candidates.Count+'; URL assertion='+[bool]($http.Candidates.Count -eq 1 -and $http.Candidates[0].URL -eq 'https://fixture.invalid/private?token=DUMMY'))}
 Write-Host 'PASS: CDB breakpoint command and x64 SecBuffer dump on own INVALID-context fixture. No Schannel/TLS/send/game test.'
 }catch{
 $message=$_.Exception.Message.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A')
 Write-Host ('::error title=Own CDB fixture failure::'+$message)
 if($log -and (Test-Path -LiteralPath $log)){
  # Only the kit's own DUMMY fixture; never runs on or prints user data.
  $lines=@(Get-Content -LiteralPath $log | Where-Object {$_ -match 'Syntax|error|Error|resolve|RM_|FIXTURE|Unable|Invalid|breakpoint|^\s*[0-9a-fA-F`]{8,17}\s{2}'} | Select-Object -Last 18)
  $detail=($lines -join ' ').Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A')
  if($detail.Length -gt 3500){$detail=$detail.Substring($detail.Length-3500)}
  Write-Host ('::error title=Own synthetic CDB diagnostics::'+$detail)
 }
 throw
}finally{
 if($exe){
  Get-Process -Name 'OwnSyntheticFixture' -ErrorAction SilentlyContinue | ForEach-Object {
   try{if($_.MainModule.FileName -eq $exe){Stop-Process -Id $_.Id -Force}}catch{}
  }
 }
 if(Test-Path -LiteralPath $dir){Remove-Item -LiteralPath $dir -Recurse -Force}
}
