# Actual attach only to OUR running, file-rendezvous fixture. No game or network.
$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Session-UI-Core.ps1')
. (Join-Path $base 'Diagnostic-Core.ps1')
. (Join-Path $PSScriptRoot 'Own-Fixture-Session.ps1')
$cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$dir=Join-Path $env:TEMP ('RM-owned-attach-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
$target=$null;$debugger=$null;$helper=$null
try{
 $exe=Join-Path $dir 'OwnSyntheticFixture.exe';$signal=Join-Path $dir 'OWN-only-go.txt';$cmd=Join-Path $dir 'commands.txt';$log=Join-Path $dir 'synthetic-only.txt'
 & $csc /nologo /platform:x64 /target:exe ('/out:'+$exe) (Join-Path $PSScriptRoot 'EncryptMessage-ABI-Fixture.cs')
 if($LASTEXITCODE -ne 0){throw 'Own attach fixture compile failed'}
 [IO.File]::WriteAllText($cmd,(New-RMCdbCommands),[Text.Encoding]::ASCII)
 $target=Start-Process -FilePath $exe -ArgumentList ('attach-hold "'+$signal+'"') -PassThru -WindowStyle Hidden
 Start-Sleep -Milliseconds 500
 $debugger=Start-Process -FilePath $cdb -ArgumentList ('-pd -p '+$target.Id+' -cf "'+$cmd+'" -logo "'+$log+'"') -PassThru -WindowStyle Hidden
 Start-OwnInitialContinuation $debugger $dir $log $exe $cdb $base
 [IO.File]::WriteAllText($signal,'OWN fixture only')
 $captured=$false
 for($i=0;$i -lt 60;$i++){Start-Sleep -Milliseconds 500;$text=Read-RMLiveLog $log;if($text -match '(?m)^\s*RM_END\s*$'){$captured=$true;break}}
 if(!$captured){throw 'Own attached fixture did not capture'}
 $diag=Get-RMDiagnostics $text
 if(!$diag.UserInitialContinueMarker -or $diag.APIEntryMarkers -ne 1){throw 'Own attach user continuation/API entry evidence absent'}
 $http=Get-RMHttpCandidates (Read-RMCdbData $text).Records
 if($http.Candidates.Count -ne 1){throw 'Own attached invalid-context candidate missing'}
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $session=Join-Path $dir 'PRIVATE-ui-session.json'
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $base 'Stop-Debugger.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){throw 'Own attach stop timed out'}
 $result=Get-Content (Join-Path $dir 'stop-result.json') -Raw|ConvertFrom-Json
 if(!$result.StopConfirmed -or !$result.TargetAliveAfterDebuggerExit -or !$debugger.HasExited -or $target.HasExited){throw 'Own attached target survival/stop evidence failed'}
 Write-Host '::notice title=Owned running-fixture attach PASS::No startup auto-go; expected initial break required; explicit test request continued; invalid-context dump captured; detach request ended debugger; own target survived. No game/network.'
}catch{
 $message=$_.Exception.Message.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A');Write-Host ('::error title=Own attach gate test::'+$message);throw
}finally{
 # OWN CI process cleanup only; no user binaries are accepted by this test.
 foreach($p in @($helper,$debugger,$target)){if($p -and !$p.HasExited){$p.Kill()}}
 Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
