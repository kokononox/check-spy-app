# Only the kit's own fixture. Validates interrupt/detach path without user binaries or network.
$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Session-UI-Core.ps1')
$cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
if(!(Test-Path -LiteralPath $cdb)){throw 'CDB unavailable for required stop smoke'}
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$dir=Join-Path ([IO.Path]::GetTempPath()) ('rm-stop-fixture-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
$debugger=$null;$helper=$null
try{
 $exe=Join-Path $dir 'OwnSyntheticFixture.exe';$cmd=Join-Path $dir 'commands.txt';$log=Join-Path $dir 'synthetic-only.txt'
 & $csc /nologo /platform:x64 /target:exe ('/out:'+$exe) (Join-Path $PSScriptRoot 'EncryptMessage-ABI-Fixture.cs')
 if($LASTEXITCODE -ne 0){throw 'Fixture build failed'}
 [IO.File]::WriteAllText($cmd,(New-RMCdbCommands),[Text.Encoding]::ASCII)
 # -2 gives the owned debuggee a separate console; stop helper may only touch CDB's own console.
 $args='-2 -G -pd -cf "'+$cmd+'" -logo "'+$log+'" "'+$exe+'" hold'
 $debugger=Start-Process -FilePath $cdb -ArgumentList $args -PassThru -WindowStyle Hidden
 $ready=$false
 for($i=0;$i -lt 30;$i++){
  Start-Sleep -Milliseconds 500
  if(Test-Path -LiteralPath $log){try{$fs=[IO.File]::Open($log,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);$sr=New-Object IO.StreamReader($fs);$text=$sr.ReadToEnd();$sr.Dispose();if($text -match '(?m)^\s*RM_END\s*$'){$ready=$true;break}}catch{}}
 }
 if(!$ready){throw ('Fixture observer did not become ready; CDB exited='+$debugger.HasExited+'; log exists='+(Test-Path -LiteralPath $log)+'; own log markers='+@([regex]::Matches([string]$text,'RM_END')).Count)}
 $owned=@(Get-Process -Name 'OwnSyntheticFixture' -ErrorAction SilentlyContinue|Where-Object {try{$_.MainModule.FileName -eq $exe}catch{$false}})
 if($owned.Count -ne 1){throw 'Own target identity not unique'}
 $session=Join-Path $dir 'PRIVATE-ui-session.json'
 @{TargetId=$owned[0].Id;TargetStart=$owned[0].StartTime.ToUniversalTime().ToString('o');DebuggerId=$debugger.Id;DebuggerStart=$debugger.StartTime.ToUniversalTime().ToString('o');CdbPath=$cdb;CdbSHA256=(Get-FileHash -LiteralPath $cdb -Algorithm SHA256).Hash}|ConvertTo-Json|Set-Content -LiteralPath $session -Encoding UTF8
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $base 'Stop-Debugger.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){throw 'Owned stop helper timed out'}
 $result=Get-Content -LiteralPath (Join-Path $dir 'stop-result.json') -Raw|ConvertFrom-Json
 if(!$result.StopConfirmed -or !$debugger.HasExited -or !$result.TargetAliveAfterDebuggerExit){throw ('Owned stop not confirmed: '+$result.Reason)}
 $alive=@(Get-Process -Name 'OwnSyntheticFixture' -ErrorAction SilentlyContinue|Where-Object {try{$_.MainModule.FileName -eq $exe}catch{$false}})
 if(!$alive.Count){throw 'Own held fixture not alive after detach'}
 Write-Host '::notice title=Owned-console stop PASS::Stop helper interrupted and detached own CDB; own fixture remained alive. No game/network tested.'
}catch{
 Write-Host ('::error title=Own stop smoke failure::'+$_.Exception.Message.Replace('%','%25').Replace("`n",'%0A').Replace("`r",'%0D'))
 throw
}finally{
 # Force cleanup is allowed only here for OWN CI fixture/helpers, never in the user UI.
 if($helper -and !$helper.HasExited){$helper.Kill()}
 if($debugger -and !$debugger.HasExited){$debugger.Kill()}
 Get-Process -Name 'OwnSyntheticFixture' -ErrorAction SilentlyContinue|ForEach-Object {try{if($_.MainModule.FileName -eq $exe){Stop-Process -Id $_.Id -Force}}catch{}}
 Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
}
