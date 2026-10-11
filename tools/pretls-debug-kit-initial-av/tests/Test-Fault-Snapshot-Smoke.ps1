$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Session-UI-Core.ps1');. (Join-Path $base 'Diagnostic-Core.ps1')
. (Join-Path $PSScriptRoot 'Own-Fixture-Session.ps1')
$cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs=(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath|Select-Object -First 1)
if(!$vs){throw 'Own native fixture compiler unavailable'}
$dir=Join-Path $env:TEMP ('RM-native-fault-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
$target=$null;$debugger=$null;$helper=$null
try{
 $exe=Join-Path $dir 'OwnSyntheticFixture.exe';$signal=Join-Path $dir 'OWN-fault-signal.txt';$cmd=Join-Path $dir 'commands.txt';$log=Join-Path $dir 'synthetic-only.txt'
 $builder=Join-Path $dir 'build-own.cmd'
 $source=Join-Path $PSScriptRoot 'Own-Native-Fault-Fixture.c'
 @('@echo off',('call "'+(Join-Path $vs 'Common7\Tools\VsDevCmd.bat')+'" -arch=amd64 -host_arch=amd64 >nul'),('cl /nologo /W3 /Od /Fe:"'+$exe+'" /Fo:"'+(Join-Path $dir 'own.obj')+'" "'+$source+'" /link /MACHINE:X64'))|Set-Content -LiteralPath $builder -Encoding ASCII
 & $env:ComSpec /d /c ('"'+$builder+'"')
 if($LASTEXITCODE -ne 0 -or !(Test-Path $exe)){throw 'Own native fixture compile failed'}
 [IO.File]::WriteAllText($cmd,(New-RMCdbCommands),[Text.Encoding]::ASCII)
 $target=Start-Process -FilePath $exe -ArgumentList ('"'+$signal+'"') -PassThru -WindowStyle Hidden
 Start-Sleep -Milliseconds 500
 $debugger=Start-Process -FilePath $cdb -ArgumentList ('-pd -p '+$target.Id+' -cf "'+$cmd+'" -logo "'+$log+'"') -PassThru -WindowStyle Hidden
 Start-OwnInitialContinuation $debugger $dir $log $exe $cdb $base
 [IO.File]::WriteAllText($signal,'OWN synthetic exception only')
 $fault=$false
 for($i=0;$i -lt 60;$i++){Start-Sleep -Milliseconds 500;$d=Get-RMDiagnostics (Read-RMLiveLog $log);if($d.LastExceptionClass -eq 'AccessViolation' -and $d.LastExceptionChance -eq 'first' -and $d.ExceptionPausePossible){$fault=$true;break}}
 if(!$fault){throw 'Own synthetic first-chance AV not observed'}
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe';$session=Join-Path $dir 'PRIVATE-ui-session.json'
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $base 'Fault-Snapshot.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){throw 'Own read-only fault helper timed out'}
 $result=Get-Content (Join-Path $dir 'fault-snapshot-result.json') -Raw|ConvertFrom-Json
 if(!$result.SnapshotCommandsQueued){throw ('Own fault snapshot refused: '+$result.FailureStage)}
 $record=$false
 for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 500;$d=Get-RMDiagnostics (Read-RMLiveLog $log);if($d.FaultRecordComplete){$record=$true;break}}
 if(!$record -or $d.FaultRecordExceptionClass -ne 'AccessViolation' -or $d.FaultAccessKind -ne 'Execute' -or $d.ContinuationAfterFaultObserved -or !$d.ExceptionPausePossible){throw ('Own fault metadata assertion failed: complete='+$d.FaultRecordComplete+'; class='+$d.FaultRecordExceptionClass+'; operation='+$d.FaultAccessKind)}
 if(Test-Path ($signal+'.handled')){throw 'Own exception unexpectedly resumed before stop'}
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $base 'Stop-Debugger.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){throw 'Own fault stop helper timed out'}
 $end=Get-Content (Join-Path $dir 'stop-result.json') -Raw|ConvertFrom-Json
 if(!$end.StopConfirmed -or !$end.TargetAliveAfterDebuggerExit -or $target.HasExited){throw 'Own native target did not survive stop'}
 Write-Host '::notice title=Read-only own fault snapshot PASS::Observed synthetic first-chance AV, read .exr without g/gn/interrupt, classified Execute, no exception continuation before stop; debugger ended and own native target survived. No game/network.'
}catch{
 $message=$_.Exception.Message.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A');Write-Host ('::error title=Own fault snapshot test::'+$message);throw
}finally{
 # OWN CI cleanup only, never a user program.
 foreach($p in @($helper,$debugger,$target)){if($p -and !$p.HasExited){$p.Kill()}}
 Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
