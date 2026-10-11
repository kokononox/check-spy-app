$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Session-UI-Core.ps1');. (Join-Path $base 'Diagnostic-Core.ps1');. (Join-Path $base 'Startup-Metadata-Core.ps1')
$cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs=(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath|Select-Object -First 1)
if(!$vs){throw 'Own metadata test compiler missing'}
$dir=Join-Path $env:TEMP ('RM-own-metadata-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
$target=$null;$debugger=$null;$helper=$null
try{
 $exe=Join-Path $dir 'OwnMetadataTarget.exe';$dll=Join-Path $dir 'Wow_loader.dll';$ready=Join-Path $dir 'OWN-ready.txt';$cmd=Join-Path $dir 'commands.txt';$log=Join-Path $dir 'synthetic-only.txt';$builder=Join-Path $dir 'build-own.cmd'
 @('@echo off',('call "'+(Join-Path $vs 'Common7\Tools\VsDevCmd.bat')+'" -arch=amd64 -host_arch=amd64 >nul'),('cl /nologo /W3 /Od /LD /Fe:"'+$dll+'" /Fo:"'+(Join-Path $dir 'ownloader.obj')+'" "'+(Join-Path $PSScriptRoot 'Own-Metadata-Loader.c')+'" /link /MACHINE:X64 /IMPLIB:"'+(Join-Path $dir 'ownloader.lib')+'"'),'if errorlevel 1 exit /b 1',('cl /nologo /W3 /Od /Fe:"'+$exe+'" /Fo:"'+(Join-Path $dir 'owntarget.obj')+'" "'+(Join-Path $PSScriptRoot 'Own-Metadata-Target.c')+'" /link /MACHINE:X64'))|Set-Content $builder -Encoding ASCII
 & $env:ComSpec /d /c ('"'+$builder+'"');if($LASTEXITCODE -ne 0){throw 'Own metadata fixtures compile failed'}
 $target=Start-Process -FilePath $exe -ArgumentList ('"'+$dll+'" "'+$ready+'"') -PassThru -WindowStyle Hidden
 for($i=0;$i -lt 30 -and !(Test-Path $ready);$i++){Start-Sleep -Milliseconds 200}
 if(!(Test-Path $ready)){throw 'Own DLL loading not confirmed'}
 [IO.File]::WriteAllText($cmd,(New-RMCdbCommands),[Text.Encoding]::ASCII)
 $debugger=Start-Process -FilePath $cdb -ArgumentList ('-pd -p '+$target.Id+' -cf "'+$cmd+'" -logo "'+$log+'"') -PassThru -WindowStyle Hidden
 $waiting=$false
 for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 500;$d=Get-RMDiagnostics (Read-RMLiveLog $log);if($d.InitialWaiting -and $d.InitialContinueAllowed){$waiting=$true;break}}
 if(!$waiting){throw 'Own initial event not ready for metadata'}
 $session=Join-Path $dir 'PRIVATE-ui-session.json'
 @{TargetId=$target.Id;TargetStart=$target.StartTime.ToUniversalTime().ToString('o');TargetSHA256=(Get-FileHash $exe -Algorithm SHA256).Hash;DebuggerId=$debugger.Id;DebuggerStart=$debugger.StartTime.ToUniversalTime().ToString('o');CdbPath=$cdb;CdbSHA256=(Get-FileHash $cdb -Algorithm SHA256).Hash;LogPath=$log}|ConvertTo-Json|Set-Content $session -Encoding UTF8
 $ownHelper=Join-Path $dir 'own-kit';[void][IO.Directory]::CreateDirectory($ownHelper)
 foreach($name in @('Startup-Metadata.ps1','Startup-Metadata-Core.ps1','Session-UI-Core.ps1','Diagnostic-Core.ps1','Debugger-Core.ps1')){Copy-Item (Join-Path $base $name) (Join-Path $ownHelper $name)}
 @{LoaderSHA256=(Get-FileHash $dll -Algorithm SHA256).Hash;MainSHA256=(Get-FileHash $exe -Algorithm SHA256).Hash}|ConvertTo-Json|Set-Content (Join-Path $ownHelper 'OfflineBaseline-safe.json') -Encoding UTF8
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $ownHelper 'Startup-Metadata.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(35000)){throw 'Own metadata helper timed out'}
 $safe=Get-RMSafeStartupMetadata $dir
 if($safe.Collection -ne 'Collected' -or !$safe.ContextCommandsQueued){throw ('Own metadata helper not confirmed: stage='+$safe.FailureStage)}
 if(!$safe.Loader.Present -or !$safe.Loader.MatchesSuppliedBaseline -or !$safe.MainExecutable.MatchesSuppliedBaseline){throw 'Own module file hash/baseline comparison failed'}
 if($safe.EventThreadQuery -ne 'Success' -or $safe.EventThreadStartClass -ne 'NtdllRemoteBreakinAddressMatchNotOriginProof'){throw ('Own event thread metadata failed: query='+$safe.EventThreadQuery+'; class='+$safe.EventThreadStartClass+'; system file match='+$safe.SystemNtdllFileMatchToHelper+'; signature='+$safe.SystemNtdllSignatureVerified)}
 $ctx=$null
 for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 500;$text=Read-RMLiveLog $log;$ctx=Get-RMContextIndicators $text;if($ctx.Complete){break}}
 if(!$ctx.Complete -or !$ctx.CurrentContextMatchesLastEventThread -or $ctx.StackFrameRowsObserved -lt 1){throw ('Own stack context incomplete: complete='+$ctx.Complete+'; thread match='+$ctx.CurrentContextMatchesLastEventThread+'; frames='+$ctx.StackFrameRowsObserved)}
 $d=Get-RMDiagnostics $text
 if(!$d.InitialWaiting -or $d.UserInitialContinueMarker -or $d.PromptContinueCommands -gt 0 -or $safe.ContinuationAuthorized){throw 'Metadata collection changed continuation/gate policy'}
 & (Join-Path $base 'Read-Private-Log.ps1') -LogPath $log
 $report=Get-Content (Join-Path $dir 'local-results\Report-to-share.json') -Raw|ConvertFrom-Json
 if(!$report.StartupMetadata.Loader.MatchesSuppliedBaseline -or !$report.StartupContext.Complete){throw 'Safe report missing startup evidence'}
 $json=$report|ConvertTo-Json -Depth 10
 if($json -match 'C:\\|ThreadStartAddress|ModuleFiles|ThreadCreationUTC|CurrentPid|CurrentTid'){throw 'Private metadata leaked into safe report'}
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $base 'Stop-Debugger.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){throw 'Own metadata stop helper timed out'}
 $end=Get-Content (Join-Path $dir 'stop-result.json') -Raw|ConvertFrom-Json
 if(!$end.StopConfirmed -or !$end.TargetAliveAfterDebuggerExit -or $target.HasExited){throw 'Own metadata fixture did not survive stop'}
 Write-Host '::notice title=Own read-only startup metadata PASS::Loaded own harmless DLL; disk hashes matched own baseline; event thread start matched verified ntdll remote-breakin export; bounded current-thread stack captured; no initial continue; own target survived debugger end. No game/network.'
}catch{
 Write-Host ('::error title=Own startup metadata test::'+$_.Exception.Message.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A'));throw
}finally{
 foreach($p in @($helper,$debugger,$target)){if($p -and !$p.HasExited){$p.Kill()}}
 Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
