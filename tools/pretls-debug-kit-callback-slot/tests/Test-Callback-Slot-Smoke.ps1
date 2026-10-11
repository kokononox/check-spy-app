$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Session-UI-Core.ps1');. (Join-Path $base 'Diagnostic-Core.ps1');. (Join-Path $base 'Callback-Slot-Core.ps1')
$cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs=(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath|Select-Object -First 1)
if(!$vs){throw 'OwnSlotCompilerMissing'}
$dir=Join-Path $env:TEMP ('RM-own-slot-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
$target=$null;$debugger=$null;$helper=$null
try{
 $exe=Join-Path $dir 'OwnSlotTarget.exe';$dll=Join-Path $dir 'Wow_loader.dll';$obj=Join-Path $dir 'OwnSlot.obj';$ready=Join-Path $dir 'OwnConfig.json';$handled=Join-Path $dir 'OWN-handled.txt';$cmd=Join-Path $dir 'commands.txt';$log=Join-Path $dir 'synthetic-only.txt';$builder=Join-Path $dir 'build-own.cmd'
 @('@echo off',('call "'+(Join-Path $vs 'Common7\Tools\VsDevCmd.bat')+'" -arch=amd64 -host_arch=amd64 >nul'),('ml64 /nologo /c /Fo"'+$obj+'" "'+(Join-Path $PSScriptRoot 'Own-Callback-Slot.asm')+'"'),'if errorlevel 1 exit /b 1',('link /nologo /DLL /NOENTRY /NODEFAULTLIB /MACHINE:X64 /OUT:"'+$dll+'" /IMPLIB:"'+(Join-Path $dir 'ownslot.lib')+'" /DEF:"'+(Join-Path $PSScriptRoot 'Own-Callback-Slot.def')+'" "'+$obj+'"'),'if errorlevel 1 exit /b 1',('cl /nologo /W3 /Od /Fe:"'+$exe+'" /Fo:"'+(Join-Path $dir 'owntarget.obj')+'" "'+(Join-Path $PSScriptRoot 'Own-Callback-Target.c')+'" /link /MACHINE:X64'))|Set-Content $builder -Encoding ASCII
 & $env:ComSpec /d /c ('"'+$builder+'"');if($LASTEXITCODE -ne 0){throw 'OwnSlotCompileFailed'}
 [IO.File]::WriteAllText($cmd,(New-RMCdbCommands),[Text.Encoding]::ASCII)
 # Fixture only: skip standard process launch break so first observer stop is our custom handled CC.
 $debugger=Start-Process -FilePath $cdb -ArgumentList ('-2 -pd -g -cf "'+$cmd+'" -logo "'+$log+'" "'+$exe+'" "'+$dll+'" "'+$ready+'" "'+$handled+'"') -PassThru -WindowStyle Hidden
 for($i=0;$i -lt 50;$i++){Start-Sleep -Milliseconds 200;$target=Get-Process -Name 'OwnSlotTarget' -ErrorAction SilentlyContinue|Where-Object {$_.MainModule.FileName -eq $exe}|Select-Object -First 1;if($target -and (Test-Path $ready)){break}}
 if(!$target -or !(Test-Path $ready)){throw 'OwnSlotTargetNotReady'}
 for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 500;$d=Get-RMDiagnostics (Read-RMLiveLog $log);if($d.InitialWaiting -and $d.InitialGate -eq 'InitialBreakLocationUnverified'){break}}
 if(!$d.InitialWaiting -or $d.InitialGate -ne 'InitialBreakLocationUnverified'){throw 'OwnSlotInitialGateUnexpected'}
 $session=Join-Path $dir 'PRIVATE-ui-session.json';@{TargetId=$target.Id;TargetStart=$target.StartTime.ToUniversalTime().ToString('o');TargetSHA256=(Get-FileHash $exe -Algorithm SHA256).Hash;DebuggerId=$debugger.Id;DebuggerStart=$debugger.StartTime.ToUniversalTime().ToString('o');CdbPath=$cdb;CdbSHA256=(Get-FileHash $cdb -Algorithm SHA256).Hash;LogPath=$log}|ConvertTo-Json|Set-Content $session -Encoding UTF8
 $ownkit=Join-Path $dir 'own-kit';[void][IO.Directory]::CreateDirectory($ownkit)
 foreach($name in @('Callback-Slot.ps1','Callback-Slot-Core.ps1','Startup-Metadata.ps1','Startup-Metadata-Core.ps1','Session-UI-Core.ps1','Diagnostic-Core.ps1','Debugger-Core.ps1')){Copy-Item (Join-Path $base $name) (Join-Path $ownkit $name)}
 $config=Get-Content $ready -Raw|ConvertFrom-Json;$expected='0x'+([uint64]$config.ExpectedCandidateRVA).ToString('x')
 @{LoaderSHA256=(Get-FileHash $dll -Algorithm SHA256).Hash;ExceptionRVA=$config.ExceptionRVA;CallerReturnRVA=$config.CallerReturnRVA;SlotOffset=48}|ConvertTo-Json|Set-Content (Join-Path $ownkit 'CallbackTarget-local.json') -Encoding UTF8
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $ownkit 'Startup-Metadata.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(35000)){throw 'OwnMetadataTimedOut'}
 for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 500;$text=Read-RMLiveLog $log;$frame=Get-RMRecordedCallbackFrame $text;if($frame){break}}
 if(!$frame){throw 'OwnSlotContextMissing'}
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $ownkit 'Callback-Slot.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){throw 'OwnSlotHelperTimedOut'}
 $receipt=Get-Content (Join-Path $dir 'callback-slot-result.json') -Raw|ConvertFrom-Json
 if(!$receipt.CommandsQueued){throw ('OwnSlotReadRefused: '+$receipt.FailureStage)}
 for($i=0;$i -lt 40;$i++){Start-Sleep -Milliseconds 500;$text=Read-RMLiveLog $log;$r=Get-RMSafeCallbackSlot $dir $text;if($r.DoneMarkerObserved){break}}
 if($r.ReadState -ne 'OneSlotReadNotActualCallProof' -or $r.CandidatePoint.ModuleKind -ne 'Loader' -or $r.CandidatePoint.RVA -ne $expected){
  # Diagnostics from OWN fixture only; never added to production export.
  $tail=@($text -split '\r?\n'|Select-Object -Last 35) -join ' | '
  Write-Host ('::error title=Own synthetic slot log::'+$tail.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A'))
  throw ('OwnSlotCandidateFailed: state='+$r.ReadState)
 }
 $d=Get-RMDiagnostics $text;if($d.InitialContinueAllowed -or !$d.InitialWaiting -or $d.UserInitialContinueMarker -or $d.PromptContinueCommands -gt 0 -or (Test-Path $handled)){throw 'OwnSlotUnexpectedContinuation'}
 & (Join-Path $base 'Read-Private-Log.ps1') -LogPath $log
 $report=Get-Content (Join-Path $dir 'local-results\Report-to-share.json') -Raw|ConvertFrom-Json;$json=$report|ConvertTo-Json -Depth 10
 if($report.CallbackSlot.CandidatePoint.RVA -ne $expected -or $json -match 'C:\\|SlotAddress|CallerStackPointer|TopReturnAddress|PRIVATE-|Ranges|ExceptionAddress'){throw 'OwnSlotSafeExportFailed'}
 # Wrong configuration must refuse BEFORE queue, even with a valid paused own fixture.
 Remove-Item (Join-Path $dir 'callback-slot.lock');@{LoaderSHA256=('0'*64);ExceptionRVA=$config.ExceptionRVA;CallerReturnRVA=$config.CallerReturnRVA;SlotOffset=48}|ConvertTo-Json|Set-Content (Join-Path $ownkit 'CallbackTarget-local.json') -Encoding UTF8
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $ownkit 'Callback-Slot.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(20000)){throw 'OwnWrongHashHelperTimedOut'}
 $bad=Get-Content (Join-Path $dir 'callback-slot-result.json') -Raw|ConvertFrom-Json;if($bad.CommandsQueued -or $bad.FailureStage -ne 'ModuleIdentity'){throw 'OwnWrongHashNotRefused'}
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $base 'Stop-Debugger.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){throw 'OwnSlotStopTimedOut'}
 $end=Get-Content (Join-Path $dir 'stop-result.json') -Raw|ConvertFrom-Json
 if(!$end.StopConfirmed -or !$end.TargetAliveAfterDebuggerExit -or $target.HasExited){throw 'OwnSlotTargetSurvivalFailed'}
 Write-Host '::notice title=Own guarded callback slot PASS::Custom owned asm breakpoint; exact caller return/RSP/TID guards; one stack qword maps to expected own callback RVA; debugger-local context restored; safe export; wrong loader hash refused; no initial continue/handled marker before stop; own target survived debugger end. No game/network.'
}catch{Write-Host ('::error title=Own callback slot test::'+$_.Exception.Message.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A'));throw}finally{
 foreach($p in @($helper,$debugger,$target)){if($p -and !$p.HasExited){$p.Kill()}}
 Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue
}
