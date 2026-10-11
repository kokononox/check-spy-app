# Test-only helper: our fixture and our scripts, no user process allowed.
function Start-OwnInitialContinuation($Debugger,[string]$Directory,[string]$Log,[string]$Exe,[string]$Cdb,[string]$Base){
 . (Join-Path $Base 'Diagnostic-Core.ps1')
 $ready=$false;$diagnostic=$null
 for($i=0;$i -lt 40;$i++){
  Start-Sleep -Milliseconds 500
  if($Debugger.HasExited){throw 'Own CDB exited before initial snapshot'}
  try{$diagnostic=Get-RMDiagnostics (Read-RMLiveLog $Log);if($diagnostic.InitialContinueAllowed){$ready=$true;break}}catch{}
 }
 if(!$ready){throw ('Own initial snapshot not accepted: gate='+$diagnostic.InitialGate+'; last class='+$diagnostic.LastExceptionClass+'; initial breaks='+$diagnostic.BreakInstructionsBeforeInitialization+'; later breaks='+$diagnostic.BreakInstructionsAfterInitialization)}
 $owned=@(Get-Process -Name 'OwnSyntheticFixture' -ErrorAction SilentlyContinue|Where-Object {try{$_.MainModule.FileName -eq $Exe}catch{$false}})
 if($owned.Count -ne 1){throw 'Own fixture generation not unique'}
 $session=Join-Path $Directory 'PRIVATE-ui-session.json'
 @{TargetId=$owned[0].Id;TargetStart=$owned[0].StartTime.ToUniversalTime().ToString('o');DebuggerId=$Debugger.Id;DebuggerStart=$Debugger.StartTime.ToUniversalTime().ToString('o');CdbPath=$Cdb;CdbSHA256=(Get-FileHash -LiteralPath $Cdb -Algorithm SHA256).Hash;LogPath=$Log}|ConvertTo-Json|Set-Content -LiteralPath $session -Encoding UTF8
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $helper=Start-Process -FilePath $ps -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $Base 'Continue-Initial.ps1')+'" -SessionPath "'+$session+'"') -PassThru -WindowStyle Hidden
 if(!$helper.WaitForExit(25000)){ $helper.Kill();throw 'OWN continuation helper timed out' }
 $result=Get-Content -LiteralPath (Join-Path $Directory 'continue-result.json') -Raw|ConvertFrom-Json
 if(!$result.ContinueCommandQueued -or !$result.InitialSnapshotAccepted){throw ('Own initial continue not confirmed: stage='+$result.FailureStage)}
 Write-Host 'Own initial break: no automatic g; explicit test request accepted and queued.'
}
