# Execute GUI construction and its actual tick body in a FRESH process, not a caller with parsers preloaded.
$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
$ps=(Get-Process -Id $PID).MainModule.FileName
& $ps -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File (Join-Path $base 'Easy-UI.ps1') -TickSmoke
if($LASTEXITCODE -ne 0){throw 'FreshUITickChildFailed'}
Write-Host 'PASS: fresh standalone UI tick, callback scheduling and timeout on parser failure'
