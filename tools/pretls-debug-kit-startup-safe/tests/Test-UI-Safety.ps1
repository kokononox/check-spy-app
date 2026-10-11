$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Session-UI-Core.ps1')
function Check($ok,$why){if(!$ok){throw $why}}
Check (Test-RMStopConsoleScope @(100,200) 100 200) 'Own debugger/helper pair'
Check (!(Test-RMStopConsoleScope @(100,200,300) 100 200)) 'Refuse unrelated console process'
Check (!(Test-RMStopConsoleScope @(100) 100 200)) 'Refuse missing helper'
Check (!(Test-RMStopConsoleScope @(100,200) 200 200)) 'Refuse debugger/helper PID collision'
Check (!(Test-RMStopConsoleScope @(0,200) 0 200)) 'Refuse invalid PID'
$blocked=$false;try{New-RMPrivateUiSession '' 0 ([datetime]::UtcNow) '' $false $true|Out-Null}catch{$blocked=$true};Check $blocked 'Isolation attestation mandatory'
$blocked=$false;try{New-RMPrivateUiSession '' 0 ([datetime]::UtcNow) '' $true $false|Out-Null}catch{$blocked=$true};Check $blocked 'Private consent mandatory'
if($env:OS -eq 'Windows_NT'){
 & (Join-Path $base 'Easy-UI.ps1') -LayoutSmoke
}
Write-Host 'PASS: consent gates and own-console scope checks; GUI only constructed in Windows smoke.'
