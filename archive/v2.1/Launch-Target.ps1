#requires -Version 5.1
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$pr=New-Object Security.Principal.WindowsPrincipal($id)
if($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'For safety, run Launch-Target.cmd from ordinary, non-elevated Explorer. Target was NOT launched.'}
$config=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Launch-Target.json') -Raw | ConvertFrom-Json
if(!(Test-Path -LiteralPath $config.Target -PathType Leaf)){throw 'Target not found.'}
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=$config.Target; $info.Arguments=$config.Arguments
$info.UseShellExecute=$false; $info.WorkingDirectory=[IO.Path]::GetDirectoryName($config.Target)
$info.EnvironmentVariables['SSLKEYLOGFILE']=$config.KeyFile
[void][Diagnostics.Process]::Start($info)
Write-Host 'Target launched without elevation. The key file appears only if the TLS library supports key logging.'
Write-Host ('Keep private: '+$config.KeyFile)
