#requires -Version 5.1
$ErrorActionPreference='Stop'
$id=[Security.Principal.WindowsIdentity]::GetCurrent()
$pr=New-Object Security.Principal.WindowsPrincipal($id)
if($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'For safety, run Launch-Target.cmd from ordinary, non-elevated Explorer. Target was NOT launched.'}
$config=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Launch-Target.json') -Raw | ConvertFrom-Json
if(!(Test-Path -LiteralPath $config.Target -PathType Leaf)){throw 'Target not found.'}
if($config.TargetSHA256 -and (Get-FileHash -LiteralPath $config.Target -Algorithm SHA256).Hash -ne $config.TargetSHA256){throw 'Target file changed since the session began. Start a fresh monitoring session.'}
$already=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {$_.ExecutablePath -and [string]::Equals($_.ExecutablePath,$config.Target,[StringComparison]::OrdinalIgnoreCase)})
if($already.Count){throw 'Close the existing target first, then run this launcher. No process was killed or restarted.'}
$info=New-Object Diagnostics.ProcessStartInfo
$info.FileName=$config.Target; $info.Arguments=$config.Arguments
$info.UseShellExecute=$false; $info.WorkingDirectory=[IO.Path]::GetDirectoryName($config.Target)
$info.EnvironmentVariables['SSLKEYLOGFILE']=$config.KeyFile
$proc=[Diagnostics.Process]::Start($info)
. (Join-Path $PSScriptRoot 'TLS-Key-Status.ps1')
Write-Host 'Waiting up to 30 seconds for supported TLS-key-log records. Keep capture running and trigger an online action in the target.'
$until=[datetime]::UtcNow.AddSeconds(30)
do {Start-Sleep -Milliseconds 500;$k=Get-RMTLSKeyStatus $config.KeyFile} while(!$k.ValidEntries -and [datetime]::UtcNow -lt $until -and !$proc.HasExited)
Write-Host ('TLS key status: '+$k.Assessment+'; valid records: '+$k.ValidEntries)
if(!$k.ValidEntries){Write-Warning 'Key logging not established. The EXE may ignore SSLKEYLOGFILE, forward to an existing process, or not have opened a TLS connection. No keys were extracted from memory.'}
$proc.Dispose()
Write-Host 'Target launched without elevation. The key file appears only if the TLS library supports key logging.'
Write-Host ('Keep private: '+$config.KeyFile)
