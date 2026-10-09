#requires -Version 5.1
param([string]$StatusPath)
$ErrorActionPreference='Stop';$script:ProxyStartupPath=$StatusPath
try{
 Add-Type -AssemblyName System.Windows.Forms
 . (Join-Path $PSScriptRoot 'Proxy-Startup-Status.ps1');Set-ProxyStartupStatus 'Starting'
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$pr=New-Object Security.Principal.WindowsPrincipal($id)
 if($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Start-TLS-Test.cmd را با دوبار کلیک معمولی اجرا کن؛ نه با ادمین.'}
 if(![Environment]::Is64BitOperatingSystem -or ![Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64'){throw 'این بسته فقط Windows x64 است؛ روی ARM64 یا PowerShell سی‌ودوبیتی اجرا نمی‌شود.'}
 if(!(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'tools\mitmproxy\mitmdump.exe'))){& (Join-Path $PSScriptRoot 'Install-Mitmdump.ps1')}
 foreach($name in @('TLS-Test-UI.ps1','TLS-Cleanup.ps1','TLS-Guard.ps1','Telemetry-Fields.py','tools\mitmproxy\mitmdump.exe')){if(!(Test-Path -LiteralPath (Join-Path $PSScriptRoot $name))){throw ('فایل لازم پیدا نشد: '+$name)}}
 . (Join-Path $PSScriptRoot 'TLS-Test-UI.ps1');Set-ProxyStartupStatus 'Closed'
}catch{try{Set-ProxyStartupStatus 'Failed' $_.Exception.Message}catch{};[void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'خطای شروع بررسی TLS','OK','Error');exit 1}
