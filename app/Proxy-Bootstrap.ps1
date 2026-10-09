#requires -Version 5.1
param([string]$StatusPath)
$ErrorActionPreference='Stop';$script:ProxyStartupPath=$StatusPath
try {
 Add-Type -AssemblyName System.Windows.Forms
 if(!(Test-Path -LiteralPath (Join-Path $PSScriptRoot 'Proxy-Startup-Status.ps1'))){throw 'فایل Proxy-Startup-Status.ps1 پیدا نشد. فایل‌های به‌روزرسانی را کامل کپی کن.'}
 . (Join-Path $PSScriptRoot 'Proxy-Startup-Status.ps1')
 Set-ProxyStartupStatus 'Starting'
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$pr=New-Object Security.Principal.WindowsPrincipal($id)
 if($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'برای جلوگیری از اجرای بازی با ادمین، پنجره باز نشد. Start-Proxy-Test.cmd را از Explorer با دوبار کلیک معمولی اجرا کن؛ نه با ادمین.'}
 foreach($name in @('Proxy-Probe.cs','Proxy-Test-UI.ps1')){if(!(Test-Path -LiteralPath (Join-Path $PSScriptRoot $name) -PathType Leaf)){throw ('فایل لازم پیدا نشد: '+$name+'. به‌روزرسانی را کامل کپی کن.')}}
 # Dot-source deliberately shares only startup status; no target or private network data.
 . (Join-Path $PSScriptRoot 'Proxy-Test-UI.ps1')
 Set-ProxyStartupStatus 'Closed'
} catch {
 $message=$_.Exception.Message
 try{Set-ProxyStartupStatus 'Failed' $message}catch{}
 try{[void][Windows.Forms.MessageBox]::Show("پنجره آزمون پروکسی باز نشد.`n`n"+$message,'خطای شروع آزمون پروکسی','OK','Error')}catch{Write-Error $message -ErrorAction Continue}
 exit 1
}
