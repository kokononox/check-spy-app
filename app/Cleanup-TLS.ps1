$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Windows.Forms
try{
 . (Join-Path $PSScriptRoot 'TLS-Cleanup.ps1')
 $root=Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor\TLS-Sessions';$count=0
 if(Test-Path -LiteralPath $root){foreach($dir in Get-ChildItem -LiteralPath $root -Directory){if(Test-Path -LiteralPath (Join-Path $dir.FullName 'lease.json')){$r=Invoke-TLSCleanup $dir.FullName;if(!$r.CertificateAbsent -or !$r.ProxyStopped){throw 'پاک‌سازی کامل تأیید نشد. بازی را ببند و پیام خطا را برای بررسی نگه دار.'};$count++}}}
 [void][Windows.Forms.MessageBox]::Show("پاک‌سازی انجام شد؛ تعداد سابقه بررسی‌شده: $count`nفقط گواهی‌های دقیقاً ثبت‌شده همین ابزار بررسی و حذف شدند.",'پاک‌سازی TLS')
}catch{[void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'خطای پاک‌سازی','OK','Error');exit 1}
