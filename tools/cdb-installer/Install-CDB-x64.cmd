@echo off
setlocal
set "CDB_INSTALLER_SELF=%~f0"
set "CDB_PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "CDB_PS=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%CDB_PS%" -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -Command "$s=[IO.File]::ReadAllText($env:CDB_INSTALLER_SELF,[Text.Encoding]::UTF8);$m='#PS_PAYLOAD_START';$i=$s.LastIndexOf($m);if($i -lt 0){exit 1}; & ([scriptblock]::Create($s.Substring($i+$m.Length)))"
exit /b %errorlevel%
#PS_PAYLOAD_START
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
function Show-Result([string]$Message,[bool]$Failure=$false){
 $icon=if($Failure){[Windows.Forms.MessageBoxIcon]::Error}else{[Windows.Forms.MessageBoxIcon]::Information}
 [void][Windows.Forms.MessageBox]::Show($Message,'نصب CDB x64',[Windows.Forms.MessageBoxButtons]::OK,$icon)
}
function Test-MicrosoftX64Cdb([string]$Path){
 if([IO.Path]::GetFileName($Path) -ine 'cdb.exe' -or !(Test-Path -LiteralPath $Path -PathType Leaf)){return $false}
 $sig=Get-AuthenticodeSignature -LiteralPath $Path
 if($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){return $false}
 $stream=[IO.File]::OpenRead($Path);$reader=New-Object IO.BinaryReader($stream)
 try{
  if($reader.ReadUInt16() -ne 0x5a4d){return $false}
  $stream.Position=0x3c;$offset=$reader.ReadInt32()
  if($offset -lt 64 -or $offset -gt $stream.Length-6){return $false}
  $stream.Position=$offset
  return ($reader.ReadUInt32() -eq 0x4550 -and $reader.ReadUInt16() -eq 0x8664)
 }finally{$reader.Dispose()}
}
$work=$null;$stage='Start'
try{
 if(![Environment]::Is64BitOperatingSystem -or ![Environment]::Is64BitProcess -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64'){throw 'Windows x64 required'}
 $cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
 if(Test-MicrosoftX64Cdb $cdb){Show-Result "CDB x64 معتبر از قبل نصب است.`r`nاکنون Start.cmd ابزار را باز کن.";exit 0}
 $message="این فایل فقط بخش Debugging Tools for Windows شامل CDB را از نصب‌کنندهٔ رسمی Microsoft درخواست می‌کند، نه کل SDK.`r`nاینترنت و تأیید دسترسی مدیر لازم است. نصب تابع شرایط مجوز مایکروسافت است؛ ادامه یعنی موافقت با نصب.`r`nهیچ گواهی، پروکسی یا تنظیم ضدتقلبی تغییر داده نمی‌شود. راه‌اندازی مجدد خودکار انجام نمی‌شود.`r`nادامه؟"
 $answer=[Windows.Forms.MessageBox]::Show($message,'تأیید نصب رسمی CDB',[Windows.Forms.MessageBoxButtons]::YesNo,[Windows.Forms.MessageBoxIcon]::Question,[Windows.Forms.MessageBoxDefaultButton]::Button2)
 if($answer -ne [Windows.Forms.DialogResult]::Yes){exit 0}
 $stage='Download';Write-Host 'Downloading official Microsoft installer. Please wait...'
 $work=Join-Path ([IO.Path]::GetTempPath()) ('CDB-Official-'+[guid]::NewGuid().ToString('N'))
 [void][IO.Directory]::CreateDirectory($work)
 $setup=Join-Path $work 'winsdksetup.exe'
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2382321' -OutFile $setup -UseBasicParsing -TimeoutSec 180
 $stage='Verify'
 # Official Windows SDK 10.0.26100.9457 bootstrapper; checked against the Microsoft download.
 $expected='B0BDBAD38AE74C40CCAE8CDBCF229807627FBA2BC3100BE28301C4BA884F755E'
 if((Get-FileHash -LiteralPath $setup -Algorithm SHA256).Hash -ne $expected){throw 'Installer hash mismatch; refused to run'}
 $signature=Get-AuthenticodeSignature -LiteralPath $setup
 if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw 'Microsoft signature invalid; refused to run'}
 $stage='Install';Write-Host 'Installing Debugging Tools only. Approve the Windows administrator prompt for Microsoft.'
 $process=Start-Process -FilePath $setup -ArgumentList '/features OptionId.WindowsDesktopDebuggers /passive /norestart' -Verb RunAs -Wait -PassThru
 if($process.ExitCode -notin @(0,3010)){throw ('Official installer exit code '+$process.ExitCode)}
 $stage='CheckCDB';$valid=$false
 for($i=0;$i -lt 30;$i++){if(Test-MicrosoftX64Cdb $cdb){$valid=$true;break};Start-Sleep -Seconds 2}
 if(!$valid){throw 'CDB x64 not confirmed at expected path'}
 $message="نصب CDB x64 تأیید شد.`r`nاکنون Start.cmd ابزار را دوباره باز کن؛ CDB خودکار پیدا می‌شود."
 if($process.ExitCode -eq 3010){$message+="`r`nمایکروسافت درخواست راه‌اندازی مجدد داده است؛ پس از ذخیرهٔ کارها، خودت ویندوز را Restart کن."}
 Show-Result $message;exit 0
}catch{
 Write-Host ('Installation not confirmed. Stage: '+$stage) -ForegroundColor Red
 $hint=switch($stage){
  'Download'{'اتصال اینترنت یا دسترسی به سرور مایکروسافت برقرار نشد.'}
  'Verify'{'امضا یا hash نصب‌کننده تأیید نشد؛ فایل اجرا نشده است. بررسی امضا را غیرفعال نکن.'}
  'Install'{'درخواست مدیر لغو شد یا نصب‌کنندهٔ رسمی خطا داد. اگر SDK دیگری باز است، آن را ببند و دوباره تلاش کن.'}
  'CheckCDB'{'CDB معتبر در مسیر پیش‌فرض پیدا نشد؛ اگر مسیر سفارشی داری، آن را در رابط ابزار انتخاب کن.'}
  default{'این فایل فقط برای Windows x64 است.'}
 }
 Show-Result ("نصب تأیید نشد.`r`n"+$hint+"`r`nحفاظت سیستم را غیرفعال نکن؛ نصب دستی فقط از صفحهٔ رسمی مایکروسافت:`r`nhttps://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools") $true
 exit 1
}finally{
 if($work -and (Test-Path -LiteralPath $work)){Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue}
}
