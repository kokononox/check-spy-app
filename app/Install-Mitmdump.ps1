# Fetch portable vendor binary only; no CA import, no system installer, no administrator rights.
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
$dest=Join-Path $PSScriptRoot 'tools\mitmproxy\mitmdump.exe'
$archiveHash='04A01EA95AE96DF75058A893E774957D294E69012DAB1F4E256CE2B0C6725483'
$exeHash='36A45AADEB842185B8064B8F0BE3730E079C9F9C125BC8BE22363332969857BF'
if(Test-Path -LiteralPath $dest){if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -eq $exeHash){return};throw 'ابزار موجود با هش رسمی تطبیق ندارد؛ جایگزینی خودکار انجام نشد.'}
if([Windows.Forms.MessageBox]::Show('نسخه رسمی قابل‌حمل mitmproxy 12.2.3 با مجوز MIT دانلود شود؟ حجم دانلود حدود ۸۶ مگابایت است. فقط mitmdump.exe استخراج و هش فایل بررسی می‌شود؛ نصب گواهی یا تغییر تنظیمات در این مرحله انجام نمی‌شود.','دریافت ابزار رسمی','YesNo','Question') -ne 'Yes'){throw 'دریافت ابزار لغو شد.'}
$temp=Join-Path ([IO.Path]::GetTempPath()) ('mitmproxy-'+[guid]::NewGuid().ToString('N')+'.zip');$client=New-Object Net.WebClient;$old=[Net.ServicePointManager]::SecurityProtocol
try{
 [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
 $client.DownloadFile('https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-windows-x86_64.zip',$temp)
 if((Get-FileHash -LiteralPath $temp -Algorithm SHA256).Hash -ne $archiveHash){throw 'هش بسته دانلودشده تطبیق ندارد؛ استخراج و اجرا انجام نشد.'}
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $zip=[IO.Compression.ZipFile]::OpenRead($temp)
 try{$entry=$zip.GetEntry('mitmdump.exe');if(!$entry){throw 'mitmdump.exe در بسته رسمی پیدا نشد.'};[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($dest));[IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$dest,$false)}finally{$zip.Dispose()}
 if((Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash -ne $exeHash){Remove-Item -LiteralPath $dest -Force;throw 'هش فایل استخراج‌شده تطبیق ندارد؛ فایل حذف شد.'}
}finally{$client.Dispose();[Net.ServicePointManager]::SecurityProtocol=$old;if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Force}}
