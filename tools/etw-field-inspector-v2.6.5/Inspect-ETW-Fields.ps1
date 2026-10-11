#requires -Version 5.1
param([string]$InputPath='')
$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Windows.Forms
. (Join-Path $PSScriptRoot 'ETW-Field-Core.ps1')
. (Join-Path $PSScriptRoot 'WebTrace-Core.ps1')
try{
 if(!$InputPath){$pick=New-Object Windows.Forms.OpenFileDialog;$pick.Title='رویداد خصوصی همان نشست؛ ضبط تازه لازم نیست';$pick.Filter='Private target events|private-target-events.jsonl|Original local ETL|*.etl';$pick.FilterIndex=2;$pick.InitialDirectory=Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor\Web-ETW';if($pick.ShowDialog() -ne 'OK'){$pick.Dispose();return};$InputPath=$pick.FileName;$pick.Dispose()}
 $file=Get-Item -LiteralPath $InputPath -ErrorAction Stop;if($file.Length -gt 67108864){throw 'ورودی از سقف ۶۴ MiB بزرگ‌تر است؛ تحلیل شروع نشد.'}
 if($file.Extension -notin @('.jsonl','.etl')){throw 'ورودی باید private-target-events.jsonl یا ETL محلی باشد، نه گزارش عمومی JSON.'}
 if([Windows.Forms.MessageBox]::Show('این فایل خصوصی فقط محلی خوانده می‌شود. مقدارها، URL کامل، query، توکن و بدنه صادر نمی‌شوند. گزارش خروجی فقط ساختار و نشانه‌های محدود API/URL را دارد. در حالت ETL، فایل process-observations-private.json کنار آن برای انتساب لازم است. ادامه؟','رضایت بررسی محلی','YesNo','Information') -ne 'Yes'){return}
 Write-Host 'Inspecting existing local events. Raw field values are not printed or exported.'
 $acc=New-RMFieldAccumulator;$rows=0;$parseErrors=0;$unsupportedRows=0;$renderErrors=0;$renderPresent=0;$renderEmpty=0;$unmatched=0;$limit=$false;$sourceMode='PrivateJSONL'
 if($file.Extension -eq '.jsonl'){
  foreach($line in [IO.File]::ReadLines($file.FullName)){
   if(!$line.Trim()){continue};$rows++;if($rows -gt 100000){$limit=$true;break};if($line.Length -gt 2097152){$limit=$true;$unsupportedRows++;continue}
   try{$e=$line|ConvertFrom-Json -ErrorAction Stop}catch{$parseErrors++;continue}
   if(!$e.PSObject.Properties['Fields'] -or !$e.PSObject.Properties['Provider'] -or !$e.PSObject.Properties['EventID']){$unsupportedRows++;continue}
   Add-RMFieldEvent $acc $e
  }
 }else{
  $sourceMode='LocalETLWithFormattedMessage';$ctx=Join-Path $file.DirectoryName 'process-observations-private.json'
  if(!(Test-Path -LiteralPath $ctx)){throw 'process-observations-private.json همان نشست کنار ETL نیست؛ برای جلوگیری از تحلیل پردازش‌های دیگر، عملیات متوقف شد.'}
  $processes=@(Get-Content -LiteralPath $ctx -Raw|ConvertFrom-Json);if(!$processes.Count){throw 'هیچ پردازش مشاهده‌شده‌ای برای انتساب وجود ندارد.'}
  Get-WinEvent -Path $file.FullName -Oldest -ErrorAction Stop|Select-Object -First 100001|ForEach-Object {
   $rows++;if($rows -gt 100000){$limit=$true;return};try{$e=Get-RMWebEvent $_.ToXml()}catch{$parseErrors++;return}
   if(!$e -or $e.Provider -notin @('Microsoft-Windows-WinHttp','Microsoft-Windows-WinINet')){$unmatched++;return}
   if(!@(Get-RMWebAttribution $e $processes).Count){$unmatched++;return}
   $message='';try{$message=[string]$_.FormatDescription();if($message){$renderPresent++}else{$renderEmpty++}}catch{$renderErrors++}
   Add-RMFieldEvent $acc $e $message
  }
 }
 if(!$acc.Events -and $file.Extension -eq '.jsonl'){throw 'هیچ ردیف سازگار با قالب رویداد خصوصی پیدا نشد؛ فایل درست را انتخاب کن.'}
 $doc=Complete-RMFieldReport $acc
 $doc|Add-Member -NotePropertyName 'SourceMode' -NotePropertyValue $sourceMode
 $doc|Add-Member -NotePropertyName 'InputRowsOrEventsRead' -NotePropertyValue $rows
 $doc|Add-Member -NotePropertyName 'ParseErrors' -NotePropertyValue $parseErrors
 $doc|Add-Member -NotePropertyName 'UnsupportedRows' -NotePropertyValue $unsupportedRows
 $doc|Add-Member -NotePropertyName 'UnmatchedETLEvents' -NotePropertyValue $unmatched
 $doc|Add-Member -NotePropertyName 'MessageRenderErrors' -NotePropertyValue $renderErrors
 $doc|Add-Member -NotePropertyName 'FormattedMessagesPresent' -NotePropertyValue $renderPresent
 $doc|Add-Member -NotePropertyName 'FormattedMessagesEmpty' -NotePropertyValue $renderEmpty
 $doc|Add-Member -NotePropertyName 'InputLimitReached' -NotePropertyValue $limit
 $share=Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor\Reports-to-share';[void][IO.Directory]::CreateDirectory($share);$path=Join-Path $share ('EventFieldReport-'+[guid]::NewGuid().ToString('N')+'.json');$doc|ConvertTo-Json -Depth 14|Set-Content -LiteralPath $path -Encoding UTF8
 $count=0;foreach($g in $doc.Groups){foreach($f in $g.Fields){$count+=$f.URLLikeStringOccurrences}}
 $text="رویداد بررسی‌شده: $($acc.Events)`nرخداد رشتهٔ شبیه URL: $count`nاین شمارنده درخواست یکتا یا ارسال موفق نیست.`nفقط EventFieldReport را پس از بازبینی بفرست؛ فایل ورودی خصوصی را نفرست."
 if($limit -or $acc.LimitsReached -or $parseErrors -or $unsupportedRows -or $renderErrors){$text+="`nمحدودیت یا خطای خواندن وجود دارد؛ نتیجه کامل نیست."}
 [void][Windows.Forms.MessageBox]::Show($text,'نتیجهٔ بررسی ساختار');Start-Process explorer.exe -ArgumentList ('/select,"'+$path+'"')
}catch{[void][Windows.Forms.MessageBox]::Show('بررسی انجام نشد. '+$_.Exception.Message,'خطای بررسی','OK','Error')}
