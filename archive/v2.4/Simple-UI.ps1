# Single primary action. Core monitoring and capture continue on their existing workers.
$script:simpleMode=$true;$script:autoPreparing=$false;$script:autoPhase='Idle';$script:autoAnalysis=$null;$script:autoDeadline=[datetime]::MinValue
$top.Visible=$false;$bottom.Visible=$false;$tabs.Visible=$false;$alerts.Checked=$false
$form.Text='بررسی سادهٔ ارتباط برنامه — ۲٫۴';$form.Size=New-Object Drawing.Size(980,820);$area=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea;$form.Size=New-Object Drawing.Size([Math]::Min(980,$area.Width-32),[Math]::Min(820,$area.Height-32));$form.MinimumSize=New-Object Drawing.Size([Math]::Min(900,$area.Width-32),[Math]::Min(680,$area.Height-32));$form.BackColor=[Drawing.Color]::White
$simple=New-Object Windows.Forms.TableLayoutPanel;$simple.Dock='Fill';$simple.Padding=New-Object Windows.Forms.Padding(28);$simple.AutoScroll=$true;$simple.ColumnCount=1;$simple.RowCount=8;$simple.BackColor=[Drawing.Color]::White
foreach($height in @(62,108,34,76,55,22)) {[void]$simple.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height)))}
[void]$simple.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));[void]$simple.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,44)))
$form.Controls.Add($simple);$simple.BringToFront()
function New-SimpleLabel($text,$size=12){$l=New-Object Windows.Forms.Label;$l.Text=$text;$l.Dock='Fill';$l.RightToLeft='Yes';$l.TextAlign='MiddleRight';$l.ForeColor=[Drawing.Color]::FromArgb(44,44,43);$l.Font=New-Object Drawing.Font('Segoe UI',$size);return $l}
$heading=New-SimpleLabel 'یک دکمه؛ انتخاب، ضبط و نتیجه' 23;$simple.Controls.Add($heading,0,0)
$how=New-SimpleLabel "۱. برنامهٔ هدف را ببند؛ بعد دکمهٔ پایین را بزن و فایل EXE را انتخاب کن.`n۲. ابزارها در صورت نیاز با تأیید تو نصب می‌شوند و برنامهٔ هدف باز می‌شود.`n۳. حدود ۹۰ ثانیه با برنامه کار کن؛ نتیجه خودکار همین‌جا نمایش داده می‌شود." 12;$simple.Controls.Add($how,0,1)
$compare=New-Object Windows.Forms.CheckBox;$compare.Text='تطبیق محدود نام سیستم، نام کاربر و شناسه‌های محلی با دادهٔ قابل‌خواندن (اختیاری)';$compare.Checked=$false;$compare.Dock='Fill';$compare.RightToLeft='Yes';$compare.Font=New-Object Drawing.Font('Segoe UI',11);$compare.ForeColor=[Drawing.Color]::FromArgb(70,70,70);$simple.Controls.Add($compare,0,2)
$action=New-Object Windows.Forms.Button;$action.Text='شروع بررسی خودکار';$action.Dock='Fill';$action.FlatStyle='Flat';$action.BackColor=[Drawing.Color]::FromArgb(39,131,222);$action.ForeColor=[Drawing.Color]::White;$action.Font=New-Object Drawing.Font('Segoe UI',17,[Drawing.FontStyle]::Bold);$action.Margin=New-Object Windows.Forms.Padding(0,8,0,8);$simple.Controls.Add($action,0,3)
$phaseLabel=New-SimpleLabel 'آماده — قبل از شروع، فایل‌ها و کارهای باز برنامهٔ هدف را ذخیره کن.' 12;$simple.Controls.Add($phaseLabel,0,4)
$progress=New-Object Windows.Forms.ProgressBar;$progress.Dock='Fill';$progress.Maximum=90;$progress.Minimum=0;$simple.Controls.Add($progress,0,5)
$result=New-Object Windows.Forms.RichTextBox;$result.Dock='Fill';$result.ReadOnly=$true;$result.RightToLeft='Yes';$result.BackColor=[Drawing.Color]::FromArgb(249,248,247);$result.ForeColor=[Drawing.Color]::FromArgb(44,44,43);$result.Font=New-Object Drawing.Font('Segoe UI',12);$result.BorderStyle='FixedSingle';$result.Margin=New-Object Windows.Forms.Padding(0,16,0,8);$simple.Controls.Add($result,0,6)
$result.Text="نتیجهٔ بررسی اینجا می‌آید.`n`nمهم: اتصال به یک سرور، به‌تنهایی ثابت نمی‌کند چه اطلاعاتی ارسال شده است. اگر برنامه کلید TLS تولید نکند، محتوای HTTPS ممکن است نامعلوم بماند."
$foot=New-Object Windows.Forms.LinkLabel;$foot.Text='بررسی راه جایگزین TLS | فقط گزارش نهایی را بفرست؛ کلید و ضبط خام را نفرست.';$foot.LinkArea=New-Object Windows.Forms.LinkArea(0,22);$foot.Dock='Fill';$foot.RightToLeft='Yes';$foot.TextAlign='MiddleRight';$foot.Font=New-Object Drawing.Font('Segoe UI',11);$simple.Controls.Add($foot,0,7)
$foot.Add_LinkClicked({
 if($script:autoPhase -in @('Capturing','Stopping','Analyzing') -or $script:autoPreparing){[void][Windows.Forms.MessageBox]::Show('اول بررسی جاری را تمام کن.');return}
 Start-Process (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe') -ArgumentList ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $PSScriptRoot 'Diagnostics-UI.ps1')+'"')
})
function Set-SimpleError([string]$message) {
 if($script:autoAnalysis){try{if(!$script:autoAnalysis.HasExited){$script:autoAnalysis.Kill()}}catch{};$script:autoAnalysis.Dispose();$script:autoAnalysis=$null}
 $script:autoPhase='Error';$phaseLabel.Text='بررسی متوقف شد';$result.Text=$message+"`n`nفایل هدف خودکار بسته یا کشته نمی‌شود. بعد از رفع مشکل، دوباره دکمه را بزن.";$action.Text='تلاش دوباره';$action.Enabled=$true;$compare.Enabled=$true;$progress.Style='Blocks'
}
function Invoke-DesktopLaunch([string]$scriptPath) {
 # Use the original desktop Explorer broker. The launcher also refuses administrator tokens.
 $shell=New-Object -ComObject Shell.Application;$windows=$shell.Windows();$loc=0;$rootLoc=0;$hwnd=0
 $desktop=$windows.FindWindowSW([ref]$loc,[ref]$rootLoc,8,[ref]$hwnd,1)
 if(!$desktop){throw 'اجرای امن از Explorer ممکن نشد. از حالت فنی و لانچر معمولی استفاده کنید؛ هدف با ادمین اجرا نشد.'}
 $broker=$desktop.Document.Application
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$scriptPath+'"'
 $broker.ShellExecute($ps,$args,[IO.Path]::GetDirectoryName($scriptPath),'open',0)
}
function New-AutoLaunchFiles {
 $folder=Join-Path $root ('evidence-'+$script:session);New-Item -ItemType Directory -Force -Path $folder | Out-Null
 $script:tlsFile=Join-Path $folder ('tls-keys-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.log');$script:autoLaunchStatus=Join-Path $folder 'launcher-status.json'
 [ordered]@{Target=$script:target;TargetSHA256=$script:targetHash;Arguments=$evArgs.Text;KeyFile=$script:tlsFile} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'Launch-Target.json') -Encoding UTF8
 foreach($f in @('Launch-Target.ps1','Launch-Target.cmd','TLS-Key-Status.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination (Join-Path $folder $f) -Force}
 return (Join-Path $folder 'Launch-Target.ps1')
}
function Start-AutoAnalysis {
 $phaseLabel.Text='در حال پایان ضبط و ساخت گزارش…';$action.Enabled=$false;$script:autoPhase='Stopping'
 RM-StopCapture;if($script:captureOwned){throw 'ضبط متوقف نشد؛ دوباره تلاش کنید یا متن خطا را بررسی کنید.'}
 Stop-Monitor
 if(!$script:capturePCAP -or !(Test-Path -LiteralPath $script:capturePCAP)){throw 'فایل ضبط تبدیل نشده است؛ پیام خطای تبدیل را بررسی کنید.'}
 $tshark=RM-FindWireshark;if(!$tshark){throw 'تحلیل‌گر tshark پیدا نشد.'}
 $context=$script:capturePCAP+'.analysis-context.json';Copy-Item -LiteralPath $script:captureContext -Destination $context -Force
 $script:lastEvidence=$script:capturePCAP+'.evidence.json'
 $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $PSScriptRoot 'Analyze-Capture.ps1')+'" -CapturePath "'+$script:capturePCAP+'" -ContextPath "'+$context+'" -OutputPath "'+$script:lastEvidence+'" -TsharkPath "'+$tshark+'" -LaunchStatusPath "'+$script:autoLaunchStatus+'" -KeyLogPath "'+$script:tlsFile+'"'
 if($compare.Checked){$args+=' -CompareLocalIdentifiers'}
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe';$info.Arguments=$args;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $script:autoAnalysis=New-Object Diagnostics.Process;$script:autoAnalysis.StartInfo=$info;[void]$script:autoAnalysis.Start()
 $script:autoStdout=$script:autoAnalysis.StandardOutput.ReadToEndAsync();$script:autoStderr=$script:autoAnalysis.StandardError.ReadToEndAsync()
 $script:autoAnalysisDeadline=[datetime]::UtcNow.AddMinutes(10);$script:autoPhase='Analyzing';$progress.Style='Marquee';$phaseLabel.Text='در حال تحلیل؛ لطفاً صبر کن…'
}
function Show-SimpleResult($d) {
 $text="بررسی تمام شد.`n`n"
 if($d.CaptureAssessment -like 'No IP*'){$text+='قالب ضبط قابل ارزیابی نبود؛ از این نتیجه نمی‌توان دربارهٔ ارسال اطلاعات نتیجه گرفت.'}
 elseif(!$d.CorrelatedOutboundFrames){$text+='ترافیک هدف با این ضبط تطبیق داده نشد؛ این به معنی نبود ارسال نیست.'}
 else {
  $text+='ارتباط‌های برنامه ثبت و با ضبط تطبیق داده شدند.'+"`n"
  if($d.ReadableHTTPOverTLSFrames -gt 0){$text+='بخشی از محتوای HTTP/HTTP2 روی TLS قابل‌خواندن شده است.'+"`n"}
  else{$text+='محتوای HTTPS رمزگشایی‌شده اثبات نشد؛ هنوز نمی‌توان فهرست کامل اطلاعات ارسالی را تعیین کرد.'+"`n"}
  if(!$d.KeyLogFileExists){
   if($d.LauncherDiagnostic -and $d.LauncherDiagnostic.Success){$text+='هدف اجرا شد، ولی کلید TLS ساخته/پیدا نشد. به‌جای تکرار همان ضبط، از لینک بررسی راه جایگزین TLS استفاده کن.'+"`n"}
   else{$text+='فایل کلید TLS ایجاد/پیدا نشد. وضعیت اجرای هدف را بررسی کن.'+"`n"}
  }
  elseif(!$d.KeyLogValidRecords){$text+='فایل کلید هست، اما رکورد معتبر ندارد یا فعلاً خوانده نمی‌شود.'+"`n"}
  elseif(!$d.KeyLogClientRandomMatches){$text+='کلید با قالب معتبر هست، اما نشست متناظر در این ضبط تطبیق داده نشد.'+"`n"}
  if($d.LauncherDiagnostic -and !$d.LauncherDiagnostic.Success){$text+='مشکل اجرای هدف: '+$d.LauncherDiagnostic.Error+"`n"}
  $names=@($d.Endpoints | ForEach-Object {$_.SNI} | Where-Object {$_} | Select-Object -Unique)
  if($names.Count){$text+="`nنام مقصدهای مشاهده‌شده:`n"+($names -join "`n")+"`n"}
  $ids=@($d.LocalIdentifierMatchFrameCounts.PSObject.Properties | Where-Object {$_.Value -gt 0} | ForEach-Object {$_.Name})
  if($ids.Count){$text+="`nرشته‌هایی مطابق شناسه‌های محلی دیده شد: "+($ids -join '، ')+"`nاین تطبیق به‌تنهایی اثبات سرقت یا سوءنیت نیست.`n"}
 }
 if($d.QuarantinedPacketCount -gt 0){$text+="`nهشدار داخلی تحلیل‌گر ثبت شد؛ بسته‌های نام‌برده کنار گذاشته شدند و نتیجه برای بقیهٔ ضبط ساخته شد. این گزارش کامل نیست.`n"}
 $text+="`nفقط فایل گزارش زیر را، بعد از بازبینی اطلاعات حساس، ارسال کن:`n"+[char]0x200e+[IO.Path]::GetFileName($script:lastEvidence)
 $result.Text=$text;$phaseLabel.Text='تمام شد — نتیجه اینجا و گزارش در پوشهٔ بازشده است.';$progress.Style='Blocks';$progress.Value=90;$script:autoPhase='Done';$action.Text='شروع بررسی تازه';$action.Enabled=$true;$compare.Enabled=$true
 Start-Process explorer.exe -ArgumentList ('/select,"'+$script:lastEvidence+'"')
}
$action.Add_Click({
 if($script:autoPhase -eq 'Capturing'){try {Start-AutoAnalysis}catch{Set-SimpleError $_.Exception.Message};return}
 if($script:autoPreparing -or $script:autoPhase -in @('Stopping','Analyzing')){return}
 $script:autoPreparing=$true;$action.Enabled=$false;$compare.Enabled=$false
 try {
  if(!(RM-IsAdmin)){throw 'برنامهٔ مانیتور را ببند و Start.cmd را با Run as administrator اجرا کن. خود فایل هدف را با ادمین اجرا نکن.'}
  $pick=New-Object Windows.Forms.OpenFileDialog;$pick.Title='فایل برنامه‌ای را که می‌خواهی بررسی کنی انتخاب کن';$pick.Filter='برنامهٔ ویندوز (*.exe)|*.exe'
  if($pick.ShowDialog() -ne 'OK'){$pick.Dispose();$script:autoPhase='Idle';return};$pathBox.Text=$pick.FileName;$pick.Dispose()
  $existing=@(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object {$_.ExecutablePath -and [string]::Equals($_.ExecutablePath,$pathBox.Text,[StringComparison]::OrdinalIgnoreCase)})
  if($existing.Count){throw 'برنامهٔ هدف باز است. کارهای بازش را ذخیره کن، خودت آن را کامل ببند و دوباره دکمه را بزن.'}
  if([Windows.Forms.MessageBox]::Show("این بررسی برنامهٔ انتخاب‌شده را با دسترسی معمولی اجرا می‌کند، حدود ۹۰ ثانیه ترافیک کل سیستم را محلی ضبط می‌کند و برای همین اجرای هدف درخواست ثبت کلید TLS می‌دهد. ضبط و کلید ممکن است حساس باشند. هیچ داده‌ای آپلود نمی‌شود، گواهی/فایروال تغییر نمی‌کند و کلیدی از حافظه استخراج نمی‌شود. ادامه می‌دهی؟",'تأیید بررسی محلی','YesNo','Warning') -ne 'Yes'){$script:autoPhase='Idle';return}
  $phaseLabel.Text='آماده‌سازی ابزارها…';$result.Text='اگر ابزار لازم نصب نباشد، تأیید مجوز/نصب نشان داده می‌شود. بعد از آماده‌سازی، ادامهٔ بررسی خودکار است.';$progress.Style='Marquee'
  if(!(RM-InstallWireshark)){throw 'تحلیل‌گر آماده نشد یا نصب آن لغو شد.'}
  if($script:running){Stop-Monitor};Start-MonitorSession;if(!$script:running){throw 'شروع مانیتور انجام نشد. پیام نمایش‌داده‌شده را بررسی کن.'}
  Start-RMPacketCapture -ConsentAlreadyGiven;if(!$script:captureOwned){throw 'شروع ضبط انجام نشد؛ پیام خطا را بررسی کن.'}
  $launcher=New-AutoLaunchFiles;Invoke-DesktopLaunch $launcher
  $script:autoLaunchedAt=[datetime]::UtcNow;$script:autoDeadline=[datetime]::UtcNow.AddSeconds(90);$script:autoPhase='Capturing';$progress.Style='Blocks';$progress.Value=0;$phaseLabel.Text='برنامه باز می‌شود؛ طی ۹۰ ثانیه با آن کار کن.';$result.Text="در برنامهٔ هدف، فعالیت آنلاین موردنظر را انجام بده.`n`nضبط و بررسی وضعیت کلید خودکار است. بعد از پایان زمان، گزارش ساخته می‌شود. اگر زودتر تمام کردی، همین دکمه را دوباره بزن.";$action.Text='پایان زودتر و ساخت نتیجه';$action.Enabled=$true
 } catch {
  try {if($script:captureOwned){RM-StopCapture}}catch{}
  if($script:running){Stop-Monitor};Set-SimpleError $_.Exception.Message
 } finally {$script:autoPreparing=$false;if($script:autoPhase -in @('Idle','Error')){$action.Enabled=$true;$compare.Enabled=$true;$progress.Style='Blocks'}}
})
$autoTimer=New-Object Windows.Forms.Timer;$autoTimer.Interval=500
$autoTimer.Add_Tick({
 try {
  if($script:autoPhase -eq 'Capturing') {
   $left=[Math]::Max(0,[int][Math]::Ceiling(($script:autoDeadline-[datetime]::UtcNow).TotalSeconds));$progress.Value=[Math]::Min(90,90-$left);$phaseLabel.Text=('در حال ضبط — {0} ثانیه باقی مانده؛ با برنامه کار کن.' -f $left)
   if(([datetime]::UtcNow-$script:autoLaunchedAt).TotalSeconds -gt 12 -and !(Test-Path -LiteralPath $script:autoLaunchStatus)){RM-StopCapture;Stop-Monitor;Set-SimpleError 'اجرای امن هدف تأیید نشد. ممکن است Explorer معمولی در دسترس نباشد یا حساب ادمین با حساب دسکتاپ متفاوت باشد. هدف با ادمین اجرا نشد. برای راه جایگزین، Start-Advanced.cmd را اجرا کن.';return}
   if($script:autoLaunchStatus -and (Test-Path -LiteralPath $script:autoLaunchStatus)) {
    try {$ld=Get-Content -LiteralPath $script:autoLaunchStatus -Raw | ConvertFrom-Json;if($ld.Phase -eq 'Failed'){RM-StopCapture;Stop-Monitor;Set-SimpleError ('اجرای هدف انجام نشد: '+$ld.Error);return}}catch{}
   }
   if(!$left){Start-AutoAnalysis}
  } elseif($script:autoPhase -eq 'Analyzing' -and [datetime]::UtcNow -gt $script:autoAnalysisDeadline){Set-SimpleError 'تحلیل بیش از حد طول کشید و متوقف شد. فایل ضبط حفظ شده است؛ از حالت فنی برای بررسی خطا استفاده کن.'}
  elseif($script:autoPhase -eq 'Analyzing' -and $script:autoAnalysis.HasExited) {
   $code=$script:autoAnalysis.ExitCode;$out=$script:autoStdout.GetAwaiter().GetResult();$err=$script:autoStderr.GetAwaiter().GetResult();$script:autoAnalysis.Dispose();$script:autoAnalysis=$null
   [IO.File]::WriteAllText($script:lastEvidence+'.console.txt',$out+[Environment]::NewLine+$err,(New-Object Text.UTF8Encoding($false)))
   if($code -ne 0 -or !(Test-Path -LiteralPath $script:lastEvidence)){Set-SimpleError ('ساخت گزارش به خطا خورد. پیام تحلیل:'+"`n"+$err);return}
   $d=Get-Content -LiteralPath $script:lastEvidence -Raw | ConvertFrom-Json
   # Keep raw capture/keys elsewhere; present a report-only sharing folder.
   $script:privateEvidence=$script:lastEvidence
   foreach($prop in @('Capture','AnalyzedCapture','Target')){if($d.PSObject.Properties[$prop] -and $d.$prop){$d.$prop=[IO.Path]::GetFileName($d.$prop)}}
   if($d.Normalization){foreach($prop in @('OriginalPath','EffectivePath')){if($d.Normalization.$prop){$d.Normalization.$prop=[IO.Path]::GetFileName($d.Normalization.$prop)}}}
   $share=Join-Path $root 'Reports-to-share';New-Item -ItemType Directory -Force -Path $share | Out-Null
   $script:lastEvidence=Join-Path $share ('NetworkReport-'+$script:session+'.evidence.json')
   $d | ConvertTo-Json -Depth 14 | Set-Content -LiteralPath $script:lastEvidence -Encoding UTF8
   Show-SimpleResult $d
  }
 } catch {Set-SimpleError $_.Exception.Message}
});$autoTimer.Start()
$form.Add_FormClosed({$autoTimer.Stop();$autoTimer.Dispose();if($script:autoAnalysis){try {if(!$script:autoAnalysis.HasExited){$script:autoAnalysis.Kill()}}catch{};$script:autoAnalysis.Dispose()}})
