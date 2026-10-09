. (Join-Path $PSScriptRoot 'Local-Log-Audit.ps1')
. (Join-Path $PSScriptRoot 'Build-Unified-Report.ps1')
# Single primary action. Core monitoring and capture continue on their existing workers.
$script:simpleMode=$true;$script:autoPreparing=$false;$script:autoPhase='Idle';$script:autoAnalysis=$null;$script:autoDeadline=[datetime]::MinValue
$top.Visible=$false;$bottom.Visible=$false;$tabs.Visible=$false;$alerts.Checked=$false
$form.Text='بررسی سادهٔ ارتباط برنامه — ۲٫۷';$form.Size=New-Object Drawing.Size(980,820);$area=[Windows.Forms.Screen]::PrimaryScreen.WorkingArea;$form.Size=New-Object Drawing.Size([Math]::Min(980,$area.Width-32),[Math]::Min(820,$area.Height-32));$form.MinimumSize=New-Object Drawing.Size([Math]::Min(900,$area.Width-32),[Math]::Min(680,$area.Height-32));$form.BackColor=[Drawing.Color]::White
$simple=New-Object Windows.Forms.TableLayoutPanel;$simple.Dock='Fill';$simple.Padding=New-Object Windows.Forms.Padding(28);$simple.AutoScroll=$true;$simple.ColumnCount=1;$simple.RowCount=8;$simple.BackColor=[Drawing.Color]::White
foreach($height in @(62,108,34,76,55,22)) {[void]$simple.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,$height)))}
[void]$simple.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Percent,100)));[void]$simple.RowStyles.Add((New-Object Windows.Forms.RowStyle([Windows.Forms.SizeType]::Absolute,44)))
$form.Controls.Add($simple);$simple.BringToFront()
function New-SimpleLabel($text,$size=12){$l=New-Object Windows.Forms.Label;$l.Text=$text;$l.Dock='Fill';$l.RightToLeft='Yes';$l.TextAlign='MiddleRight';$l.ForeColor=[Drawing.Color]::FromArgb(44,44,43);$l.Font=New-Object Drawing.Font('Segoe UI',$size);return $l}
$heading=New-SimpleLabel 'یک دکمه؛ مقصدها، دادهٔ خوانا و لاگ همان اجرا' 23;$simple.Controls.Add($heading,0,0)
$how=New-SimpleLabel "۱. برنامهٔ هدف را ببند؛ بعد دکمهٔ پایین را بزن و فایل EXE را انتخاب کن.`n۲. ابزارها در صورت نیاز با تأیید تو نصب می‌شوند و برنامهٔ هدف باز می‌شود.`n۳. حدود ۹۰ ثانیه با برنامه کار کن؛ نتیجه خودکار همین‌جا نمایش داده می‌شود." 12;$simple.Controls.Add($how,0,1)
$compare=New-Object Windows.Forms.CheckBox;$compare.Text='تطبیق محدود نام سیستم، نام کاربر و شناسه‌های محلی با دادهٔ قابل‌خواندن (اختیاری)';$compare.Checked=$false;$compare.Dock='Fill';$compare.RightToLeft='Yes';$compare.Font=New-Object Drawing.Font('Segoe UI',11);$compare.ForeColor=[Drawing.Color]::FromArgb(70,70,70);$simple.Controls.Add($compare,0,2)
$action=New-Object Windows.Forms.Button;$action.Text='شروع بررسی خودکار';$action.Dock='Fill';$action.FlatStyle='Flat';$action.BackColor=[Drawing.Color]::FromArgb(39,131,222);$action.ForeColor=[Drawing.Color]::White;$action.Font=New-Object Drawing.Font('Segoe UI',17,[Drawing.FontStyle]::Bold);$action.Margin=New-Object Windows.Forms.Padding(0,8,0,8);$simple.Controls.Add($action,0,3)
$phaseLabel=New-SimpleLabel 'آماده — قبل از شروع، فایل‌ها و کارهای باز برنامهٔ هدف را ذخیره کن.' 12;$simple.Controls.Add($phaseLabel,0,4)
$progress=New-Object Windows.Forms.ProgressBar;$progress.Dock='Fill';$progress.Maximum=90;$progress.Minimum=0;$simple.Controls.Add($progress,0,5)
$result=New-Object Windows.Forms.RichTextBox;$result.Dock='Fill';$result.ReadOnly=$true;$result.RightToLeft='Yes';$result.BackColor=[Drawing.Color]::FromArgb(249,248,247);$result.ForeColor=[Drawing.Color]::FromArgb(44,44,43);$result.Font=New-Object Drawing.Font('Segoe UI',12);$result.BorderStyle='FixedSingle';$result.Margin=New-Object Windows.Forms.Padding(0,16,0,8);$simple.Controls.Add($result,0,6)
$result.Text="نسخهٔ غیرفعال TLS: هیچ گواهی یا پروکسی اضافه نمی‌شود. مقصدها، شمارندهٔ رفت‌وبرگشت و شواهد خوانا بررسی می‌شوند؛ محتوای رمزگذاری‌شده نامعلوم می‌ماند.`n`nنتیجهٔ بررسی اینجا می‌آید.`n`nمهم: اتصال به یک سرور، به‌تنهایی ثابت نمی‌کند چه اطلاعاتی ارسال شده است. در این حالت محتوای HTTPS رمزگذاری‌شده نامعلوم می‌ماند."
$foot=New-Object Windows.Forms.Button;$foot.Text='باز کردن پوشه گزارش‌ها';$foot.Dock='Fill';$foot.FlatStyle='Flat';$foot.BackColor=[Drawing.Color]::White;$foot.ForeColor=[Drawing.Color]::FromArgb(39,100,160);$foot.Font=New-Object Drawing.Font('Segoe UI',11);$simple.Controls.Add($foot,0,7)
$foot.Add_Click({$share=Join-Path $root 'Reports-to-share';[void][IO.Directory]::CreateDirectory($share);Start-Process explorer.exe -ArgumentList ('"'+$share+'"')})
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
 $script:tlsFile='';$script:autoLaunchStatus=Join-Path $folder 'launcher-status.json'
 [ordered]@{Target=$script:target;TargetSHA256=$script:targetHash;Arguments=$evArgs.Text;KeyFile=$script:tlsFile;RequestTLSKeyLogging=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'Launch-Target.json') -Encoding UTF8
 foreach($f in @('Launch-Target.ps1','Launch-Target.cmd','TLS-Key-Status.ps1')){Copy-Item -LiteralPath (Join-Path $PSScriptRoot $f) -Destination (Join-Path $folder $f) -Force}
 return (Join-Path $folder 'Launch-Target.ps1')
}
function Start-AutoAnalysis {
 $script:logWindowEnd=[datetime]::UtcNow
 $phaseLabel.Text='در حال پایان ضبط و ساخت گزارش…';$action.Enabled=$false;$script:autoPhase='Stopping'
 RM-StopCapture;if($script:captureOwned){throw 'ضبط متوقف نشد؛ دوباره تلاش کنید یا متن خطا را بررسی کنید.'}
 Stop-Monitor
 if(!$script:capturePCAP -or !(Test-Path -LiteralPath $script:capturePCAP)){throw 'فایل ضبط تبدیل نشده است؛ پیام خطای تبدیل را بررسی کنید.'}
 $tshark=RM-FindWireshark;if(!$tshark){throw 'تحلیل‌گر tshark پیدا نشد.'}
 $context=$script:capturePCAP+'.analysis-context.json';Copy-Item -LiteralPath $script:captureContext -Destination $context -Force
 $script:lastEvidence=$script:capturePCAP+'.evidence.json'
 $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $PSScriptRoot 'Analyze-Capture.ps1')+'" -CapturePath "'+$script:capturePCAP+'" -ContextPath "'+$context+'" -OutputPath "'+$script:lastEvidence+'" -TsharkPath "'+$tshark+'" -LaunchStatusPath "'+$script:autoLaunchStatus+'"'
 if($compare.Checked){$args+=' -CompareLocalIdentifiers'}
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe';$info.Arguments=$args;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $script:autoAnalysis=New-Object Diagnostics.Process;$script:autoAnalysis.StartInfo=$info;[void]$script:autoAnalysis.Start()
 $script:autoStdout=$script:autoAnalysis.StandardOutput.ReadToEndAsync();$script:autoStderr=$script:autoAnalysis.StandardError.ReadToEndAsync()
 $script:autoAnalysisDeadline=[datetime]::UtcNow.AddMinutes(10);$script:autoPhase='Analyzing';$progress.Style='Marquee';$phaseLabel.Text='در حال تحلیل؛ لطفاً صبر کن…'
}
function Show-SimpleResult($d) {
 $n=$d.Network;$text="بررسی تمام شد — بدون گواهی و پروکسی.`n`n"
 if(!$n.CorrelatedOutboundFrames){$text+='شواهد خروجی هدف با این ضبط تطبیق داده نشد؛ نبود ارسال اثبات نشده است.'+"`n"}
 else{$text+='مقصدهای خروجی با زمان و tuple تطبیق داده شدند؛ انتساب قطعی کرنلی نیست.'+"`n"}
 $text+="`n۱. چیزهایی که در دادهٔ خروجی خوانا دیده شدند:`n"
 $fields=@($d.EvidenceLevels.ReadableOutgoingFieldNameIndicators);$ids=@($d.EvidenceLevels.ReadableOutgoingIdentifierHints)
 if($fields.Count){$text+='نام فیلدهای نیازمند بررسی: '+($fields -join '، ')+"`nمقدار واقعی از نام فیلد به‌تنهایی معلوم نیست.`n"}else{$text+="فیلد سیستمیِ خوانای قابل‌تشخیص ثبت نشد؛ این نتیجه نبود ارسال نیست.`n"}
 if($ids.Count){$text+='تطبیق رشته با شناسه محلی: '+($ids -join '، ')+"`nاین صرفاً نشانه است، نه اثبات سرقت یا نیت.`n"}
 $text+="`n۲. فقط در لاگ محلی همین اجرا دیده شد:`n"
 $locals=@($d.EvidenceLevels.LocalLogOnlyCategories)
 if($locals.Count){$text+=($locals -join '، ')+"`nثبت محلی این موارد، ارسال آن‌ها را ثابت نمی‌کند.`n"}else{$text+="موردی در قالب پشتیبانی‌شده و بازه همین اجرا پیدا نشد؛ لاگ ممکن است نبود یا قابل‌بررسی نبود.`n"}
 $text+="`n۳. مقصدها و میزان قابل مشاهده:`n"
 foreach($g in ($d.Destinations|Sort-Object ObservedOutboundTransportPayloadBytes -Descending|Select-Object -First 12)){
  $name=if(@($g.Names).Count){$g.Names -join ', '}else{$g.IP}
  $visibility=if($g.Visibility -like 'Some outgoing*'){'بخشی خوانا'}else{'محتوا نامعلوم'}
  $text+=('{0}:{1} — {2} — خروجی {3} / ورودی {4} بایت مشاهده‌شده' -f $name,$g.Port,$visibility,$g.ObservedOutboundTransportPayloadBytes,$g.ObservedInboundTransportPayloadBytes)+"`n"
 }
 $text+="این بایت‌ها طول مشاهده‌شدهٔ payload ترابری‌اند، شامل سربار TLS و احتمال تکرار؛ نه حجم خالص اطلاعات شخصی.`n"
 if(@($d.Destinations).Count -gt 12){$text+="بقیه مقصدها در گزارش هستند.`n"}
 if($n.QuarantinedPacketCount -gt 0){$text+="`nهشدار تحلیل‌گر: بسته‌های نام‌برده کنار گذاشته شدند؛ گزارش partial است.`n"}
 if($n.LauncherDiagnostic -and !$n.LauncherDiagnostic.Success){$text+="اجرای هدف تأیید نشده؛ لاگ خصوصی launcher را بررسی کن.`n"}
 $text+="`nهیچ راهی در این حالت محتوای TLS رمزگذاری‌شده را آشکار نمی‌کند.`nفقط فایل زیر را پس از بازبینی بفرست:`n"+[IO.Path]::GetFileName($script:lastEvidence)
 $result.Text=$text;$phaseLabel.Text='تمام شد — گزارش یکپارچه ساخته شد';$progress.Style='Blocks';$progress.Value=90;$script:autoPhase='Done';$action.Text='شروع بررسی تازه';$action.Enabled=$true;$compare.Enabled=$true
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
  if([Windows.Forms.MessageBox]::Show("این بررسی برنامهٔ انتخاب‌شده را با دسترسی معمولی اجرا می‌کند، حدود ۹۰ ثانیه ترافیک کل سیستم را محلی ضبط می‌کند و تغییرات لاگ‌های شناخته‌شده در پوشه Logs کنار EXE را در همین بازه می‌خواند. ضبط ممکن است حساس باشد؛ مقدارهای لاگ داخل گزارش نوشته نمی‌شوند. هیچ کلید TLS درخواست نمی‌شود. هیچ داده‌ای آپلود نمی‌شود، گواهی/فایروال تغییر نمی‌کند و کلیدی از حافظه استخراج نمی‌شود. ادامه می‌دهی؟",'تأیید بررسی محلی','YesNo','Warning') -ne 'Yes'){$script:autoPhase='Idle';return}
  $phaseLabel.Text='آماده‌سازی ابزارها…';$result.Text='اگر ابزار لازم نصب نباشد، تأیید مجوز/نصب نشان داده می‌شود. بعد از آماده‌سازی، ادامهٔ بررسی خودکار است.';$progress.Style='Marquee'
  if(!(RM-InstallWireshark)){throw 'تحلیل‌گر آماده نشد یا نصب آن لغو شد.'}
  if($script:running){Stop-Monitor};Start-MonitorSession;if(!$script:running){throw 'شروع مانیتور انجام نشد. پیام نمایش‌داده‌شده را بررسی کن.'}
  $script:logBaseline=Get-RM27LogBaseline $script:target;$script:logWindowStart=[datetime]::UtcNow
  Start-RMPacketCapture -ConsentAlreadyGiven;if(!$script:captureOwned){throw 'شروع ضبط انجام نشد؛ پیام خطا را بررسی کن.'}
  $launcher=New-AutoLaunchFiles;Invoke-DesktopLaunch $launcher
  $script:autoLaunchedAt=[datetime]::UtcNow;$script:autoDeadline=[datetime]::UtcNow.AddSeconds(90);$script:autoPhase='Capturing';$progress.Style='Blocks';$progress.Value=0;$phaseLabel.Text='برنامه باز می‌شود؛ طی ۹۰ ثانیه با آن کار کن.';$result.Text="در برنامهٔ هدف، فعالیت آنلاین موردنظر را انجام بده.`n`nضبط، شمارندهٔ شبکه و بررسی محدود لاگ همان اجرا خودکار است. بعد از پایان زمان، گزارش ساخته می‌شود. اگر زودتر تمام کردی، همین دکمه را دوباره بزن.";$action.Text='پایان زودتر و ساخت نتیجه';$action.Enabled=$true
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
   $script:privateEvidence=$script:lastEvidence
   $localAudit=$null
   try{$localAudit=Complete-RM27LogAudit $script:logBaseline $script:logWindowStart $script:logWindowEnd}catch{$localAudit=[pscustomobject]@{LocalFieldCategories=@();RecordedEvents=@();Assessment='Local log audit failed; no conclusion';Logs=@()}}
   $d=ConvertTo-RM27Unified $d $localAudit
   $share=Join-Path $root 'Reports-to-share';New-Item -ItemType Directory -Force -Path $share | Out-Null
   $script:lastEvidence=Join-Path $share ('UnifiedReport-'+$script:session+'.json')
   $d|ConvertTo-Json -Depth 18|Set-Content -LiteralPath $script:lastEvidence -Encoding UTF8
   Show-SimpleResult $d
  }
 } catch {Set-SimpleError $_.Exception.Message}
});$autoTimer.Start()
$form.Add_FormClosed({$autoTimer.Stop();$autoTimer.Dispose();if($script:autoAnalysis){try {if(!$script:autoAnalysis.HasExited){$script:autoAnalysis.Kill()}}catch{};$script:autoAnalysis.Dispose()}})
