#requires -Version 5.1
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
if(-not ('RMProxyProbe25' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'Proxy-Probe.cs')}
$script:probe=$null;$script:child=$null;$script:active=$false;$script:targetPath=$null;$script:rootPid=0;$script:samples=@();$script:sampleErrors=0;$script:nextSample=[datetime]::MinValue
$f=New-Object Windows.Forms.Form;$f.Text='آزمون عبور از پروکسی — بدون گواهی — ۲٫۵٫۱';$f.Size=New-Object Drawing.Size(900,710);$f.MinimumSize=New-Object Drawing.Size(760,580);$f.StartPosition='CenterScreen';$f.Font=New-Object Drawing.Font('Segoe UI',11);$f.RightToLeft='Yes'
$p=New-Object Windows.Forms.TableLayoutPanel;$p.Dock='Fill';$p.Padding=New-Object Windows.Forms.Padding(24);$p.ColumnCount=1;$p.RowCount=5
foreach($h in @(128,64,38,38)){[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',$h)))};[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)));$f.Controls.Add($p)
$l=New-Object Windows.Forms.Label;$l.Dock='Fill';$l.Text="۱. بازی را کامل ببند؛ دکمه را بزن و همان EXE را انتخاب کن.`n۲. بازی با دسترسی معمولی باز می‌شود؛ حدود ۹۰ ثانیه فعالیت آنلاین انجام بده.`n۳. اگر آنلاین شدن موفق بود، تیک پایین را بزن. پایان آزمون، اتصال‌های پروکسی بسته می‌شوند؛ بازی را خودت ببند و بعد معمولی باز کن.`nهیچ گواهی نصب یا تنظیم پروکسی ویندوز تغییر نمی‌کند؛ محتوای TLS خوانده نمی‌شود.";$p.Controls.Add($l,0,0)
$b=New-Object Windows.Forms.Button;$b.Dock='Fill';$b.Text='شروع آزمون پروکسی';$b.BackColor=[Drawing.Color]::FromArgb(39,131,222);$b.ForeColor=[Drawing.Color]::White;$b.FlatStyle='Flat';$b.Font=New-Object Drawing.Font('Segoe UI',14,[Drawing.FontStyle]::Bold);$p.Controls.Add($b,0,1)
$worked=New-Object Windows.Forms.CheckBox;$worked.Dock='Fill';$worked.Text='در همین آزمون، ورود یا فعالیت آنلاین بازی موفق بود';$worked.Enabled=$false;$p.Controls.Add($worked,0,2)
$status=New-Object Windows.Forms.Label;$status.Dock='Fill';$status.Text='آماده — با دوبار کلیک معمولی اجرا کن، نه با ادمین.';$p.Controls.Add($status,0,3)
$r=New-Object Windows.Forms.RichTextBox;$r.Dock='Fill';$r.ReadOnly=$true;$r.RightToLeft='Yes';$r.BackColor=[Drawing.Color]::FromArgb(249,248,247);$r.Text="این آزمون فقط HTTP_PROXY و HTTPS_PROXY را برای اجرای تازه همان برنامه تنظیم می‌کند؛ برخی برنامه‌های ویندوز آن‌ها را نادیده می‌گیرند. نتیجه منفی، ناسازگاری با همه روش‌های پروکسی را ثابت نمی‌کند.`n`nفقط مقصد و شمارنده بایت‌ها ثبت می‌شوند؛ متن درخواست، مسیر URL، توکن، بدنه و کلید ذخیره نمی‌شود. مقصدها و هش فایل نیز ممکن است حساس باشند؛ قبل از ارسال گزارش بازبینی کن.";$p.Controls.Add($r,0,4)
function Save-ProxyResult([string]$reason) {
 if(!$script:active){return};$script:active=$false;$timer.Stop();$b.Enabled=$false
 $script:probe.Stop();$rows=@($script:probe.Snapshot()|ForEach-Object {[ordered]@{TimeUTC=$_.TimeUTC;Host=$_.Host;Port=$_.Port;Method=$_.Method;ClientPID=$_.ClientPID;Outcome=$_.Outcome;BytesToServer=$_.BytesToServer;BytesFromServer=$_.BytesFromServer}})
 $relays=@($rows|Where-Object {$_.Outcome -like 'Relay established*'});$tls=@($relays|Where-Object {$_.Method -eq 'CONNECT'});$withData=@($tls|Where-Object {$_.BytesToServer -gt 0 -and $_.BytesFromServer -gt 0})
 $assessment='No attributed proxy request observed; environment-variable test is inconclusive'
 if($rows.Count){$assessment='Target used the local proxy, but successful relay not established'}
 if($relays.Count){$assessment='Target established a proxy relay; TLS certificate interception compatibility NOT tested'}
 if($withData.Count){$assessment='Bidirectional CONNECT tunnel bytes observed; TLS content, certificate interception acceptance and application success NOT established by this alone'}
 $doc=[ordered]@{Version='2.5';ReportKind='ProxyCompatibilityProbe';Target=[IO.Path]::GetFileName($script:targetPath);TargetSHA256=$script:targetHash;GeneratedUTC=[datetime]::UtcNow.ToString('o');StartedUTC=$script:started.ToString('o');EndedBy=$reason;LaunchedPID=$script:rootPid;LaunchedAsAdministrator=$false;EnvironmentVariableNames=@('HTTP_PROXY','HTTPS_PROXY','NO_PROXY');Scope='Per-process environment variables; Windows, WinHTTP and browser proxy settings unchanged';Listener='IPv4 loopback only';ListenerPort=$script:probe.ListenPort;UserReportedOnlineSuccess=[bool]$worked.Checked;CertificateInstalled=$false;TLSIntercepted=$false;PayloadStored=$false;Assessment=$assessment;ProxyRequestCount=$rows.Count;RelayEstablishedCount=$relays.Count;BidirectionalConnectTunnelCount=$withData.Count;PIDLookupFailures=$script:probe.PIDLookupFailures;RejectedOtherProcesses=$script:probe.RejectedOtherProcesses;OverloadRejections=$script:probe.OverloadRejections;MetadataLimitRejections=$script:probe.MetadataLimitRejections;PendingTasksAtReport=$script:probe.PendingTasks;SampleReadErrors=$script:sampleErrors;ObservedTargetTCPTuples=$script:samples;Events=$rows;Limitations=@('At most 32 concurrent requests and 2048 recorded requests; excess requests are closed, not forwarded.','Only requests attributed to an EXE with the exact selected path are forwarded; different child EXEs are excluded.','Only IPv4 loopback client connections and destination ports 80, 443, 1119 are supported; private/link-local destinations are blocked.','TCP sampling is snapshots of the launched PID only; short flows, UDP, child processes and replaced PIDs may be missed.','No proxy use is not proof that other supported Windows proxy methods cannot work.','CONNECT is a byte tunnel, not proof of TLS handshake or MITM certificate acceptance. No TLS decryption is attempted.','Plain HTTP forwarding is limited to one request per connection; this is a bounded diagnostic relay, not a general-purpose production proxy.','Destination DNS lookups and network connections are made locally as part of the test. No report is uploaded.','Stopping closes proxy sockets, does not kill the target; restart the target normally to remove its test environment.','HTTP paths, headers and payload pass only in memory for relay, are not included in report. Destination hostnames, IPs, timestamps and file hash may be sensitive.')}
 $out=Join-Path $PSScriptRoot ('Reports-to-share\ProxyTest-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6)+'.json');[void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($out));$doc|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $out -Encoding UTF8
 $message='در این روش، درخواست پروکسی منتسب به هدف دیده نشد؛ ممکن است بازی متغیرهای محیطی پروکسی را نادیده بگیرد.'
 if($rows.Count){$message='درخواست پروکسی از فایل هدف دیده شد؛ نتیجه مسیر در گزارش ثبت شد.'}
 if($relays.Count){$message='عبور ارتباط از پروکسی مشاهده شد. پذیرش گواهی آزمایشی و خواندن محتوای TLS هنوز بررسی نشده است.'}
 if($script:probe.PIDLookupFailures -gt 0){$message+=' انتساب بخشی از اتصال‌های محلی ناموفق بود؛ نتیجه منفی قابل اتکا نیست.'}
 $r.Text=$message+"`n`nهیچ گواهی نصب نشده و محتوای TLS رمزگشایی نشده است.`nبازی را خودت ببند و برای استفاده عادی دوباره باز کن.`n`nفقط این گزارش را پس از بازبینی بفرست:`n"+[IO.Path]::GetFileName($out);$status.Text='آزمون تمام شد؛ بازی خودکار بسته نمی‌شود.';$b.Text='شروع آزمون تازه';$b.Enabled=$true;$worked.Enabled=$false
 $script:probe.Dispose();$script:probe=$null;if($script:child){$script:child.Dispose();$script:child=$null}
 if($reason -ne 'WindowClosed'){Start-Process explorer.exe -ArgumentList ('/select,"'+$out+'"')}
}
$timer=New-Object Windows.Forms.Timer;$timer.Interval=1000
$timer.Add_Tick({
 try{
  $left=[Math]::Max(0,[int][Math]::Ceiling(($script:deadline-[datetime]::UtcNow).TotalSeconds));$status.Text="در حال آزمون — $left ثانیه باقی مانده"
  if([datetime]::UtcNow -ge $script:nextSample){$script:nextSample=[datetime]::UtcNow.AddSeconds(5);try{
   $connections=@(Get-NetTCPConnection -OwningProcess $script:rootPid -ErrorAction Stop|Where-Object {$_.State -eq 'Established'})
   foreach($c in $connections){if(!@($script:samples|Where-Object {$_.RemoteIP -eq $c.RemoteAddress -and $_.RemotePort -eq $c.RemotePort -and $_.LocalPort -eq $c.LocalPort}).Count){$script:samples+=[ordered]@{TimeUTC=[datetime]::UtcNow.ToString('o');RemoteIP=$c.RemoteAddress;RemotePort=$c.RemotePort;LocalPort=$c.LocalPort}}}
  }catch{$script:sampleErrors++}}
  if(!$left){Save-ProxyResult 'Timer'}
 }catch{try{Save-ProxyResult 'Error'}catch{};$r.Text='خطا در آزمون؛ بازی خودکار بسته نمی‌شود. '+$_.Exception.Message}
})
$b.Add_Click({
 if($script:active){try{Save-ProxyResult 'UserStopped'}catch{$r.Text='خطا در ذخیره گزارش: '+$_.Exception.Message;$b.Enabled=$true};return}
 $b.Enabled=$false
 try{
  $identity=[Security.Principal.WindowsIdentity]::GetCurrent();$principal=New-Object Security.Principal.WindowsPrincipal($identity)
  if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'این آزمون را با دوبار کلیک معمولی اجرا کن، نه Run as administrator. بازی با ادمین اجرا نمی‌شود.'}
  $pick=New-Object Windows.Forms.OpenFileDialog;$pick.Filter='EXE (*.exe)|*.exe';$pick.Title='فایل هدف را انتخاب کن';if($pick.ShowDialog() -ne 'OK'){$pick.Dispose();return};$script:targetPath=$pick.FileName;$pick.Dispose()
  $existing=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ExecutablePath -and [string]::Equals($_.ExecutablePath,$script:targetPath,[StringComparison]::OrdinalIgnoreCase)})
  if($existing.Count){throw 'بازی باز است؛ آن را خودت کامل ببند و دوباره امتحان کن.'}
  if([Windows.Forms.MessageBox]::Show('این آزمون بازی را با متغیرهای پروکسی مخصوص همین اجرا باز می‌کند. ممکن است ورود آنلاین مختل شود. هیچ گواهی نصب نمی‌شود و تنظیم پروکسی ویندوز تغییر نمی‌کند. پایان آزمون، اتصال‌های پروکسی قطع می‌شوند؛ بازی را خودت ببند و دوباره معمولی باز کن. ادامه می‌دهی؟','تأیید آزمون محدود','YesNo','Warning') -ne 'Yes'){return}
  $script:targetHash=(Get-FileHash -LiteralPath $script:targetPath -Algorithm SHA256).Hash
  $script:probe=New-Object RMProxyProbe25;$script:probe.Start($script:targetPath)
  $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$script:targetPath;$info.WorkingDirectory=[IO.Path]::GetDirectoryName($script:targetPath);$info.UseShellExecute=$false
  $proxy='http://127.0.0.1:'+$script:probe.ListenPort;$info.EnvironmentVariables['HTTP_PROXY']=$proxy;$info.EnvironmentVariables['HTTPS_PROXY']=$proxy;$info.EnvironmentVariables['NO_PROXY']=''
  $script:child=[Diagnostics.Process]::Start($info);$script:rootPid=$script:child.Id;$script:samples=@();$script:sampleErrors=0;$script:started=[datetime]::UtcNow;$script:deadline=$script:started.AddSeconds(90);$script:nextSample=$script:started;$script:active=$true;$worked.Checked=$false;$worked.Enabled=$true;$timer.Start();$b.Text='پایان آزمون و ساخت گزارش';$r.Text='با بازی فعالیت آنلاین انجام بده. اگر موفق بود تیک مربوط را بزن. پروکسی فقط مقصد و شمارنده بایت ثبت می‌کند، نه محتوای ارسالی.'
 }catch{if($script:probe){$script:probe.Dispose();$script:probe=$null};$r.Text='آزمون شروع نشد: '+$_.Exception.Message}finally{$b.Enabled=$true}
})
$f.Add_FormClosing({if($script:active){try{Save-ProxyResult 'WindowClosed'}catch{if($script:probe){$script:probe.Dispose()}}}})
$f.ShowInTaskbar=$true
$f.Add_Shown({$f.Activate();$f.BringToFront();if(Get-Command Set-ProxyStartupStatus -ErrorAction SilentlyContinue){Set-ProxyStartupStatus 'Ready'}})
[void]$f.ShowDialog();$timer.Stop();$timer.Dispose();if($script:probe){$script:probe.Dispose()};$f.Dispose()
