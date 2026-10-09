$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Windows.Forms,System.Drawing
. (Join-Path $PSScriptRoot 'TLS-Cleanup.ps1')
Invoke-TLSRecover
$script:tlsActive=$false;$script:tlsSession=$null;$script:tlsProxy=$null;$script:tlsGuard=$null;$script:tlsGame=$null;$script:tlsThumb=$null;$script:tlsCertAdded=$false;$script:tlsCertVerified=$false
$f=New-Object Windows.Forms.Form;$f.Text='بررسی محدود تله‌متری — گواهی موقت — ۲٫۶';$f.Size=New-Object Drawing.Size(950,760);$f.MinimumSize=New-Object Drawing.Size(780,620);$f.StartPosition='CenterScreen';$f.RightToLeft='Yes';$f.Font=New-Object Drawing.Font('Segoe UI',11)
$p=New-Object Windows.Forms.TableLayoutPanel;$p.Dock='Fill';$p.Padding=New-Object Windows.Forms.Padding(24);$p.ColumnCount=1;$p.RowCount=5
foreach($h in @(135,42,65,40)){[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',$h)))};[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)));$f.Controls.Add($p)
$l=New-Object Windows.Forms.Label;$l.Dock='Fill';$l.Text="۱. بازی را ببند و فایل EXE را انتخاب کن.`n۲. قبل از نصب گواهی، تأیید جداگانه با اثرانگشت گواهی نمایش داده می‌شود.`n۳. با بازی ۹۰ ثانیه کار کن؛ درخواست ورود حساب رمزگشایی نمی‌شود.`nمهم: اعتماد گواهی در حساب ویندوز محدود به یک دامنه نیست؛ محدودیت تله‌متری فقط در پروکسی اعمال می‌شود. بعد از آزمون، حذف گواهی بررسی می‌شود.";$p.Controls.Add($l,0,0)
$compare=New-Object Windows.Forms.CheckBox;$compare.Dock='Fill';$compare.Text='تطبیق دقیق و محدود با نام سیستم، کاربر، نسخه OS، CPU و GPU (اختیاری)';$p.Controls.Add($compare,0,1)
$b=New-Object Windows.Forms.Button;$b.Dock='Fill';$b.Text='شروع بررسی تله‌متری';$b.BackColor=[Drawing.Color]::FromArgb(39,131,222);$b.ForeColor=[Drawing.Color]::White;$b.FlatStyle='Flat';$p.Controls.Add($b,0,2)
$status=New-Object Windows.Forms.Label;$status.Dock='Fill';$status.Text='آماده — فقط اجرای معمولی، بدون ادمین';$p.Controls.Add($status,0,3)
$r=New-Object Windows.Forms.RichTextBox;$r.Dock='Fill';$r.ReadOnly=$true;$r.RightToLeft='Yes';$r.BackColor=[Drawing.Color]::FromArgb(249,248,247);$r.Text="فقط telemetry-in.battle.net:443 بازرسی می‌شود. سایر دامنه‌ها و ارتباط ورود حساب به‌صورت تونل بدون رمزگشایی عبور می‌کنند.`n`nگزارش فقط دستهٔ فیلدها، تطبیق‌های اختیاری و وضعیت درخواست‌هاست؛ مقدارها، توکن، بدنه، URL و کلید ذخیره نمی‌شوند. داده باینری/قالب ناشناخته ممکن است قابل تفسیر نباشد.`n`nاگر برنامه TLS را رد کند، آزمون متوقف می‌شود؛ هیچ حفاظت برنامه دور زده نمی‌شود. حذف خودکار پس از خاموشی یا بسته‌شدن هم‌زمان ابزار و محافظ تضمین‌شده نیست؛ در این حالت Cleanup-TLS.cmd را اجرا کن.";$p.Controls.Add($r,0,4)
function Read-TelemetrySummary {
 $path=Join-Path $script:tlsSession 'summary.json';if(Test-Path -LiteralPath $path){return (Get-Content -LiteralPath $path -Raw|ConvertFrom-Json)};return $null
}
function Stop-TelemetryTest([string]$reason){
 if(!$script:tlsSession){return};$timer.Stop();$script:tlsActive=$false;$b.Enabled=$false
 $summary=Read-TelemetrySummary;$cleanup=$null
 if(Test-Path -LiteralPath (Join-Path $script:tlsSession 'lease.json')){$cleanup=Invoke-TLSCleanup $script:tlsSession}
 else{if($script:tlsProxy -and !$script:tlsProxy.HasExited){$kill=Start-Process (Join-Path $env:WINDIR 'System32\taskkill.exe') -ArgumentList ('/PID '+$script:tlsProxy.Id+' /T /F') -WindowStyle Hidden -PassThru -Wait;$kill.Dispose()};foreach($name in @('ca','identifiers.json')){$item=Join-Path $script:tlsSession $name;if(Test-Path -LiteralPath $item){Remove-Item -LiteralPath $item -Recurse -Force}}}
 if($script:tlsCertAdded){
  $requests=if($summary){@($summary.Requests)}else{@()}
  $doc=[ordered]@{Version='2.6';ReportKind='ScopedTelemetryTLSInspection';Target=[IO.Path]::GetFileName($script:tlsTarget);TargetSHA256=$script:tlsHash;GeneratedUTC=[datetime]::UtcNow.ToString('o');EndedBy=$reason;ScopeHost='telemetry-in.battle.net';CertificateThumbprint=$script:tlsThumb;CertificateImportAttempted=$script:tlsCertAdded;CertificateInstalledDuringTest=$script:tlsCertVerified;Cleanup=$cleanup;LocalIdentifierComparisonEnabled=[bool]$compare.Checked;DecryptedHTTPRequestsObserved=$requests.Count;Summary=$summary;Limitations=@('CA trust in CurrentUser Root is broad; domain scope is enforced by proxy rules, not the CA store.','Only HTTP telemetry on the named host is inspected. Other domains, direct connections and proprietary game protocol are not decoded.','Requests are observed before forwarding; a request record alone does not prove server receipt. ResponseStatus is recorded when a response is observed.','Only allowlisted field-name categories and exact optional local identifier matches are reported; no values. Unknown names, nested encodings and binary formats may remain unknown.','Field categories alone do not prove their values describe this system. No matches or no decoded requests are not proof of no system information transmission.','TLS handshake failure may be certificate rejection or another incompatibility; pinning is not diagnosed or bypassed.','Shutdown can prevent both processes from running cleanup; use Cleanup-TLS.cmd after restarting. Certificate removal is reported, not assumed.')}
  $folder=Join-Path $PSScriptRoot 'Reports-to-share';[void][IO.Directory]::CreateDirectory($folder);$out=Join-Path $folder ('TelemetryReport-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6)+'.json');$doc|ConvertTo-Json -Depth 12|Set-Content -LiteralPath $out -Encoding UTF8
  $text='آزمون تمام شد.'
  if($summary -and $summary.ClientTLSFailures -gt 0){$text='دست‌دهی TLS سمت برنامه ناموفق بود؛ آزمون متوقف شد. علت قطعی رد گواهی یا pinning از این نتیجه معلوم نیست.'}
  elseif($summary -and $summary.ServerTLSFailures -gt 0){$text='TLS سمت سرور ناموفق بود؛ اعتبارسنجی سرور غیرفعال نشد و آزمون متوقف شد.'}
  elseif($requests.Count){$text='درخواست HTTP تله‌متری در پروکسی خوانده شد؛ دستهٔ فیلدها در گزارش است، نه مقدارهای خصوصی.'}
  else{$text='درخواست قابل‌خواندن تله‌متری ثبت نشد؛ نتیجه به معنی نبود ارسال نیست.'}
  if(!$cleanup -or !$cleanup.CertificateAbsent -or !$cleanup.ProxyStopped){$text+="`nهشدار: پاک‌سازی کامل تأیید نشد! Cleanup-TLS.cmd را اجرا کن."}else{$text+="`nگواهی آزمایشی دیگر در CurrentUser Root نیست و پروکسی متوقف شده است."}
  $r.Text=$text+"`n`nبازی را خودت ببند و دوباره معمولی اجرا کن.`nفقط گزارش زیر را پس از بازبینی بفرست:`n"+[IO.Path]::GetFileName($out)
  if($reason -ne 'WindowClosed'){Start-Process explorer.exe -ArgumentList ('/select,"'+$out+'"')}
 }
 if($cleanup -and (!$cleanup.CertificateAbsent -or !$cleanup.ProxyStopped)){$b.Enabled=$true;throw 'پاک‌سازی کامل تأیید نشد؛ تا حذف گواهی و توقف پروکسی، آزمون تازه شروع نکن. Cleanup-TLS.cmd را اجرا کن.'}
 $script:tlsSession=$null;$script:tlsCertAdded=$false;$script:tlsCertVerified=$false;$b.Text='شروع بررسی تازه';$b.Enabled=$true;$compare.Enabled=$true;$status.Text='پایان آزمون — بازی خودکار بسته نمی‌شود'
 foreach($name in @('tlsProxy','tlsGame','tlsGuard')){$proc=Get-Variable -Scope Script -Name $name -ValueOnly;if($proc){$proc.Dispose();Set-Variable -Scope Script -Name $name -Value $null}}
}
$timer=New-Object Windows.Forms.Timer;$timer.Interval=1000
$timer.Add_Tick({try{
 $left=[Math]::Max(0,[int][Math]::Ceiling(($script:tlsDeadline-[datetime]::UtcNow).TotalSeconds));$status.Text="در حال بررسی محدود — $left ثانیه باقی مانده"
 $s=Read-TelemetrySummary
 if($s -and ($s.ClientTLSFailures -gt 0 -or $s.ServerTLSFailures -gt 0)){Stop-TelemetryTest 'TLSFailure';return}
 if($script:tlsProxy.HasExited -or $script:tlsGuard.HasExited){Stop-TelemetryTest 'ProxyOrGuardExited';return}
 if(!$left){Stop-TelemetryTest 'Timer'}
}catch{$message=$_.Exception.Message;try{Stop-TelemetryTest 'Error'}catch{};$r.Text='خطا در آزمون/پاک‌سازی: '+$message+"`nCleanup-TLS.cmd را اجرا کن."}})
$b.Add_Click({
 if($script:tlsActive){try{Stop-TelemetryTest 'UserStopped'}catch{$r.Text='پاک‌سازی ناموفق: '+$_.Exception.Message+"`nCleanup-TLS.cmd را اجرا کن."};return}
 $b.Enabled=$false;$compare.Enabled=$false
 try{
  if($script:tlsSession){Stop-TelemetryTest 'CleanupRetry'}
  $id=[Security.Principal.WindowsIdentity]::GetCurrent();$pr=New-Object Security.Principal.WindowsPrincipal($id);if($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'این آزمون نباید با ادمین اجرا شود.'}
  $pick=New-Object Windows.Forms.OpenFileDialog;$pick.Filter='EXE (*.exe)|*.exe';if($pick.ShowDialog() -ne 'OK'){$pick.Dispose();return};$script:tlsTarget=$pick.FileName;$pick.Dispose()
  $open=@(Get-CimInstance Win32_Process -ErrorAction Stop|Where-Object {$_.ExecutablePath -and [string]::Equals($_.ExecutablePath,$script:tlsTarget,[StringComparison]::OrdinalIgnoreCase)});if($open.Count){throw 'بازی باز است؛ خودت آن را ببند و دوباره شروع کن.'}
  $exe=Join-Path $PSScriptRoot 'tools\mitmproxy\mitmdump.exe';if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne '36A45AADEB842185B8064B8F0BE3730E079C9F9C125BC8BE22363332969857BF'){throw 'هش ابزار رسمی تطبیق ندارد؛ فایل تغییر کرده یا ناقص است.'}
  $script:tlsHash=(Get-FileHash -LiteralPath $script:tlsTarget -Algorithm SHA256).Hash
  $base=Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor\TLS-Sessions';$script:tlsSession=Join-Path $base ([guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($script:tlsSession)
  $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @($id.User,(New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))){$rule=New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)}
  Set-Acl -LiteralPath $script:tlsSession -AclObject $acl
  $ca=Join-Path $script:tlsSession 'ca';$summaryPath=Join-Path $script:tlsSession 'summary.json'
  $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0);$listener.Start();$port=$listener.LocalEndpoint.Port;$listener.Stop()
  $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$exe;$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  $args=@('-q','--mode','regular','--listen-host','127.0.0.1','--listen-port',[string]$port,'--set',('confdir='+$ca),'--set','allow_hosts=(?i)^telemetry-in[.]battle[.]net:443$','--set','ssl_insecure=false','--set','upstream_cert=false','--set','connection_strategy=lazy','--set','flow_detail=0','--set','body_size_limit=2m','-s',(Join-Path $PSScriptRoot 'Telemetry-Fields.py'))
  $info.Arguments=($args|ForEach-Object {'"'+$_+'"'}) -join ' '
  $info.EnvironmentVariables['ERM_TLS_SUMMARY']=$summaryPath;$info.EnvironmentVariables['ERM_TLS_TARGET']=$script:tlsTarget;$info.EnvironmentVariables['ERM_TLS_PORT']=[string]$port
  $info.EnvironmentVariables.Remove('SSLKEYLOGFILE');$info.EnvironmentVariables.Remove('MITMPROXY_SSLKEYLOGFILE')
  if($compare.Checked){
   $cpu=@(Get-CimInstance Win32_Processor|Select-Object -First 1);$gpu=@(Get-CimInstance Win32_VideoController|Select-Object -First 1)
   $identifiers=[ordered]@{ComputerName=$env:COMPUTERNAME;WindowsUser=$env:USERNAME;OSVersion=(Get-CimInstance Win32_OperatingSystem).Version;CPUModel=if($cpu.Count){$cpu[0].Name}else{''};GPUModel=if($gpu.Count){$gpu[0].Name}else{''}}
   $idsPath=Join-Path $script:tlsSession 'identifiers.json';$identifiers|ConvertTo-Json|Set-Content -LiteralPath $idsPath -Encoding UTF8;$info.EnvironmentVariables['ERM_TLS_IDS']=$idsPath
  }else{$info.EnvironmentVariables.Remove('ERM_TLS_IDS')}
  $status.Text='آماده‌سازی ابزار قابل‌حمل؛ بار اول ممکن است تا ۹۰ ثانیه طول بکشد…';$f.Refresh()
  $script:tlsProxy=[Diagnostics.Process]::Start($info);$script:tlsProxy.BeginOutputReadLine();$script:tlsProxy.BeginErrorReadLine()
  $until=[datetime]::UtcNow.AddSeconds(90);$certPath=Join-Path $ca 'mitmproxy-ca-cert.cer';$ready=$false
  do{Start-Sleep -Milliseconds 300;if($script:tlsProxy.HasExited){throw 'ابزار TLS پیش از آماده‌شدن بسته شد. فایل‌ها یا تنظیمات ابزار را بررسی کن.'};if((Test-Path -LiteralPath $certPath) -and (Test-Path -LiteralPath $summaryPath)){$s=Read-TelemetrySummary;$ready=[bool]$s.Ready}}while(!$ready -and [datetime]::UtcNow -lt $until)
  if(!$ready){throw 'آماده‌شدن ابزار در ۹۰ ثانیه تأیید نشد.'}
  $pem=Get-Content -LiteralPath $certPath -Raw;$match=[regex]::Match($pem,'-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----');if(!$match.Success){throw 'قالب گواهی قابل تأیید نیست.'}
  $der=[Convert]::FromBase64String($match.Groups[1].Value);$cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$der)
  $basic=@($cert.Extensions|Where-Object {$_.Oid.Value -eq '2.5.29.19'});if(!$basic.Count -or !$basic[0].CertificateAuthority){throw 'گواهی CA معتبر شناسایی نشد.'}
  $preStore=New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
  try{$preStore.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly);if(@($preStore.Certificates|Where-Object {$_.Thumbprint -eq $cert.Thumbprint}).Count){throw 'این گواهی از قبل مورد اعتماد بوده است؛ نشست جدید متوقف شد و گواهی حذف نمی‌شود.'}}finally{$preStore.Close()}
  $script:tlsThumb=$cert.Thumbprint;$owner=Get-Process -Id $PID
  $lease=[ordered]@{RootWasPreexisting=$false;OwnerSID=$id.User.Value;OwnerPID=$PID;OwnerStartTicks=$owner.StartTime.ToUniversalTime().Ticks.ToString();ExpiresUTC=[datetime]::UtcNow.AddMinutes(5).ToString('o');ProxyPID=$script:tlsProxy.Id;ProxyPath=$exe;ProxyStartTicks=$script:tlsProxy.StartTime.ToUniversalTime().Ticks.ToString();CAThumbprint=$cert.Thumbprint;CAPublicDER=[Convert]::ToBase64String($der)};$owner.Dispose()
  $lease|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $script:tlsSession 'lease.json') -Encoding UTF8
  $guardInfo=New-Object Diagnostics.ProcessStartInfo;$guardInfo.FileName=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe';$guardInfo.UseShellExecute=$false;$guardInfo.CreateNoWindow=$true;$guardInfo.Arguments='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $PSScriptRoot 'TLS-Guard.ps1')+'" -SessionPath "'+$script:tlsSession+'"';$script:tlsGuard=[Diagnostics.Process]::Start($guardInfo)
  $guardUntil=[datetime]::UtcNow.AddSeconds(10);do{Start-Sleep -Milliseconds 200}while(!(Test-Path -LiteralPath (Join-Path $script:tlsSession 'guard-ready.json')) -and [datetime]::UtcNow -lt $guardUntil -and !$script:tlsGuard.HasExited)
  if(!(Test-Path -LiteralPath (Join-Path $script:tlsSession 'guard-ready.json')) -or $script:tlsGuard.HasExited){throw 'محافظ حذف گواهی آماده نشد؛ هیچ گواهی نصب نمی‌شود.'}
  $answer=[Windows.Forms.MessageBox]::Show("گواهی آزمایشی جدید در Root حساب فعلی ویندوز نصب شود؟`n`nاعتماد این گواهی برای همه دامنه‌هاست؛ فقط پروکسی بازرسی را به telemetry-in.battle.net محدود می‌کند. هیچ تنظیم پروکسی عمومی تغییر نمی‌کند. کلید CA در پوشه خصوصی محلی می‌ماند و پس از حذف تأییدشده گواهی و توقف ابزار، حذف می‌شود.`n`nاثر انگشت:`n"+$cert.Thumbprint+"`n`nپایان آزمون حذف بررسی می‌شود؛ خاموشی می‌تواند پاک‌سازی را متوقف کند. Cleanup-TLS.cmd راه حذف باقی‌مانده است. اجازه می‌دهی؟",'تأیید نصب گواهی موقت','YesNo','Warning')
  if($answer -ne 'Yes'){Stop-TelemetryTest 'ConsentDeclined';$r.Text='نصب گواهی لغو شد؛ گواهی نصب نشد.';return}
  if($script:tlsGuard.HasExited -or (Test-Path -LiteralPath (Join-Path $script:tlsSession 'cleanup.json')) -or ([datetime]::Parse($lease.ExpiresUTC).ToUniversalTime()-[datetime]::UtcNow).TotalSeconds -lt 120){throw 'مهلت تأیید گذشته یا محافظ متوقف شده؛ گواهی نصب نشد. دوباره شروع کن.'}
  $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser')
  try{$store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite);if(@($store.Certificates|Where-Object {$_.Thumbprint -eq $cert.Thumbprint}).Count){throw 'گواهی با همین اثرانگشت از قبل موجود است؛ نصب متوقف شد.'};$script:tlsCertAdded=$true;$store.Add($cert);if(!@($store.Certificates|Where-Object {$_.Thumbprint -eq $cert.Thumbprint}).Count){throw 'نصب گواهی تأیید نشد.'};$script:tlsCertVerified=$true}finally{$store.Close();$cert.Dispose()}
  if((Get-FileHash -LiteralPath $script:tlsTarget -Algorithm SHA256).Hash -ne $script:tlsHash){throw 'فایل هدف هنگام آماده‌سازی تغییر کرد.'}
  $game=New-Object Diagnostics.ProcessStartInfo;$game.FileName=$script:tlsTarget;$game.WorkingDirectory=[IO.Path]::GetDirectoryName($script:tlsTarget);$game.UseShellExecute=$false;$proxy='http://127.0.0.1:'+$port;$game.EnvironmentVariables['HTTP_PROXY']=$proxy;$game.EnvironmentVariables['HTTPS_PROXY']=$proxy;$game.EnvironmentVariables['NO_PROXY']=''
  $script:tlsGame=[Diagnostics.Process]::Start($game);$script:tlsDeadline=[datetime]::UtcNow.AddSeconds(90);$script:tlsActive=$true;$timer.Start();$b.Text='پایان بررسی و حذف گواهی';$r.Text='با بازی فعالیت آنلاین انجام بده. فقط تله‌متری بررسی می‌شود؛ اگر TLS شکست بخورد، آزمون متوقف و گواهی حذف می‌شود.'
 }catch{$message=$_.Exception.Message;try{Stop-TelemetryTest 'StartError'}catch{$message+="`nپاک‌سازی ناموفق؛ Cleanup-TLS.cmd را اجرا کن."};$r.Text=$message}finally{$b.Enabled=$true;if(!$script:tlsActive){$compare.Enabled=$true}}
})
$f.Add_Shown({$f.Activate();$f.BringToFront();if(Get-Command Set-ProxyStartupStatus -ErrorAction SilentlyContinue){Set-ProxyStartupStatus 'Ready'}})
$f.Add_FormClosing({if($script:tlsSession){try{Stop-TelemetryTest 'WindowClosed'}catch{[void][Windows.Forms.MessageBox]::Show('پاک‌سازی کامل تأیید نشد. Cleanup-TLS.cmd را اجرا کن.')}}})
[void]$f.ShowDialog();$timer.Dispose();$f.Dispose()
