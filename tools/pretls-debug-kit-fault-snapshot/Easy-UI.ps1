#requires -Version 5.1
param([switch]$LayoutSmoke)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
. (Join-Path $PSScriptRoot 'Session-UI-Core.ps1')
. (Join-Path $PSScriptRoot 'Diagnostic-Core.ps1')
function New-RMEasyWindow {
 $form=New-Object Windows.Forms.Form;$form.Text='PreTLS — بررسی آزمایشی';$form.Size=New-Object Drawing.Size(820,680);$form.StartPosition='CenterScreen';$form.FormBorderStyle='FixedDialog';$form.MaximizeBox=$false;$form.Font=New-Object Drawing.Font('Tahoma',10);$form.RightToLeft='Yes';$form.RightToLeftLayout=$true
 $heading=New-Object Windows.Forms.Label;$heading.SetBounds(20,16,760,64);$heading.Text="فقط محیط آزمایشی جداگانه؛ بدون حساب واقعی یا جلسهٔ آنلاین ضدتقلب.`r`nروی بازی تأیید نشده است. خروجی خام ممکن است حاوی اطلاعات خصوصی باشد.";$form.Controls.Add($heading)
 $pick=New-Object Windows.Forms.Button;$pick.Name='PickExe';$pick.Text='۱. انتخاب فایل EXE';$pick.SetBounds(570,86,210,38);$form.Controls.Add($pick)
 $target=New-Object Windows.Forms.Label;$target.Name='TargetLabel';$target.Text='فایلی انتخاب نشده';$target.SetBounds(20,86,530,38);$form.Controls.Add($target)
 $refresh=New-Object Windows.Forms.Button;$refresh.Name='Refresh';$refresh.Text='پیدا کردن پردازش';$refresh.SetBounds(570,136,210,38);$form.Controls.Add($refresh)
 $list=New-Object Windows.Forms.ComboBox;$list.Name='Processes';$list.DropDownStyle='DropDownList';$list.DisplayMember='Label';$list.SetBounds(20,136,530,38);$form.Controls.Add($list)
 $choose=New-Object Windows.Forms.Button;$choose.Name='PickCdb';$choose.Text='انتخاب CDB در صورت نیاز';$choose.SetBounds(570,186,210,38);$form.Controls.Add($choose)
 $cdbLabel=New-Object Windows.Forms.Label;$cdbLabel.Name='CdbLabel';$cdbLabel.SetBounds(20,186,530,45);$form.Controls.Add($cdbLabel)
 $isolated=New-Object Windows.Forms.CheckBox;$isolated.Name='Isolated';$isolated.Text='محیط آزمایشی جداگانه، برنامهٔ مجاز، بدون حساب واقعی و ضدتقلب آنلاین دارم.';$isolated.SetBounds(20,246,760,32);$form.Controls.Add($isolated)
 $private=New-Object Windows.Forms.CheckBox;$private.Name='Private';$private.Text='می‌دانم لاگ خام خصوصی است؛ آن را روی GitHub یا عمومی منتشر نمی‌کنم.';$private.SetBounds(20,283,760,32);$form.Controls.Add($private)
 $body=New-Object Windows.Forms.CheckBox;$body.Name='Body';$body.Text='بدنه‌های قابل‌خواندن را هم در فایل خصوصی ذخیره کن (اختیاری).';$body.SetBounds(20,320,760,32);$form.Controls.Add($body)
 $start=New-Object Windows.Forms.Button;$start.Name='Start';$start.Text='۲. اتصال و بررسی آغاز';$start.SetBounds(590,370,190,44);$start.Enabled=$false;$form.Controls.Add($start)
 $stop=New-Object Windows.Forms.Button;$stop.Name='Stop';$stop.Text='توقف امن';$stop.SetBounds(400,370,180,44);$stop.Enabled=$false;$form.Controls.Add($stop)
 $initial=New-Object Windows.Forms.Button;$initial.Name='InitialContinue';$initial.Text='۳. ادامهٔ اولیه';$initial.SetBounds(210,370,180,44);$initial.Enabled=$false;$form.Controls.Add($initial)
 $copy=New-Object Windows.Forms.Button;$copy.Name='ManualCopy';$copy.Text='راهنمای توقف دستی';$copy.SetBounds(20,370,180,44);$form.Controls.Add($copy)
 $status=New-Object Windows.Forms.Label;$status.Name='Status';$status.SetBounds(20,435,760,84);$status.Text='ابتدا EXE را انتخاب کن. اگر برنامهٔ آزمایشی در حال اجرا باشد، خودش پیدا می‌شود.';$form.Controls.Add($status)
 $report=New-Object Windows.Forms.Button;$report.Name='Report';$report.Text='باز کردن گزارش قابل‌اشتراک';$report.SetBounds(410,533,370,40);$report.Enabled=$false;$form.Controls.Add($report)
 $url=New-Object Windows.Forms.Button;$url.Name='PrivateURL';$url.Text='دیدن URLهای خصوصی، فقط محلی';$url.SetBounds(20,533,370,40);$url.Enabled=$false;$form.Controls.Add($url)
 $note=New-Object Windows.Forms.Label;$note.SetBounds(20,588,760,42);$note.Text='ادامهٔ اولیه فقط با تأیید تو؛ توقف پس از حدود ۳۰ ثانیه بررسی، یا ۶۰ ثانیه انتظار آغاز، درخواست می‌شود.';$form.Controls.Add($note)
 return $form
}
$form=New-RMEasyWindow
if($LayoutSmoke){
 if($form.Controls.Count -ne 18){throw 'Unexpected GUI control count'}
 if($form.Controls['Start'].Enabled -or $form.Controls['Stop'].Enabled -or $form.Controls['InitialContinue'].Enabled){throw 'Capture enabled without consent/target'}
 foreach($name in @('PickExe','PickCdb','Processes','Isolated','Private','Start','InitialContinue','Stop','Report','PrivateURL')){if(!$form.Controls[$name]){throw 'Required control missing'}}
 foreach($c in $form.Controls){if($c.Right -gt $form.ClientSize.Width -or $c.Bottom -gt $form.ClientSize.Height){throw 'Control exceeds form bounds'}}
 $form.Dispose();Write-Host 'PASS: GUI layout/default-gate smoke. No display, target or debugger started.';return
}
$script:state=[pscustomobject]@{Exe='';Cdb='';Meta=$null;Debugger=$null;StopHelper=$null;FaultHelper=$null;FaultAttempted=$false;ContinueHelper=$null;ContinueAttempted=$false;ContinueSentUTC=$null;LastDiag=$null;StartedUTC=$null;StopAttempted=$false;ReadDone=$false}
$script:base=$PSScriptRoot
$default=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
if(Test-Path -LiteralPath $default){$script:state.Cdb=$default;$form.Controls['CdbLabel'].Text='CDB پیدا شد؛ امضای Microsoft پیش از اتصال بررسی می‌شود.'}else{$form.Controls['CdbLabel'].Text='CDB نصب/پیدا نشده؛ ابزار آن را خودکار نصب نمی‌کند.'}
function Update-RMButtons {
 $running=$script:state.Debugger -and !$script:state.Debugger.HasExited
 $form.Controls['Start'].Enabled=(!$running -and $script:state.Exe -and $script:state.Cdb -and $form.Controls['Processes'].SelectedItem -and $form.Controls['Isolated'].Checked -and $form.Controls['Private'].Checked)
 $continueBusy=($script:state.ContinueHelper -and !$script:state.ContinueHelper.HasExited) -or ($script:state.FaultHelper -and !$script:state.FaultHelper.HasExited)
 $form.Controls['Stop'].Enabled=[bool]($running -and !$continueBusy -and (!$script:state.StopHelper -or $script:state.StopHelper.HasExited))
 $form.Controls['InitialContinue'].Enabled=[bool]($running -and !$script:state.StopAttempted -and !$script:state.ContinueAttempted -and $script:state.LastDiag -and $script:state.LastDiag.InitialContinueAllowed)
 $form.Controls['PickExe'].Enabled=!$running;$form.Controls['Refresh'].Enabled=!$running;$form.Controls['PickCdb'].Enabled=!$running;$form.Controls['Processes'].Enabled=!$running
}
function Refresh-RMProcesses {
 $form.Controls['Processes'].Items.Clear()
 if(!$script:state.Exe){return}
 foreach($p in @(Get-Process)){
  try{
   if([string]::Equals($p.MainModule.FileName,$script:state.Exe,[StringComparison]::OrdinalIgnoreCase)){
    [void]$form.Controls['Processes'].Items.Add([pscustomobject]@{Id=$p.Id;Start=$p.StartTime.ToUniversalTime();Label=('PID '+$p.Id+' — '+$p.StartTime.ToString('HH:mm:ss'))})
   }
  }catch{}
 }
 if($form.Controls['Processes'].Items.Count){$form.Controls['Processes'].SelectedIndex=0;$form.Controls['Status'].Text='پردازش پیدا شد. اگر چند مورد هست، فقط پردازش آزمایشی درست را انتخاب کن.'}else{$form.Controls['Status'].Text='پردازش مطابق EXE پیدا نشد یا دسترسی خواندن نداریم. برنامه را خودت فقط در محیط آزمایشی اجرا کن؛ سپس پیدا کردن پردازش را بزن.'}
 Update-RMButtons
}
function Request-RMFaultSnapshot {
 if($script:state.FaultAttempted -or $script:state.StopAttempted -or !$script:state.Meta){return}
 $script:state.FaultAttempted=$true
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $script:base 'Fault-Snapshot.ps1')+'" -SessionPath "'+(Join-Path $script:state.Meta.Root 'PRIVATE-ui-session.json')+'"'
 $script:state.FaultHelper=Start-Process -FilePath $ps -ArgumentList $args -PassThru -WindowStyle Hidden
}
function Request-RMStop {
 if(!$script:state.Debugger -or $script:state.Debugger.HasExited){return}
 if(($script:state.StopHelper -and !$script:state.StopHelper.HasExited) -or ($script:state.ContinueHelper -and !$script:state.ContinueHelper.HasExited) -or ($script:state.FaultHelper -and !$script:state.FaultHelper.HasExited)){return}
 $script:state.StopAttempted=$true
 $session=Join-Path $script:state.Meta.Root 'PRIVATE-ui-session.json';$helper=Join-Path $script:base 'Stop-Debugger.ps1'
 $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
 $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+$helper+'" -SessionPath "'+$session+'"'
 $script:state.StopHelper=Start-Process -FilePath $ps -ArgumentList $args -PassThru -WindowStyle Hidden
 $form.Controls['Status'].Text='در حال درخواست توقف و جداکردن دیباگر؛ برنامهٔ هدف با زور بسته نمی‌شود.';Update-RMButtons
}
$form.Controls['PickExe'].Add_Click({
 $dlg=New-Object Windows.Forms.OpenFileDialog;$dlg.Filter='Executable|*.exe';$dlg.Title='EXE برنامهٔ آزمایشی مجاز را انتخاب کن'
 if($dlg.ShowDialog() -eq 'OK'){$script:state.Exe=[IO.Path]::GetFullPath($dlg.FileName);$form.Controls['TargetLabel'].Text=[IO.Path]::GetFileName($dlg.FileName);Refresh-RMProcesses};$dlg.Dispose()
})
$form.Controls['Refresh'].Add_Click({Refresh-RMProcesses})
$form.Controls['PickCdb'].Add_Click({
 $dlg=New-Object Windows.Forms.OpenFileDialog;$dlg.Filter='Microsoft CDB|cdb.exe';$dlg.Title='CDB x64 از Microsoft Debugging Tools'
 if($dlg.ShowDialog() -eq 'OK'){$script:state.Cdb=$dlg.FileName;$form.Controls['CdbLabel'].Text='CDB انتخاب شد؛ اعتبارسنجی پیش از اتصال انجام می‌شود.'};$dlg.Dispose();Update-RMButtons
})
foreach($n in @('Isolated','Private')){$form.Controls[$n].Add_CheckedChanged({Update-RMButtons})}
$form.Controls['Processes'].Add_SelectedIndexChanged({Update-RMButtons})
$form.Controls['Start'].Add_Click({
 try{
  $choice=$form.Controls['Processes'].SelectedItem
  if(!$choice -or !$form.Controls['Isolated'].Checked -or !$form.Controls['Private'].Checked){return}
  $result=[Windows.Forms.MessageBox]::Show('دیباگر ممکن است برنامه را متوقف یا اتصال را قطع کند. فقط محیط جداگانه، بدون حساب واقعی/ضدتقلب آنلاین. ادامه؟','تأیید نهایی','YesNo','Warning','Button2')
  if($result -ne 'Yes'){return}
  $form.Controls['Start'].Enabled=$false;$form.Controls['Report'].Enabled=$false;$form.Controls['PrivateURL'].Enabled=$false
  $meta=New-RMPrivateUiSession $script:state.Exe $choice.Id $choice.Start $script:state.Cdb $form.Controls['Isolated'].Checked $form.Controls['Private'].Checked
  # Repeat identity check immediately before attaching. A small unavoidable race remains.
  $p=Get-Process -Id $choice.Id;if($p.StartTime.ToUniversalTime() -ne $choice.Start){throw 'Target generation changed'}
  $args='-pd -p '+$choice.Id+' -cf "'+$meta.CommandPath+'" -logo "'+$meta.LogPath+'"'
  $debugger=Start-Process -FilePath $meta.CdbPath -ArgumentList $args -PassThru
  $script:state.Meta=$meta;$script:state.Debugger=$debugger;$script:state.StartedUTC=[datetime]::UtcNow;$script:state.StopAttempted=$false;$script:state.StopHelper=$null;$script:state.FaultHelper=$null;$script:state.FaultAttempted=$false;$script:state.ContinueHelper=$null;$script:state.ContinueAttempted=$false;$script:state.ContinueSentUTC=$null;$script:state.LastDiag=$null;$script:state.ReadDone=$false
  $meta.DebuggerId=$debugger.Id;$meta.DebuggerStart=$debugger.StartTime.ToUniversalTime().ToString('o')
  $meta|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $meta.Root 'PRIVATE-ui-session.json') -Encoding UTF8
  $script:state.Meta=$meta;$script:state.Debugger=$debugger;$script:state.StartedUTC=[datetime]::UtcNow;$script:state.StopAttempted=$false;$script:state.StopHelper=$null;$script:state.FaultHelper=$null;$script:state.FaultAttempted=$false;$script:state.ContinueHelper=$null;$script:state.ContinueAttempted=$false;$script:state.ContinueSentUTC=$null;$script:state.LastDiag=$null;$script:state.ReadDone=$false
  $form.Controls['Status'].Text='اتصال انجام شد؛ ادامه خودکار حذف شده است. در حال بررسی توقف اولیه؛ اگر دکمه ادامهٔ اولیه فعال شد، علت را بخوان و خودت تأیید کن.'
 }catch{$form.Controls['Status'].Text='شروع تأیید نشد: EXE/PID، x64، امضای CDB یا مجوز را بررسی کن. محافظت/ضدتقلب را غیرفعال نکن.'}
 Update-RMButtons
})
$form.Controls['InitialContinue'].Add_Click({
 try{
  if($script:state.ContinueAttempted -or $script:state.StopAttempted -or !$script:state.Meta){return}
  $diag=Get-RMDiagnostics (Read-RMLiveLog $script:state.Meta.LogPath)
    $script:state.LastDiag=$diag
  if(!$diag.InitialContinueAllowed){$form.Controls['Status'].Text='ادامه مجاز نیست؛ علت توقف اولیه قابل تأیید نیست یا خطا دیده شده. توقف امن را بزن.';return}
  $yes=[Windows.Forms.MessageBox]::Show('فقط الگوی توقف اولیهٔ دیباگر در لاگ تأیید شده؛ این تشخیص تضمین منشأ توقف نیست. در محیط مجازِ جداگانه، ادامهٔ اولیه را درخواست می‌کنی؟','تأیید ادامه اولیه','YesNo','Warning','Button2')
  if($yes -ne 'Yes'){return}
  $script:state.ContinueAttempted=$true
  $ps=Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
  $args='-NoLogo -NoProfile -ExecutionPolicy Bypass -File "'+(Join-Path $script:base 'Continue-Initial.ps1')+'" -SessionPath "'+(Join-Path $script:state.Meta.Root 'PRIVATE-ui-session.json')+'"'
  $script:state.ContinueHelper=Start-Process -FilePath $ps -ArgumentList $args -PassThru -WindowStyle Hidden
  $script:state.ContinueSentUTC=[datetime]::UtcNow
  $form.Controls['Status'].Text='درخواست یک‌بارهٔ ادامهٔ اولیه ارسال شد؛ اجرای آن هنوز تأیید نشده. خطاهای بعدی خودکار رد نمی‌شوند.'
 }catch{$form.Controls['Status'].Text='ادامه اولیه تأیید نشد؛ تکرار نکن. توقف امن یا راهنمای توقف دستی را استفاده کن.'}
 Update-RMButtons
})
$form.Controls['Stop'].Add_Click({try{Request-RMStop}catch{$form.Controls['Status'].Text='درخواست توقف ناموفق؛ از راهنمای توقف دستی استفاده کن.'}})
$form.Controls['ManualCopy'].Add_Click({
 [Windows.Forms.Clipboard]::SetText('bc *; .logclose; .detach; q')
 [void][Windows.Forms.MessageBox]::Show('فرمان توقف کپی شد. فقط در پنجرهٔ CDB خود ابزار، Ctrl+C بزن؛ سپس فرمان را paste کن و Enter بزن. تنها q نزن.','توقف دستی')
})
$form.Controls['Report'].Add_Click({if($script:state.Meta){Start-Process explorer.exe -ArgumentList ('/select,"'+(Join-Path $script:state.Meta.Root 'local-results\Report-to-share.json')+'"')}})
$form.Controls['PrivateURL'].Add_Click({if($script:state.Meta){Start-Process notepad.exe -ArgumentList ('"'+(Join-Path $script:state.Meta.Root 'local-results\PRIVATE-URL-candidates.json')+'"')}})
$timer=New-Object Windows.Forms.Timer;$timer.Interval=500
$timer.Add_Tick({
 try{
  if($script:state.Debugger){
   if(!$script:state.Debugger.HasExited -and !$script:state.StopAttempted -and $script:state.Meta){
    $diag=Get-RMDiagnostics (Read-RMLiveLog $script:state.Meta.LogPath)
    $script:state.LastDiag=$diag
    if($diag.ExceptionPausePossible -and $diag.LastExceptionClass -eq 'AccessViolation' -and $diag.LastExceptionChance -eq 'first' -and $diag.UserInitialContinueMarker -and !$script:state.FaultAttempted){Request-RMFaultSnapshot}
    if($diag.InitialContinueAllowed -and !$script:state.ContinueAttempted){$form.Controls['Status'].Text='الگوی توقف اولیهٔ دیباگر دیده شد؛ ادامه خودکار انجام نمی‌شود. برای ادامه، دکمه ۳ و تأیید نهایی را بزن.'}
    elseif($diag.InitialWaiting -and !$diag.InitialContinueAllowed){$form.Controls['Status'].Text='علت توقف اولیه قابل تأیید نیست یا خطا دیده شده؛ ادامه مسدود است. توقف امن را بزن.'}
    elseif($diag.ExceptionPausePossible){$form.Controls['Status'].Text='توقف دیباگر/خطای برنامه در دیباگر دیده شد؛ توقف اجرا محتمل است. ابزار از روی خطا خودکار ادامه نمی‌دهد. توقف امن را بزن؛ صفر درخواست اثبات نبود ارسال نیست.'}
    elseif($diag.DebuggerCommandErrorObserved){$form.Controls['Status'].Text='خطای فرمان دیباگر دیده شد؛ ثبت داده تأیید نشده است. توقف امن را بزن.'}
   }
   if($script:state.ContinueHelper -and $script:state.ContinueHelper.HasExited -and !$script:state.StopAttempted -and !$script:state.Debugger.HasExited){
    $cp=Join-Path $script:state.Meta.Root 'continue-result.json'
    if(Test-Path -LiteralPath $cp){$cr=Get-Content -LiteralPath $cp -Raw|ConvertFrom-Json;if(!$cr.ContinueCommandQueued){$form.Controls['Status'].Text='ادامه اولیه تأیید نشد؛ دوباره ادامه نده. توقف امن یا راهنمای توقف دستی را بزن.'}}
   }
   if(!$script:state.Debugger.HasExited -and !$script:state.StopAttempted){
    $expired=if($script:state.ContinueSentUTC){([datetime]::UtcNow-$script:state.ContinueSentUTC).TotalSeconds -ge 30}else{([datetime]::UtcNow-$script:state.StartedUTC).TotalSeconds -ge 60}
    if($expired){Request-RMStop}
   }
   if($script:state.StopHelper -and $script:state.StopHelper.HasExited -and !$script:state.Debugger.HasExited){$form.Controls['Status'].Text='توقف تأیید نشد؛ راهنمای توقف دستی را بزن. ابزار هدف یا دیباگر را با زور نمی‌بندد.'}
   if($script:state.Debugger.HasExited -and (!$script:state.StopHelper -or $script:state.StopHelper.HasExited) -and (!$script:state.ContinueHelper -or $script:state.ContinueHelper.HasExited) -and (!$script:state.FaultHelper -or $script:state.FaultHelper.HasExited) -and !$script:state.ReadDone){
    $script:state.ReadDone=$true
    if(Test-Path -LiteralPath $script:state.Meta.LogPath){
     & (Join-Path $script:base 'Read-Private-Log.ps1') -LogPath $script:state.Meta.LogPath -SavePrivateBodies:$form.Controls['Body'].Checked
     $path=Join-Path $script:state.Meta.Root 'local-results\Report-to-share.json';$d=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
     $form.Controls['Status'].Text=('دیباگر پایان یافت. بافر خوانده‌شده: '+$d.ParsedDataBuffers+'؛ نامزد HTTP/1: '+$d.CandidateHTTP1Requests+'. این شمارنده‌ها اثبات ارسال نیستند.')
     if($d.DebuggerDiagnostics.ExceptionPausePossible){$form.Controls['Status'].Text='بررسی پایان یافت؛ توقف دیباگر یا خطای برنامه در لاگ دیده شد. گزارش امن را بفرست. صفر درخواست اثبات نبود ارسال نیست.'}
     elseif($d.CaptureOutcome -like 'NoDataObserved*'){$form.Controls['Status'].Text='داده‌ای ثبت نشد؛ علت و ارسال/عدم ارسال تأیید نشده‌اند. گزارش امن شامل وضعیت راه‌اندازی و پایان است.'}
     if($d.DebuggerDiagnostics.FaultRecordComplete -and $d.DebuggerDiagnostics.FaultRecordExceptionClass -eq 'AccessViolation'){
      $kind=switch($d.DebuggerDiagnostics.FaultAccessKind){'Read'{'خواندن حافظه'};'Write'{'نوشتن حافظه'};'Execute'{'اجرای حافظه'};default{'دسترسی نامشخص'}}
      $form.Controls['Status'].Text='جزئیات خطای '+$kind+' ثبت شد؛ از خطا عبور نکردیم. فقط گزارش قابل‌اشتراک را بفرست.'
     }
     if($d.EndEvidence.StopHelperEvidence -eq 'StopNotConfirmedManualRecoveryRequired'){$form.Controls['Status'].Text+=' پایانِ فرمان توقف تأیید نشده است.'}
     $form.Controls['Report'].Enabled=$true;$form.Controls['PrivateURL'].Enabled=$true
    }else{$form.Controls['Status'].Text='دیباگر پایان یافت ولی لاگ پیدا نشد؛ اتصال/ثبت تأیید نشده است.'}
   }
  }
  Update-RMButtons
 }catch{$form.Controls['Status'].Text='خواندن نتیجه کامل نشد. اگر CDB هنوز باز است، توقف امن یا راهنمای دستی را استفاده کن.'}
})
$form.Add_FormClosing({param($sender,$e)
 if($script:state.Debugger -and !$script:state.Debugger.HasExited){
  $e.Cancel=$true
  [void][Windows.Forms.MessageBox]::Show('دیباگر هنوز باز است. اول توقف امن را بزن و منتظر تأیید بمان؛ در صورت خطا توقف دستی لازم است.','ابتدا توقف')
 }
})
$timer.Start();try{[void]$form.ShowDialog()}finally{$timer.Stop();$timer.Dispose();$form.Dispose()}
