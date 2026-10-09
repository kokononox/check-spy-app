$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$f=New-Object Windows.Forms.Form;$f.Text='یافتن راه بررسی محتوای ارسالی — ۲٫۴';$f.Size=New-Object Drawing.Size(850,640);$f.MinimumSize=New-Object Drawing.Size(720,540);$f.StartPosition='CenterScreen';$f.RightToLeft='Yes';$f.Font=New-Object Drawing.Font('Segoe UI',11)
$p=New-Object Windows.Forms.TableLayoutPanel;$p.Dock='Fill';$p.Padding=New-Object Windows.Forms.Padding(24);$p.ColumnCount=1;$p.RowCount=4
foreach($h in @(100,44,64)){[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle('Absolute',$h)))};[void]$p.RowStyles.Add((New-Object Windows.Forms.RowStyle('Percent',100)));$f.Controls.Add($p)
$l=New-Object Windows.Forms.Label;$l.Dock='Fill';$l.Text="۱. دکمه را بزن و همان فایل EXE را انتخاب کن.`n۲. بررسی فقط خواندنی است؛ برنامه اجرا یا تنظیماتش تغییر نمی‌کند.`n۳. اگر لاگ موجود داری، انتخاب اختیاری آن فقط تعداد کلمات مشخص را ثبت می‌کند.";$p.Controls.Add($l,0,0)
$c=New-Object Windows.Forms.CheckBox;$c.Dock='Fill';$c.Text='می‌خواهم یک فایل لاگ موجود را هم انتخاب کنم (اختیاری)';$c.Checked=$false;$p.Controls.Add($c,0,1)
$b=New-Object Windows.Forms.Button;$b.Dock='Fill';$b.Text='انتخاب EXE و ساخت گزارش تشخیصی';$b.BackColor=[Drawing.Color]::FromArgb(39,131,222);$b.ForeColor=[Drawing.Color]::White;$b.FlatStyle='Flat';$p.Controls.Add($b,0,2)
$r=New-Object Windows.Forms.RichTextBox;$r.Dock='Fill';$r.ReadOnly=$true;$r.RightToLeft='Yes';$r.BackColor=[Drawing.Color]::FromArgb(249,248,247);$r.Text='این مرحله محتوای HTTPS را باز نمی‌کند. هدف، پیدا کردن سرنخ برای روش بعدی است. هیچ فایل کلید یا متن خام لاگ داخل گزارش قرار نمی‌گیرد.';$p.Controls.Add($r,0,3)
$b.Add_Click({
 $b.Enabled=$false;$c.Enabled=$false
 try {
  $pick=New-Object Windows.Forms.OpenFileDialog;$pick.Filter='EXE (*.exe)|*.exe';$pick.Title='همان فایل هدف را انتخاب کن'
  if($pick.ShowDialog() -ne 'OK'){$pick.Dispose();return};$target=$pick.FileName;$pick.Dispose();$log=$null
  if($c.Checked){$pick=New-Object Windows.Forms.OpenFileDialog;$pick.Filter='Existing text log (*.log;*.txt)|*.log;*.txt';$pick.Title='لاگ موجود؛ لغو یعنی ادامه بدون لاگ';if($pick.ShowDialog() -eq 'OK'){$log=$pick.FileName};$pick.Dispose()}
  $r.Text='در حال بررسی محلی؛ تا پایان این بررسی کوتاه، پنجره پاسخ‌گو نیست…';$f.Refresh()
  $out=Join-Path $PSScriptRoot ('Reports-to-share\TargetDiagnostic-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6)+'.json')
  & (Join-Path $PSScriptRoot 'Inspect-Target.ps1') -TargetPath $target -OutputPath $out -SelectedLogPath $log | Out-Null
  $d=Get-Content -LiteralPath $out -Raw|ConvertFrom-Json
  $r.Text="گزارش ساخته شد.`n`nنشانه‌های ایستا: "+(@($d.StaticMarkerNames)-join '، ')+"`nتعداد لاگ‌های پیدا‌شده: "+@($d.LogInventory).Count+"`n`nوجود یا نبود این نشانه‌ها پشتیبانی قطعی از ثبت TLS را ثابت نمی‌کند. هنوز دربارهٔ اطلاعات واقعاً ارسالی نتیجه نمی‌گیریم.`n`nفقط این گزارش را بعد از بازبینی بفرست:`n"+[IO.Path]::GetFileName($out)
  Start-Process explorer.exe -ArgumentList ('/select,"'+$out+'"')
 }catch{$r.Text='بررسی ناموفق بود: '+$_.Exception.Message}finally{$b.Enabled=$true;$c.Enabled=$true}
})
[void]$f.ShowDialog();$f.Dispose()
