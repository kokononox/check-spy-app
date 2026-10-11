param([switch]$LayoutSmoke)
$ErrorActionPreference='Stop';Add-Type -AssemblyName System.Windows.Forms;Add-Type -AssemblyName System.Drawing
$form=New-Object Windows.Forms.Form;$form.Text='Offline Loader RVA Review';$form.Size=New-Object Drawing.Size(780,470);$form.StartPosition='CenterScreen';$form.RightToLeft='Yes';$form.RightToLeftLayout=$true
$label=New-Object Windows.Forms.Label;$label.SetBounds(20,20,720,92);$label.Text="استخراج آفلاین از نشست ذخیره‌شده؛ بازی را دوباره اجرا یا دیباگر را وصل نکن.`r`nابتدا بگذار نشست قبلی از رابط قبلی پایان یابد.`r`nفقط خروجی RVA-to-share.json را بفرست؛ نه فایل‌های PRIVATE یا لاگ خام.";$form.Controls.Add($label)
$list=New-Object Windows.Forms.ComboBox;$list.SetBounds(20,125,720,35);$list.DropDownStyle='DropDownList';$form.Controls.Add($list)
$extract=New-Object Windows.Forms.Button;$extract.SetBounds(20,185,350,48);$extract.Text='استخراج از نشست انتخاب‌شده';$form.Controls.Add($extract)
$open=New-Object Windows.Forms.Button;$open.SetBounds(390,185,350,48);$open.Text='باز کردن پوشهٔ خروجی';$open.Enabled=$false;$form.Controls.Add($open)
$status=New-Object Windows.Forms.Label;$status.SetBounds(20,255,720,140);$status.Text='در حال یافتن نشست‌های ذخیره‌شده...';$form.Controls.Add($status)
if($LayoutSmoke){if($form.Controls.Count -ne 5){throw 'LayoutCount'};$form.Dispose();Write-Host 'PASS: offline GUI construction';return}
$script:folders=@();$script:output=Join-Path $PSScriptRoot 'RVA-to-share.json'
try{
 $root=Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor\PreTLS-PRIVATE'
 if(Test-Path -LiteralPath $root){
  $candidates=@(Get-ChildItem -LiteralPath $root -Directory|Where-Object {$_.Name -cmatch '^[0-9a-fA-F]{32}$' -and !($_.Attributes -band [IO.FileAttributes]::ReparsePoint)}|ForEach-Object {
   $path=Join-Path $_.FullName 'startup-metadata-safe.json'
   if(Test-Path -LiteralPath $path){$f=Get-Item -LiteralPath $path;if($f.Length -le 16384 -and !($f.Attributes -band [IO.FileAttributes]::ReparsePoint)){[pscustomobject]@{Folder=$_.FullName;Time=$f.LastWriteTime}}}
  }|Sort-Object Time -Descending|Select-Object -First 20)
  foreach($c in $candidates){$script:folders+= $c.Folder;[void]$list.Items.Add($c.Time.ToString('yyyy-MM-dd HH:mm:ss'))}
 }
 if($list.Items.Count){$list.SelectedIndex=0;$status.Text='جدیدترین نشست انتخاب شده است؛ اگر گزارش موردنظر قدیمی‌تر است، زمان آن را انتخاب کن.'}else{$extract.Enabled=$false;$status.Text='نشست دارای metadata پیدا نشد. هیچ آزمایش تازه‌ای اجرا نکن؛ همین پیام را اطلاع بده.'}
}catch{$extract.Enabled=$false;$status.Text='خواندن فهرست نشست‌ها ممکن نشد. هیچ فایل خصوصی را نفرست؛ همین پیام را اطلاع بده.'}
$extract.Add_Click({
 $extract.Enabled=$false;$open.Enabled=$false
 try{
  if($list.SelectedIndex -lt 0){throw 'NoSession'}
  if(Test-Path -LiteralPath $script:output){$answer=[Windows.Forms.MessageBox]::Show('گزارش قبلی این پوشه جایگزین شود؟','تأیید','YesNo');if($answer -ne 'Yes'){return}}
  & (Join-Path $PSScriptRoot 'Extract-RVA.ps1') -SessionFolder $script:folders[$list.SelectedIndex] -OutputPath $script:output
  $r=Get-Content -LiteralPath $script:output -Raw|ConvertFrom-Json
  if($r.ExtractionState -eq 'SnapshotAccepted'){$status.Text='گزارش نسبی ساخته شد. فقط RVA-to-share.json را بفرست. مقدار null یعنی نقطه قابل تطبیق نبود؛ نه نبود فعالیت. هیچ اتصال یا فرمان ادامه‌ای اجرا نشد.'}else{$status.Text='گزارش ساخته شد، ولی snapshot پذیرفته نشد. فقط RVA-to-share.json را بفرست؛ آزمایش را تکرار نکن.'}
  $open.Enabled=$true
 }catch{$status.Text='استخراج تأیید نشد. فایل‌های PRIVATE یا لاگ خام را نفرست؛ فقط همین پیام را اطلاع بده.'}finally{$extract.Enabled=$true}
})
$open.Add_Click({if(Test-Path -LiteralPath $script:output){Start-Process explorer.exe -ArgumentList ('/select,"'+$script:output+'"')}})
[void]$form.ShowDialog()
