#requires -Version 5.1
$ErrorActionPreference='Stop'
$config=$null;$diagFile=Join-Path $PSScriptRoot 'launcher-status.json';$process=$null
function Save-LaunchDiagnostic($phase,$success,$keyStatus,$errorMessage='') {
 $obj=[ordered]@{Phase=$phase;Success=$success;UTC=[datetime]::UtcNow.ToString('o');ValidKeyRecords=0;KeyAssessment='Not checked';Error=$errorMessage}
 if($keyStatus){$obj.ValidKeyRecords=$keyStatus.ValidEntries;$obj.KeyAssessment=$keyStatus.Assessment}
 $temp=$diagFile+'.tmp';$obj | ConvertTo-Json | Set-Content -LiteralPath $temp -Encoding UTF8;Move-Item -LiteralPath $temp -Destination $diagFile -Force
}
try {
 $config=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Launch-Target.json') -Raw | ConvertFrom-Json
 . (Join-Path $PSScriptRoot 'TLS-Key-Status.ps1')
 Save-LaunchDiagnostic 'Preparing' $false $null
 $id=[Security.Principal.WindowsIdentity]::GetCurrent();$pr=New-Object Security.Principal.WindowsPrincipal($id)
 if($pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'اجرای هدف با دسترسی ادمین متوقف شد. برنامه باید از Explorer معمولی اجرا شود.'}
 if(!(Test-Path -LiteralPath $config.Target -PathType Leaf)){throw 'فایل هدف پیدا نشد.'}
 if($config.TargetSHA256 -and (Get-FileHash -LiteralPath $config.Target -Algorithm SHA256).Hash -ne $config.TargetSHA256){throw 'فایل هدف تغییر کرده است؛ یک بررسی تازه شروع کنید.'}
 $already=@(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {$_.ExecutablePath -and [string]::Equals($_.ExecutablePath,$config.Target,[StringComparison]::OrdinalIgnoreCase)})
 if($already.Count){throw 'برنامهٔ هدف از قبل باز است. خودتان آن را ببندید و دوباره بررسی را شروع کنید.'}
 $info=New-Object Diagnostics.ProcessStartInfo;$info.FileName=$config.Target;$info.Arguments=$config.Arguments;$info.WorkingDirectory=[IO.Path]::GetDirectoryName($config.Target);$info.UseShellExecute=$false
 $requestKeys=if($config.PSObject.Properties['RequestTLSKeyLogging']){[bool]$config.RequestTLSKeyLogging}else{[bool]$config.KeyFile}
 if($requestKeys -and $config.KeyFile){$info.EnvironmentVariables['SSLKEYLOGFILE']=$config.KeyFile}else{$info.EnvironmentVariables.Remove('SSLKEYLOGFILE');$info.EnvironmentVariables.Remove('MITMPROXY_SSLKEYLOGFILE')}
 $process=[Diagnostics.Process]::Start($info)
 if(!$requestKeys){Save-LaunchDiagnostic 'PassiveLaunched' $true $null;Write-Host 'هدف معمولی اجرا شد؛ ثبت کلید یا تغییر پروکسی درخواست نشد.';return}
 Save-LaunchDiagnostic 'Launched' $true $null
 Write-Host 'برنامه اجرا شد. تا ۳۰ ثانیه وضعیت ثبت کلید بررسی می‌شود.'
 $until=[datetime]::UtcNow.AddSeconds(30)
 do {Start-Sleep -Milliseconds 500;$k=Get-RMTLSKeyStatus $config.KeyFile} while(!$k.ValidEntries -and [datetime]::UtcNow -lt $until -and !$process.HasExited)
 Save-LaunchDiagnostic 'KeyCheckCompleted' $true $k
 Write-Host ('وضعیت کلید: '+$k.Assessment+' | تعداد رکورد: '+$k.ValidEntries)
 if(!$k.ValidEntries){Write-Warning 'کلید معتبر تولید نشده است. این برنامه ممکن است ثبت کلید را پشتیبانی نکند؛ محتوای HTTPS نامعلوم می‌ماند.'}
} catch {
 try {Save-LaunchDiagnostic 'Failed' $false $null $_.Exception.Message}catch{}
 Write-Error $_.Exception.Message -ErrorAction Continue;exit 1
} finally {if($process){$process.Dispose()}}
