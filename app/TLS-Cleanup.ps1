# Current-user cleanup only. Never remove certificates except the exact recorded fresh CA.
function Read-TLSLease([string]$SessionPath){Get-Content -LiteralPath (Join-Path $SessionPath 'lease.json') -Raw|ConvertFrom-Json}
function Invoke-TLSCleanup([string]$SessionPath){
 $lease=Read-TLSLease $SessionPath;$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
 if($lease.OwnerSID -ne $sid){throw 'این نشست متعلق به حساب ویندوز فعلی نیست؛ هیچ گواهی حذف نشد.'}
 if($lease.RootWasPreexisting -ne $false){throw 'سابقه تازه‌بودن گواهی قابل تأیید نیست؛ حذف خودکار متوقف شد.'}
 $killed=$true
 try{
  $p=Get-Process -Id $lease.ProxyPID -ErrorAction Stop
  if($p.Path -eq $lease.ProxyPath -and $p.StartTime.ToUniversalTime().Ticks.ToString() -eq $lease.ProxyStartTicks){
   $kill=Start-Process -FilePath (Join-Path $env:WINDIR 'System32\taskkill.exe') -ArgumentList ('/PID '+[int]$lease.ProxyPID+' /T /F') -WindowStyle Hidden -PassThru -Wait
   $killed=($kill.ExitCode -eq 0 -or $p.HasExited);$p.Dispose();$kill.Dispose()
  }
 }catch [Microsoft.PowerShell.Commands.ProcessCommandException]{}catch{$killed=$false}
 $store=New-Object Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser');$removed=$false
 try{
  $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  $matches=@($store.Certificates|Where-Object {$_.Thumbprint -eq $lease.CAThumbprint})
  foreach($cert in $matches){
   if([Convert]::ToBase64String($cert.RawData) -ne $lease.CAPublicDER){throw 'گواهی با سابقه نشست تطبیق ندارد؛ حذف متوقف شد.'}
   $store.Remove($cert)
  }
  $removed=(@($store.Certificates|Where-Object {$_.Thumbprint -eq $lease.CAThumbprint}).Count -eq 0)
 }finally{$store.Close()}
 if($removed -and $killed){
  foreach($name in @('ca','identifiers.json')){$item=Join-Path $SessionPath $name;if(Test-Path -LiteralPath $item){Remove-Item -LiteralPath $item -Recurse -Force}}
 }
 $result=[ordered]@{CertificateAbsent=$removed;ProxyStopped=$killed;PrivateMaterialDeleted=($removed -and $killed);UTC=[datetime]::UtcNow.ToString('o')}
 $result|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $SessionPath 'cleanup.json') -Encoding UTF8
 return [pscustomobject]$result
}
function Invoke-TLSRecover {
 $root=Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor\TLS-Sessions'
 if(!(Test-Path -LiteralPath $root)){return}
 foreach($dir in Get-ChildItem -LiteralPath $root -Directory){
  if(!(Test-Path -LiteralPath (Join-Path $dir.FullName 'lease.json'))){continue}
  $lease=Read-TLSLease $dir.FullName;$live=$false
  try{$owner=Get-Process -Id $lease.OwnerPID -ErrorAction Stop;$live=($owner.StartTime.ToUniversalTime().Ticks.ToString() -eq $lease.OwnerStartTicks);$owner.Dispose()}catch{}
  if(!$live -or [datetime]::UtcNow -ge [datetime]::Parse($lease.ExpiresUTC).ToUniversalTime()){Invoke-TLSCleanup $dir.FullName|Out-Null}
 }
}
