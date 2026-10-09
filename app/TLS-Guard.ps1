#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$SessionPath)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'TLS-Cleanup.ps1')
try{
 $lease=Read-TLSLease $SessionPath
 [ordered]@{Ready=$true;UTC=[datetime]::UtcNow.ToString('o')}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $SessionPath 'guard-ready.json') -Encoding UTF8
 $watch=[Diagnostics.Stopwatch]::StartNew()
 while($true){
  if(Test-Path -LiteralPath (Join-Path $SessionPath 'cleanup.json')){
   $done=Get-Content -LiteralPath (Join-Path $SessionPath 'cleanup.json') -Raw|ConvertFrom-Json
   if($done.CertificateAbsent -and $done.ProxyStopped){break}
  }
  $live=$false
  try{$owner=Get-Process -Id $lease.OwnerPID -ErrorAction Stop;$live=($owner.StartTime.ToUniversalTime().Ticks.ToString() -eq $lease.OwnerStartTicks);$owner.Dispose()}catch{}
  if(!$live -or [datetime]::UtcNow -ge [datetime]::Parse($lease.ExpiresUTC).ToUniversalTime() -or $watch.Elapsed.TotalSeconds -ge 300){
   Invoke-TLSCleanup $SessionPath|Out-Null;break
  }
  Start-Sleep -Seconds 1
 }
}catch{exit 1}
