$ErrorActionPreference='Stop'
. ../app/Proxy-Startup-Status.ps1
$script:ProxyStartupPath='/data/qa/v251/status.json'
foreach($phase in @('Starting','Ready','Failed','Closed')){
 Set-ProxyStartupStatus $phase 'Test startup state'
 $d=Get-Content -LiteralPath $script:ProxyStartupPath -Raw|ConvertFrom-Json
 if($d.Phase -ne $phase -or $d.Version -ne '2.5.1'){throw 'Startup phase round-trip failed'}
 if(Test-Path ($script:ProxyStartupPath+'.tmp')){throw 'Temporary state file left behind'}
}
Set-ProxyStartupStatus 'Failed' ('C:\Users\PRIVATE_USER\Desktop\Proxy-Probe.cs: compiler failure'+[Environment]::NewLine+('x'*2200))
$d=Get-Content -LiteralPath $script:ProxyStartupPath -Raw|ConvertFrom-Json
if($d.Message.Length -gt 1800 -or $d.Message.Contains('PRIVATE_USER')){throw 'Diagnostic redaction failed'}
'Startup phase writes, atomic replacement, message length and Windows path redaction: PASS'
