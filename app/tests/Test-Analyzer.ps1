# Runs mock-data unit tests, not a real Windows capture integration test.
$ErrorActionPreference='Stop'
$base=Split-Path -Parent $PSScriptRoot
$work=Join-Path ([IO.Path]::GetTempPath()) ('ExeRouteMonitor-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
 $capture=Join-Path $work 'fixture.pcapng'; [IO.File]::WriteAllText($capture,'synthetic placeholder; no packets')
 $context=Join-Path $work 'fixture.json'; $report=Join-Path $work 'report.json'
 $connections=@()
 foreach($spec in @(@('192.0.2.1:50000','203.0.113.10',80,'TCP','Snapshot','Established'),@('2001:db8::1:50001','2001:db8::2',80,'TCP','Snapshot','Established'),@('192.0.2.1:50002','203.0.113.10',80,'TCP','Sysmon','Inbound event'),@('192.0.2.1:50003','203.0.113.11',9999,'UDP','Sysmon','Outbound event'))) {
  $connections+=@{FirstUTC='2026-01-01T00:00:00Z';LastUTC='2026-01-01T00:00:10Z';Local=$spec[0];RemoteIP=$spec[1];Port=$spec[2];Protocol=$spec[3];Source=$spec[4];State=$spec[5];PID=100;Process='Fixture.exe'}
 }
 @{Target='Fixture.exe';Connections=$connections} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $context -Encoding UTF8
 & (Join-Path $base 'Analyze-Capture.ps1') -CapturePath $capture -ContextPath $context -OutputPath $report -TsharkPath (Join-Path $PSScriptRoot 'Mock-Tshark.ps1') -CompareLocalIdentifiers
 $d=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
 if($d.AllCapturedFrames -ne 7 -or $d.CorrelatedOutboundFrames -ne 4 -or $d.TLSRecognizedFrames -ne 1 -or $d.ReadableEvidenceFrames -ne 2){throw 'Frame counters failed.'}
 $r=@($d.Evidence | Where-Object {$_.HTTPMethod -eq 'POST'})[0]
 foreach($name in @('computer_name','username','cpu')){if($r.SystemOrSensitiveFieldNames -notcontains $name){throw ('Missing field indicator: '+$name)}}
 if([Environment]::MachineName.Length -ge 4 -and $r.LocalIdentifierMatchKinds -notcontains 'ComputerName'){throw 'Computer-name match failed.'}
 if([Environment]::UserName.Length -ge 4 -and $r.LocalIdentifierMatchKinds -notcontains 'WindowsUserName'){throw 'Username match failed.'}
 if((Get-Content -LiteralPath $report -Raw) -match 'SECRET_FIXTURE'){throw 'Query value leaked.'}
 if($d.MissingTsharkFields -notcontains 'http2.streamid'){throw 'Missing-field reporting failed.'}
 Write-Host 'PASS: IPv4/IPv6, outbound UDP, HTTP hex-body decoding, system field indicators, optional local IDs, unrelated tuple exclusion, inbound exclusion, time-window exclusion, opaque TLS/UDP, URL redaction and missing-field reporting.'
 & (Join-Path $base 'Analyze-Capture.ps1') -CapturePath $capture -ContextPath $context -OutputPath $report -TsharkPath (Join-Path $PSScriptRoot 'Mock-Tshark.ps1')
 $d=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
 if($d.LocalIdentifierComparisonEnabled -or @($d.LocalIdentifierMatchFrameCounts.PSObject.Properties).Count){throw 'Opt-out baseline test failed.'}
 Write-Host 'PASS: local identifier comparison disabled by default.'
 $oldWarning=$env:RM_TEST_WARNING;$oldFatal=$env:RM_TEST_FATAL
 try {
  $env:RM_TEST_WARNING='1'
  & (Join-Path $base 'Analyze-Capture.ps1') -CapturePath $capture -ContextPath $context -OutputPath $report -TsharkPath (Join-Path $PSScriptRoot 'Mock-Tshark.ps1')
  $d=Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
  if($d.TsharkExitCode -ne 0 -or $d.QuarantinedPacketCount -ne 1 -or $d.CorrelatedOutboundFrames -ne 3 -or $d.ReadableEvidenceFrames -ne 2){throw 'Warning/quarantine test failed.'}
  if(Test-Path -LiteralPath ($report+'.packet-fields.tmp')){throw 'Temporary field data not cleaned.'}
  Write-Host 'PASS: native X509-style stderr warning does not terminate PowerShell; affected frame quarantined, partial report produced, temporary data deleted.'
  $env:RM_TEST_WARNING='';$env:RM_TEST_FATAL='1';$caught=$false
  try {& (Join-Path $base 'Analyze-Capture.ps1') -CapturePath $capture -ContextPath $context -OutputPath $report -TsharkPath (Join-Path $PSScriptRoot 'Mock-Tshark.ps1')}catch{$caught=$true}
  if(!$caught -or (Test-Path -LiteralPath $report)){throw 'Fatal exit was not preserved.'}
  if(Test-Path -LiteralPath ($report+'.packet-fields.tmp')){throw 'Failure temporary data not cleaned.'}
  Write-Host 'PASS: genuine nonzero tool exit remains a fatal analysis error; no misleading success report.'
 } finally {$env:RM_TEST_WARNING=$oldWarning;$env:RM_TEST_FATAL=$oldFatal}

} finally {Remove-Item -LiteralPath $work -Recurse -Force}
