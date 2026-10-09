$ErrorActionPreference='Stop'
$script='../app/Inspect-Target.ps1'
$before=(Get-FileHash /data/qa/v24/fixture.exe).Hash
& $script -TargetPath /data/qa/v24/fixture.exe -OutputPath /data/qa/v24/report.json -SelectedLogPath /data/qa/v24/Logs/private-user-DO_NOT_EXPORT.log | Out-Null
$d=Get-Content /data/qa/v24/report.json -Raw|ConvertFrom-Json
if($d.PEImportInspectionFailed -or $d.RecognizedNetworkImports -notcontains 'winhttp.dll' -or $d.StaticMarkerNames -notcontains 'SSLKEYLOGFILE'){throw 'PE fixture failed'}
if($d.SelectedLogSummary.FieldNameOccurrenceCounts.username -ne 1 -or $d.SelectedLogSummary.FieldNameOccurrenceCounts.authorization -ne 1){throw 'Log counts failed'}
$raw=Get-Content /data/qa/v24/report.json -Raw
if($raw -match 'PRIVATE_|SECRET_VALUE|example.test|DO_NOT_EXPORT|/data/qa'){throw 'Privacy check failed'}
if((Get-FileHash /data/qa/v24/fixture.exe).Hash -ne $before){throw 'Target changed'}
& $script -TargetPath /data/qa/v24/bad.exe -OutputPath /data/qa/v24/bad.json | Out-Null
if(!(Get-Content /data/qa/v24/bad.json -Raw|ConvertFrom-Json).PEImportInspectionFailed){throw 'Malformed PE not identified'}
& $script -TargetPath /data/vendor-downloads/Sysmon-extracted/Sysmon64.exe -OutputPath /data/qa/v24/real.json | Out-Null
if((Get-Content /data/qa/v24/real.json -Raw|ConvertFrom-Json).PEImportInspectionFailed){throw 'Real PE test failed'}
Write-Output 'PASS: imports, markers, allowlisted log counts, privacy sentinel, read-only target, malformed PE, repeated invocation, real PE64'
