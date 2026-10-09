$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Local-Log-Audit.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Build-Unified-Report.ps1')
$root=Join-Path ([IO.Path]::GetTempPath()) ('rm27-'+[guid]::NewGuid().ToString('N'));$logs=Join-Path $root 'Logs';[void][IO.Directory]::CreateDirectory($logs)
try{
 $target=Join-Path $root 'fixture.exe';[IO.File]::WriteAllText($target,'synthetic')
 $start=[datetime]::UtcNow;$stamp=$start.ToLocalTime().ToString('M/d HH:mm:ss.fff',[Globalization.CultureInfo]::InvariantCulture)
 $cpu=Join-Path $logs 'cpu.log';[IO.File]::WriteAllText($cpu,'old undated content')
 $baseline=Get-RM27LogBaseline $target
 [IO.File]::WriteAllText($cpu,"$stamp  branding: PRIVATE_CPU_VALUE`n$stamp  cores: 8`n1/1 00:00:00.000  vendor: OLD_OUT_OF_WINDOW`nUNDATED_PRIVATE_SENTINEL")
 [IO.File]::WriteAllText((Join-Path $logs 'gx.log'),"$stamp  Motherboard: PRIVATE_BOARD (BIOS:PRIVATE_BIOS)`n$stamp  16 GB System Memory`n$stamp  Adapter 0: PRIVATE_GPU driver_ver:PRIVATE_DRIVER")
 [IO.File]::WriteAllText((Join-Path $logs 'Client.log'),"$stamp  Character Login SEND")
 [IO.File]::WriteAllText((Join-Path $logs 'Tact.log'),"$stamp  Downloading config with key PRIVATE_CONFIG")
 $audit=Complete-RM27LogAudit $baseline $start ([datetime]::UtcNow.AddSeconds(1))
 foreach($name in @('CPUModel','CPUCoreTopology','Motherboard','BIOS','PhysicalMemory','GPU','GPUDriver')){if($audit.LocalFieldCategories -notcontains $name){throw "Missing local category: $name"}}
 if($audit.LocalFieldCategories -contains 'CPUVendor'){throw 'Out-of-window row was interpreted'}
 if($audit.RecordedEvents -notcontains 'CharacterLoginSendRecorded'){throw 'Local event missing'}
 $raw=$audit|ConvertTo-Json -Depth 10;if($raw -match 'PRIVATE_|OLD_OUT|UNDATED_PRIVATE|fixture.exe|rm27-'){throw 'Local audit privacy leak'}
 # Unchanged logs must not be counted as new execution evidence.
 $second=Get-RM27LogBaseline $target;$none=Complete-RM27LogAudit $second $start ([datetime]::UtcNow.AddSeconds(1));if($none.LocalFieldCategories.Count){throw 'Unchanged historical logs interpreted'}
 # Appended content is read from baseline offset.
 [IO.File]::AppendAllText($cpu,"`n$stamp  features: PRIVATE_FEATURES");$appended=Complete-RM27LogAudit $second $start ([datetime]::UtcNow.AddSeconds(1));if($appended.LocalFieldCategories -notcontains 'CPUFeatures' -or $appended.LocalFieldCategories -contains 'CPUModel'){throw 'Append boundary failed'}
 $net=[pscustomobject]@{Target='fixture.exe';TargetSHA256AtSessionStart='SYNTHETIC_HASH';Capture='/private/capture.pcapng';AnalyzedCapture='/private/copy.pcapng';Normalization=$null;Endpoints=@([pscustomobject]@{RemoteIP='203.0.113.10';Port=80;Protocol='TCP';SNI=@();Hosts=@('fixture.invalid');CorrelatedOutboundFrames=1;CorrelatedInboundFrames=1;ReadableEvidenceFrames=1;TLSRecognizedFrames=0;ObservedOutboundTransportPayloadBytes=100;ObservedInboundTransportPayloadBytes=50;ObservedRetransmissionFrames=0;ByteLengthUnknownFrames=0;TLSVersionCodes=@();KnownALPN=@();TLSAlertCodes=@()});Evidence=@([pscustomobject]@{ReadableApplicationEvidence=$true;SystemOrSensitiveFieldNames=@('cpu');RequestURI='/private/SECRET_PATH?token=PRIVATE_TOKEN';HTTPUserAgent='PRIVATE_AGENT';HTTP2HeaderNames=':method,authorization,PRIVATE_HEADER';LocalIdentifierMatchKinds=@()});LocalIdentifierMatchFrameCounts=[pscustomobject]@{};LauncherDiagnostic=$null}
 $unified=ConvertTo-RM27Unified $net $audit;$json=$unified|ConvertTo-Json -Depth 18
 if($json -match 'PRIVATE_|SECRET_PATH|/private/|OLD_OUT'){throw 'Unified report privacy leak'}
 if($unified.EvidenceLevels.LocalLogOnlyCategories -notcontains 'CPUModel' -or $unified.EvidenceLevels.ReadableOutgoingFieldNameIndicators -notcontains 'cpu'){throw 'Evidence separation failed'}
 'PASS: timestamp window, rewrite, append, historical exclusion, fixed categories/events, no local values/paths, unified outgoing-vs-local separation, path/agent/header export redaction'
}finally{Remove-Item -LiteralPath $root -Recurse -Force}
