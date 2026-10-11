# Owned fake saved-session files and header-only PE bytes. Never executes PE files, targets or CDB.
$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
$old=$env:LOCALAPPDATA;$temp=Join-Path $env:TEMP ('RM-own-offline-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temp)
try{
 $env:LOCALAPPDATA=$temp;$folder=Join-Path $temp ('ExeRouteMonitor\PreTLS-PRIVATE\'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($folder)
 $fake=Join-Path $temp 'OwnHeaderOnly.bin';$bytes=New-Object byte[] 1024
 function SetBytes($offset,$value){[Array]::Copy($value,0,$bytes,$offset,$value.Length)}
 SetBytes 0 ([BitConverter]::GetBytes([uint16]0x5a4d));SetBytes 0x3c ([BitConverter]::GetBytes([uint32]0x80));SetBytes 0x80 ([BitConverter]::GetBytes([uint32]0x4550));SetBytes 0x84 ([BitConverter]::GetBytes([uint16]0x8664));SetBytes 0x94 ([BitConverter]::GetBytes([uint16]0xf0));SetBytes 0x98 ([BitConverter]::GetBytes([uint16]0x20b));SetBytes 0xd0 ([BitConverter]::GetBytes([uint32]0x1000));[IO.File]::WriteAllBytes($fake,$bytes)
 $hash=(Get-FileHash -LiteralPath $fake -Algorithm SHA256).Hash
 $log=Join-Path $folder 'PRIVATE-cdb.txt'
 $text=@'
RM_INITIAL_EVENT_BEGIN
Last event: 1234.abcd: Break instruction exception - code 80000003 (first chance)
ExceptionAddress: 00000001`80000123 (SENSITIVE_NAME+0x123)
ExceptionCode: 80000003 (Break instruction exception)
RM_INITIAL_EVENT_END
RM_CONTEXT_BEGIN
Last event: 1234.abcd: Break instruction exception - code 80000003 (first chance)
. 2 Id: 1234.abcd Suspend: 1 Teb: 00000000`00112233 Unfrozen
00000000`11223344 00000001`80000456 : 00000000`99887766 SENSITIVE_ARGS
RM_CONTEXT_END
'@
 [IO.File]::WriteAllText($log,$text)
 @{Root=$folder;LogPath=$log;TargetId=0x1234}|ConvertTo-Json|Set-Content (Join-Path $folder 'PRIVATE-ui-session.json') -Encoding UTF8
 @{ModuleFiles=@(@{Kind='Loader';Path=$fake;BaseAddress='0x180000000';FileSHA256=$hash});EventThreadId=0xabcd;ThreadStartAddress='0x180000789'}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $folder 'PRIVATE-startup-metadata.json') -Encoding UTF8
 @{Collection='Collected';EventThreadQuery='Success';Loader=@{Present=$true;SHA256=$hash;FileBytes=1024}}|ConvertTo-Json -Depth 6|Set-Content (Join-Path $folder 'startup-metadata-safe.json') -Encoding UTF8
 $output=Join-Path $temp 'RVA-to-share.json'
 & (Join-Path $base 'Extract-RVA.ps1') -SessionFolder $folder -OutputPath $output
 $json=Get-Content $output -Raw;$r=$json|ConvertFrom-Json
 if($r.ExtractionState -ne 'SnapshotAccepted' -or $r.InitialException.Point.RVA -ne '0x123' -or $r.RecordedThreadStart.RVA -ne '0x789' -or $r.StackReturnAddresses.Rows[0].ReturnPoint.RVA -ne '0x456' -or $r.ModuleFingerprints.Count -ne 1){throw 'OfflineWindowsValidRecordFailed'}
 if($json -match 'SENSITIVE|C:\\|180000123|11223344|99887766|OwnHeaderOnly|EventThreadId|ThreadStartAddress|BaseAddress') {throw 'OfflinePrivacyFailed'}
 # Changed disk file is not a valid mapping source, even if recorded hash/paths look plausible.
 $bytes[1023]=1;[IO.File]::WriteAllBytes($fake,$bytes)
 & (Join-Path $base 'Extract-RVA.ps1') -SessionFolder $folder -OutputPath $output
 $r=Get-Content $output -Raw|ConvertFrom-Json
 if($r.ModuleFingerprints.Count -ne 0 -or $null -ne $r.InitialException.Point -or $null -ne $r.RecordedThreadStart){throw 'ChangedFileNotRejected'}
 $refused=$false;try{& (Join-Path $base 'Extract-RVA.ps1') -SessionFolder $temp -OutputPath $output}catch{$refused=$true};if(!$refused){throw 'OutsideSessionNotRefused'}
 & (Join-Path $base 'Easy-RVA.ps1') -LayoutSmoke
 Write-Host '::notice title=Own offline RVA Windows PASS::Read owned saved-session fixture and non-executable PE header bytes; correct exception/start/return RVAs; no paths, absolute addresses, symbols or arguments exported; changed disk hash discarded; outside session refused; GUI constructed. No CDB/game/network.'
}finally{$env:LOCALAPPDATA=$old;Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue}
