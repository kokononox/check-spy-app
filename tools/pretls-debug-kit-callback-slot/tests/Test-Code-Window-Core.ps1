$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot;. (Join-Path $base 'Code-Window-Core.ps1')
$n=0;function Check($v,$why){if(!$v){throw $why};$script:n++}
[byte[]]$expected=0..31
$row1=($expected[0..15]|ForEach-Object {$_.ToString('x2')}) -join ' ';$row2=($expected[16..31]|ForEach-Object {$_.ToString('x2')}) -join ' '
$t="RM_CODE_ENTRY_BEGIN`n00000001``80001000  $row1  PRIVATE_ASCII`n00000001``80001010  $row2  PRIVATE_ASCII`nRM_CODE_ENTRY_END"
$r=Get-RMCodeWindowComparison $t 'ENTRY' 0x180001000 $expected
Check ($r.ReadState -eq 'CompleteSmallWindow' -and $r.EqualToDisk -and $r.ComparedBytes -eq 32) 'Exact 32-byte comparison'
Check (($r|ConvertTo-Json -Depth 6) -notmatch 'PRIVATE|180001000|00 01 02|DiskHex') 'No raw bytes/ASCII/address export'
Check ($r.DiskSHA256 -eq $r.MemorySHA256 -and $r.DiskSHA256.Length -eq 64) 'Digest agreement'
$r=Get-RMCodeWindowComparison ($t.Replace('14 15 16','cc 15 16')) 'ENTRY' 0x180001000 $expected
Check (!$r.EqualToDisk -and $r.ChangedByteOffsets.Count -eq 1 -and $r.ChangedByteOffsets[0] -eq 20 -and $r.MemoryInt3ByteOffsets[0] -eq 20) 'Single artificial mismatch/CC offset'
Check ($r.DiskSHA256 -ne $r.MemorySHA256 -and $r.DifferenceCause -eq 'NotEstablished') 'No cause claim from digest mismatch'
Check ((Get-RMCodeWindowComparison ($t.Replace('80001010','80001020')) 'ENTRY' 0x180001000 $expected).ReadState -eq 'NotEstablished') 'Discontinuous rows refused'
Check ((Get-RMCodeWindowComparison ($t.Replace('RM_CODE_ENTRY_END','')) 'ENTRY' 0x180001000 $expected).ReadState -eq 'NotEstablished') 'Incomplete window refused'
Check ((Get-RMCodeWindowComparison ($t+"`nRM_CODE_GUARD_REJECTED") 'ENTRY' 0x180001000 $expected).ReadState -eq 'NotEstablished') 'Code guard rejection overrides data'
Check ((Get-RMCodeWindowComparison ("RM_BEGIN ctx=0/0 declared=0 captured=0`n"+$t+"`nRM_END") 'ENTRY' 0x180001000 $expected).ReadState -eq 'NotEstablished') 'Payload markers ignored'
Check ((Get-RMCodeWindowComparison ($t.Replace('00 01','?? 01')) 'ENTRY' 0x180001000 $expected).ReadState -eq 'NotEstablished') 'Unreadable memory refused'
Check ((Get-RMCodeWindowComparison ($t.Replace('07 08','07-08')) 'ENTRY' 0x180001000 $expected).EqualToDisk) 'CDB half-row dash supported'
$cmd=New-RMIndependentCodeCommands 1 0x7ff000001234 0x180001000 0x180002000
Check ($cmd -match 'db /c 0x10 0x180001000 L0x20' -and $cmd -match 'db /c 0x10 0x180002000 L0x10' -and $cmd -match '@rip == 0x7ff000001234') 'Exact 48-byte reads guarded by current event'
Check ($cmd -notmatch 'WriteProcessMemory|SetThreadContext|(?:^|;\s)(?:g|gn|gh)(?:;|\s|$)') 'No target change/resume commands'
$dir=Join-Path ([IO.Path]::GetTempPath()) ('RM-own-code-core-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
try{
 $p=Join-Path $dir 'OWN-header-only.bin';$bytes=New-Object byte[] 1024
 function SetBytes($off,$v){[Array]::Copy($v,0,$bytes,$off,$v.Length)}
 SetBytes 0 ([BitConverter]::GetBytes([uint16]0x5a4d));SetBytes 0x3c ([BitConverter]::GetBytes([uint32]0x80));SetBytes 0x80 ([BitConverter]::GetBytes([uint32]0x4550));SetBytes 0x84 ([BitConverter]::GetBytes([uint16]0x8664));SetBytes 0x86 ([BitConverter]::GetBytes([uint16]1));SetBytes 0x94 ([BitConverter]::GetBytes([uint16]0xf0));SetBytes 0x98 ([BitConverter]::GetBytes([uint16]0x20b));SetBytes 0x190 ([BitConverter]::GetBytes([uint32]0x100));SetBytes 0x194 ([BitConverter]::GetBytes([uint32]0x1000));SetBytes 0x198 ([BitConverter]::GetBytes([uint32]0x100));SetBytes 0x19c ([BitConverter]::GetBytes([uint32]0x200));SetBytes 0x1ac ([BitConverter]::GetBytes([uint32]0x20000000));SetBytes 0x210 $expected;[IO.File]::WriteAllBytes($p,$bytes)
 $w=Read-RMStaticCodeWindow $p 0x1010 32;Check ($w.Length -eq 32 -and $w[20] -eq 20) 'File RVA to executable raw section window'
 $bad=$false;try{Read-RMStaticCodeWindow $p 0x10ff 32|Out-Null}catch{$bad=$true};Check $bad 'Cross-section/window boundary refused'
 SetBytes 0x1ac ([BitConverter]::GetBytes([uint32]0));[IO.File]::WriteAllBytes($p,$bytes)
 $bad=$false;try{Read-RMStaticCodeWindow $p 0x1010 32|Out-Null}catch{$bad=$true};Check $bad 'Nonexecutable section refused'
 $bad=$false;try{Read-RMStaticCodeWindow $p 0x1010 4096|Out-Null}catch{$bad=$true};Check $bad 'Large window refused'
}finally{Remove-Item $dir -Recurse -Force}
$diag=[pscustomobject]@{InitialWaiting=$true;UserInitialContinueMarker=$false;PromptContinueCommands=0;InitialGate='ExpectedInitialBreakAwaitingUser'}
$ev=[pscustomobject]@{Complete=$true;ProcessId=1;ThreadId=2;Code='80000003';RecordCode='80000003';Chance='first'}
Check (Test-RMCodeReadEligibility $diag $ev 1) 'Expected ntdll initial break eligible for reading only'
$diag.InitialGate='InitialBreakLocationUnverified';Check (Test-RMCodeReadEligibility $diag $ev 1) 'Unknown loader initial break eligible for same reading'
$diag.UserInitialContinueMarker=$true;Check (!(Test-RMCodeReadEligibility $diag $ev 1)) 'Prior continuation refuses code reading';$diag.UserInitialContinueMarker=$false
$diag.InitialGate='EventChangedAfterSnapshot';Check (!(Test-RMCodeReadEligibility $diag $ev 1)) 'Event changed refuses';$diag.InitialGate='ExpectedInitialBreakAwaitingUser'
$ev.Chance='second';Check (!(Test-RMCodeReadEligibility $diag $ev 1)) 'Second chance refuses';$ev.Chance='first'
Check (!(Test-RMCodeReadEligibility $diag $ev 99)) 'Wrong target refuses'
$independent=New-RMIndependentCodeCommands 1 0x7ff000001234 0x180001000 0x180002000
Check ($independent -match '@rip == 0x7ff000001234' -and $independent -match 'db /c 0x10 0x180001000 L0x20') 'Guard uses current event independently of configured sites'
Check ($independent -notmatch 'poi|dq|frame /c /r 0x1') 'No slot/frame1 dependency in new command'
$reader=Get-Content (Join-Path $base 'Code-Windows.ps1') -Raw
Check ($reader -notmatch 'Get-RMRecordedCallbackFrame|TopReturnAddress|CallerStackPointer|GenerateConsoleCtrlEvent|WriteProcessMemory|ResumeThread|SetThreadContext') 'Reader independent and read-only'
Write-Host ('PASS: '+$n+' bounded code window/file/parser/privacy assertions')
