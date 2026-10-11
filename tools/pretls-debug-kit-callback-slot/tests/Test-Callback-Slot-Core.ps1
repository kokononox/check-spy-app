$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot;. (Join-Path $base 'Callback-Slot-Core.ps1')
$n=0;function Check($v,$why){if(!$v){throw $why};$script:n++}
$t=@'
RM_CONTEXT_BEGIN
Last event: 1234.abcd: Break instruction exception - code 80000003 (first chance)
. 2 Id: 1234.abcd Suspend: 1 Teb: 00000000`99999999 Unfrozen
00 00000000`11111000 00000001`80000500 PRIVATE_SYMBOL
01 00000000`11111100 00007fff`00000001 PRIVATE_ARGUMENT
RM_CONTEXT_END
'@
$f=Get-RMRecordedCallbackFrame $t
Check ($f.TopReturnAddress -eq 0x180000500 -and $f.CallerStackPointer -eq 0x11111100) 'Frame1 bounded private parsing'
Check ($null -eq (Get-RMRecordedCallbackFrame ($t.Replace('Id: 1234.abcd','Id: 1234.aaaa')))) 'Wrong context thread refused'
Check ($null -eq (Get-RMRecordedCallbackFrame ($t.Replace('RM_CONTEXT_END','')))) 'Incomplete context refused'
Check ($null -eq (Get-RMRecordedCallbackFrame ("RM_BEGIN ctx=0/0 declared=0 captured=0`n"+$t+"`nRM_END"))) 'Captured payload context ignored'
$cmd=New-RMCallbackSlotCommands 0xabcd 0x180000400 0x180000500 0x11111100 0x30
Check ($cmd -match 'dq @rsp\+0x30 L0x1' -and $cmd -match '@rip == 0x180000500' -and $cmd -match '@rsp == 0x11111100' -and $cmd -match '@\$tid == 0xabcd') 'Exact one-slot read and current TID/RIP/RSP guards'
Check ($cmd -match '\.frame /c /r 0x1' -and $cmd -match '~~\[0xabcd\]s; \.echo RM_SLOT_CONTEXT_RESTORED') 'Same recorded OS thread reselected to reset local override'
Check ($cmd -notmatch '(?:^|[;{}]\s*)(?:g|gn|gh|eb|eq|ed|r\s+@|\.detach|q)(?:\s|;|$)') 'No resume/memory write/detach in snapshot'
$bad=$false;try{New-RMCallbackSlotCommands 1 1 2 3 257|Out-Null}catch{$bad=$true};Check $bad 'Oversized offset refused'
$ranges=@([pscustomobject]@{Kind='Loader';Base=[uint64]0x180000000;Size=[uint64]0x1000})
$log="RM_SLOT_BEGIN`n00000000``11111130 00000001``80000400`nRM_SLOT_END`nRM_SLOT_CONTEXT_RESTORED`nRM_SLOT_DONE"
$r=Get-RMCallbackSlotResult $log 0x11111130 $ranges
Check ($r.ReadState -eq 'OneSlotReadNotActualCallProof' -and $r.CandidatePoint.RVA -eq '0x400') 'One candidate relative point'
Check (($r|ConvertTo-Json -Depth 6) -notmatch '11111130|180000400') 'Raw slot/pointer not exported'
Check (!$r.ContinuationAuthorized -and $r.SlotIsCandidateNotProvenCallTarget -and $r.UnwindAccuracy -eq 'NotEstablished') 'No call/unwind/continuation proof'
Check ((Get-RMCallbackSlotResult ($log+"`nRM_SLOT_GUARD_REJECTED") 0x11111130 $ranges).ReadState -eq 'GuardRejected') 'Guard rejection overrides apparent data'
Check ((Get-RMCallbackSlotResult ($log.Replace('RM_SLOT_CONTEXT_RESTORED','')) 0x11111130 $ranges).ReadState -eq 'NotEstablished') 'Missing restore marker refused'
Check ((Get-RMCallbackSlotResult $log 0x22222222 $ranges).ReadState -eq 'NotEstablished') 'Wrong slot address refused'
Check ((Get-RMCallbackSlotResult ($log.Replace('RM_SLOT_END',"00000000``11111138 00000001``80000500`nRM_SLOT_END")) 0x11111130 $ranges).ReadState -eq 'NotEstablished') 'Multiple qwords refused'
Check ($null -eq (Get-RMCallbackSlotResult ($log.Replace('80000400','90000400')) 0x11111130 $ranges).CandidatePoint) 'Unmapped candidate discarded'
Check ((Get-RMCallbackSlotResult ("RM_BEGIN ctx=0/0 declared=0 captured=0`n"+$log+"`nRM_END") 0x11111130 $ranges).ReadState -eq 'NotEstablished') 'Payload marker spoof ignored'
$dir=Join-Path ([IO.Path]::GetTempPath()) ('RM-slot-core-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
try{
 $p=Join-Path $dir 'config.json';@{LoaderSHA256=('a'*64);ExceptionRVA=1024;CallerReturnRVA=1280;SlotOffset=48;Malicious='SECRET'}|ConvertTo-Json|Set-Content $p -Encoding UTF8
 $c=Get-RMCallbackConfig $p;Check ($c.SlotOffset -eq 48 -and ($c|ConvertTo-Json) -notmatch 'SECRET') 'Numeric allowlist config'
 @{LoaderSHA256=('a'*64);ExceptionRVA='g';CallerReturnRVA=1280;SlotOffset=48}|ConvertTo-Json|Set-Content $p -Encoding UTF8
 $bad=$false;try{Get-RMCallbackConfig $p|Out-Null}catch{$bad=$true};Check $bad 'String command injection refused'
}finally{Remove-Item $dir -Recurse -Force}
$s=Get-Content (Join-Path $base 'Callback-Slot.ps1') -Raw
Check ($s -notmatch 'GenerateConsoleCtrlEvent|WriteProcessMemory|SetThreadContext|ResumeThread|TerminateProcess') 'No interrupt/write/resume/termination APIs'
# Compile owned console interop without executing any Windows native calls.
$code=([regex]::Match($s,"(?s)Add-Type -TypeDefinition @'\r?\n(.*?)\r?\n'@")).Groups[1].Value
if(!$code){throw 'InteropMissing'};Add-Type -TypeDefinition $code
Check $true 'Console interop compilation'
Write-Host ('PASS: '+$n+' callback slot/numeric guard/privacy assertions')
