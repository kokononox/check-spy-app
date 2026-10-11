$ErrorActionPreference='Stop';. (Join-Path (Split-Path -Parent $PSScriptRoot) 'RVA-Core.ps1')
$n=0;function Check($v,$why){if(!$v){throw $why};$script:n++}
$m=@([pscustomobject]@{Kind='Loader';Base=[uint64]0x180000000;ImageBytes=[uint64]0x1000000;SHA256=('a'*64)},[pscustomobject]@{Kind='SystemNtdll';Base=[uint64]0x7ff000000000;ImageBytes=[uint64]0x100000;SHA256=('b'*64)})
$p=Convert-RMAddressToSafeRVA 0x180fb4806 $m;Check ($p.ModuleKind -eq 'Loader' -and $p.RVA -eq '0xfb4806') 'Correct loader RVA'
Check ($null -eq (Convert-RMAddressToSafeRVA 0x181000000 $m)) 'Upper bound excluded'
Check ($null -eq (Convert-RMAddressToSafeRVA 0 $m)) 'Null PC unknown'
Check ($null -eq (Convert-RMRecordedHex 'SECRET_URL')) 'Bad hex rejected'
Check ((Convert-RMRecordedHex '00000001`80fb4806') -eq 0x180fb4806) 'Backtick address accepted'
$overlap=@($m[0],$m[0]);Check ($null -eq (Convert-RMAddressToSafeRVA 0x180fb4806 $overlap)) 'Ambiguous ranges rejected'
$t=@'
RM_INITIAL_EVENT_BEGIN
Last event: 1234.abcd: Break instruction exception - code 80000003 (first chance)
ExceptionAddress: 00000001`80fb4806 (SECRET_MODULE+0xfb4806)
ExceptionCode: 80000003 (Break instruction exception)
RM_INITIAL_EVENT_END
RM_CONTEXT_BEGIN
Last event: 1234.abcd: Break instruction exception - code 80000003 (first chance)
. 2 Id: 1234.abcd Suspend: 1 Teb: 00000000`00112233 Unfrozen
00000000`11223344 00000001`80fb4460 : 00000000`99887766 SECRET_TOKEN C:\SECRET
01 00000000`11223355 00007ff0`00001234 SECRET_URL
02 00000000`11223366 00000000`00000000 SECRET
RM_CONTEXT_END
'@
$priv=[pscustomobject]@{EventThreadId=0xabcd;ThreadStartAddress='0x180fb4460';PrivatePath='C:\SECRET'}
$safe=[pscustomobject]@{Collection='Collected';EventThreadQuery='Success'}
$r=Get-RMOfflineRVAReport $t $priv $safe 0x1234 $m
Check ($r.ExtractionState -eq 'SnapshotAccepted') 'Matching snapshot accepted'
Check ($r.InitialException.Point.RVA -eq '0xfb4806' -and $r.RecordedThreadStart.RVA -eq '0xfb4460') 'Exception/start points'
Check ($r.StackReturnAddresses.Rows.Count -eq 3 -and $r.StackReturnAddresses.Rows[0].ReturnPoint.RVA -eq '0xfb4460') 'Unnumbered return-PC column extracted'
Check ($r.StackReturnAddresses.Rows[1].ReturnPoint.ModuleKind -eq 'SystemNtdll' -and $r.StackReturnAddresses.Rows[1].ReturnPoint.RVA -eq '0x1234') 'Numbered return-PC extracted'
Check ($null -eq $r.StackReturnAddresses.Rows[2].ReturnPoint) 'Null return address unknown'
$json=$r|ConvertTo-Json -Depth 10
Check ($json -notmatch 'SECRET|1234.abcd|11223344|99887766|180fb4806|PrivatePath|ThreadStartAddress') 'No pointers/symbols/args/paths/IDs'
Check (!$r.ContinuationAuthorized -and $r.BreakpointOrigin -eq 'NotEstablished' -and !$r.AbsoluteAddressesExported) 'No origin/continuation claim'
Check ($r.StackReturnAddresses.ReturnAddressesAreNotExecutedInstructions -and $r.StackReturnAddresses.UnwindAccuracy -eq 'NotEstablished') 'Stack limits explicit'
Check ((Get-RMOfflineRVAReport $t $priv $safe 0x9999 $m).ExtractionState -eq 'SnapshotNotAccepted') 'Wrong process refused'
$priv.EventThreadId=0xaaaa;Check ((Get-RMOfflineRVAReport $t $priv $safe 0x1234 $m).ExtractionState -eq 'SnapshotNotAccepted') 'Wrong event thread refused';$priv.EventThreadId=0xabcd
Check ($null -eq (Get-RMOfflineRVAReport ($t.Replace('Id: 1234.abcd','Id: 1234.aaaa')) $priv $safe 0x1234 $m).StackReturnAddresses) 'Context-thread mismatch discards stack'
Check ((Get-RMOfflineRVAReport ($t.Replace('ExceptionCode: 80000003','ExceptionCode: c0000005')) $priv $safe 0x1234 $m).ExtractionState -eq 'SnapshotNotAccepted') 'Record mismatch refused'
Check ((Get-RMOfflineRVAReport ($t.Replace('(first chance)','(second chance)')) $priv $safe 0x1234 $m).ExtractionState -eq 'SnapshotNotAccepted') 'Second chance refused'
Check (!(Get-RMExceptionRelativePoint ($t.Replace('RM_INITIAL_EVENT_END','')) $m).Complete) 'Incomplete initial record'
Check (!(Get-RMStackRelativeReturns ($t.Replace('RM_CONTEXT_END','')) $m).Complete) 'Incomplete stack rejected'
Check ((Get-RMOfflineRVAReport ("RM_BEGIN ctx=0/0 declared=0 captured=0`n"+$t+"`nRM_END") $priv $safe 0x1234 $m).ExtractionState -eq 'SnapshotNotAccepted') 'Captured payload markers excluded'
$safe.EventThreadQuery='NotEstablished';Check ($null -eq (Get-RMOfflineRVAReport $t $priv $safe 0x1234 $m).RecordedThreadStart) 'Unverified native query discarded'
$safe.Collection='NotConfirmed';Check ((Get-RMOfflineRVAReport $t $priv $safe 0x1234 $m).ExtractionState -eq 'SnapshotNotAccepted') 'Unconfirmed collection refused'
$base=Split-Path -Parent $PSScriptRoot
$source=(Get-Content (Join-Path $base 'Extract-RVA.ps1') -Raw)+(Get-Content (Join-Path $base 'RVA-Core.ps1') -Raw)
Check ($source -notmatch 'Get-Process|AttachConsole|WriteConsoleInput|GenerateConsoleCtrlEvent|WriteProcessMemory|ResumeThread|Start-Process|Invoke-WebRequest') 'No process/debugger/network operations in extraction'
Write-Host ('PASS: '+$n+' offline RVA/parser/privacy assertions')
