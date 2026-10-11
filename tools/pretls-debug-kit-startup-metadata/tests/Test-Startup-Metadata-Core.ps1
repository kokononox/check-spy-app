$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
. (Join-Path $base 'Startup-Metadata-Core.ps1')
$n=0;function Check($v,$label){if(!$v){throw $label};$script:n++}
$t=@'
RM_INITIAL_EVENT_BEGIN
Last event: 1234.abcd: Break instruction exception - code 80000003 (first chance)
RM_INITIAL_EVENT_END
'@
$e=Get-RMInitialEventIdentity $t
Check ($e.Complete -and $e.ProcessId -eq 0x1234 -and $e.ThreadId -eq 0xabcd -and $e.Code -eq '80000003' -and $e.Chance -eq 'first') 'Event identity parsed bounded snapshot'
Check (!(Get-RMInitialEventIdentity ($t.Replace('RM_INITIAL_EVENT_END',''))).Complete) 'Incomplete event snapshot'
Check (!(Get-RMInitialEventIdentity ("RM_BEGIN ctx=0/0 declared=0 captured=0`n"+$t+"`nRM_END")).Complete) 'Payload excluded'
$context=@'
RM_CONTEXT_BEGIN
Last event: 1234.abcd: Break instruction exception - code 80000003 (first chance)
. 12 Id: 1234.abcd Suspend: 1 Teb: 00000000`00000000 Unfrozen
 # Child-SP          RetAddr           Call Site
00 00000000`11111111 00000000`22222222 ntdll!DbgBreakPoint
01 00000000`33333333 00000000`44444444 ntdll!DbgUiRemoteBreakin+0x33
02 00000000`55555555 00000000`66666666 kernel32!BaseThreadInitThunk
RM_CONTEXT_END
'@
$c=Get-RMContextIndicators $context
Check ($c.Complete -and $c.CurrentContextMatchesLastEventThread -and $c.StackFrameRowsObserved -eq 3) 'Context tied to last event thread'
Check ($c.RemoteBreakinSymbolTextObserved -and $c.DbgBreakPointSymbolTextObserved -and $c.ThreadStartSymbolTextObserved) 'Whitelist-only stack indicators'
Check ($c.Origin -eq 'NotEstablished' -and $c.StackSymbolsAreTextEvidenceNotProof) 'No origin authorization from stack text'
Check (($c|ConvertTo-Json) -notmatch '11111111|22222222|1234|abcd') 'No context addresses/IDs export'
Check (!(Get-RMContextIndicators ($context.Replace('Id: 1234.abcd','Id: 1234.aaaa'))).CurrentContextMatchesLastEventThread) 'Different current thread rejected'
Check (!(Get-RMContextIndicators ($context.Replace('RM_CONTEXT_END',''))).Complete) 'Incomplete context unknown'
Check (!(Get-RMContextIndicators ("RM_BEGIN ctx=0/0 declared=0 captured=0`n"+$context+"`nRM_END")).Complete) 'Payload context spoof excluded'
$ranges=@([pscustomobject]@{Kind='SystemNtdll';Base=1000;Size=100},[pscustomobject]@{Kind='Loader';Base=2000;Size=100},[pscustomobject]@{Kind='MainExecutable';Base=3000;Size=100})
Check ((Get-RMThreadStartClass 1010 $ranges 1010 $true) -eq 'NtdllRemoteBreakinAddressMatchNotOriginProof') 'Verified address match hint'
Check ((Get-RMThreadStartClass 1010 $ranges 1010 $false) -eq 'OtherNtdllAddress') 'Unverified system file cannot be remote-breakin match'
Check ((Get-RMThreadStartClass 2050 $ranges $null $false) -eq 'LoaderAddress') 'Loader mapping'
Check ((Get-RMThreadStartClass 3050 $ranges $null $false) -eq 'MainExecutableAddress') 'Main mapping'
Check ((Get-RMThreadStartClass 2100 $ranges $null $false) -eq 'NotInEnumeratedModuleRanges') 'Range upper bound excluded'
Check ((Get-RMThreadStartClass 0 $ranges $null $false) -eq 'NotEstablished') 'Zero address unknown'
$dir=Join-Path ([IO.Path]::GetTempPath()) ('RM-meta-test-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($dir)
try{
 @{Collection='Collected';FailureStage='None';Loader=@{Present=$true;SHA256=('a'*64);FileBytes=100;MatchesSuppliedBaseline=$false;PrivatePath='C:\SECRET\token'};EventThreadQuery='Success';EventThreadStartClass='LoaderAddress';ThreadStartAddress='SECRET_POINTER';BreakpointOrigin='Confirmed';ContinuationAuthorized=$true;ContextCommandsQueued=$true}|ConvertTo-Json -Depth 4|Set-Content (Join-Path $dir 'startup-metadata-safe.json') -Encoding UTF8
 $safe=Get-RMSafeStartupMetadata $dir
 Check ($safe.Loader.SHA256 -eq ('a'*64) -and $safe.Loader.MatchesSuppliedBaseline -eq $false) 'Hashes and mismatch preserved'
 Check (($safe|ConvertTo-Json -Depth 6) -notmatch 'SECRET|token|PrivatePath|ThreadStartAddress') 'Unsafe additional fields discarded'
 Check (!$safe.ContinuationAuthorized -and $safe.BreakpointOrigin -eq 'NotEstablished') 'Untrusted file cannot authorize continuation'
 @{Loader=@{Present=$true;SHA256='https://PRIVATE';FileBytes=-3};EventThreadStartClass='SECRET'}|ConvertTo-Json -Depth 4|Set-Content (Join-Path $dir 'startup-metadata-safe.json') -Encoding UTF8
 $safe=Get-RMSafeStartupMetadata $dir
 Check ($null -eq $safe.Loader.SHA256 -and $null -eq $safe.Loader.FileBytes -and $safe.EventThreadStartClass -eq 'NotEstablished') 'Invalid scalar values refused'
}finally{Remove-Item $dir -Recurse -Force}
$source=[IO.File]::ReadAllText((Join-Path $base 'Startup-Metadata.ps1'))
Check ($source -notmatch 'GenerateConsoleCtrlEvent|WriteProcessMemory|SetThreadContext|ResumeThread|TerminateProcess') 'No interrupt, memory write or thread/process control'
Check ($source -match 'string cmd="\.echo RM_CONTEXT_BEGIN; \.lastevent; ~\.; kv 0x8; \.echo RM_CONTEXT_END\\r";') 'Exact bounded read-only context commands'
Write-Host ('PASS: '+$n+' synthetic startup event/module/thread/context/privacy assertions.')
