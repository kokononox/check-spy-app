param([string]$Root=(Split-Path $PSScriptRoot -Parent))
$ErrorActionPreference='Stop'
trap {Write-Output ('::error::Owned page fixture failure: '+$_.Exception.Message+'; line='+$_.InvocationInfo.ScriptLineNumber);exit 1}
Add-Type -Path (Join-Path $Root 'Query-Native.cs')
. (Join-Path $Root 'Query-Core.ps1')
$script:checks=0
function Check($ok,$label){if(-not $ok){throw ('Failed: '+$label)};$script:checks++}
$c=Get-RegionClassification 0x1000 0x104 0x1000000
Check $c.GuardFlag 'guard distinguished'
Check (-not $c.NoAccess) 'guard not noaccess'
Check ($c.State -eq 'MEM_COMMIT') 'commit label'
Check ($c.Type -eq 'MEM_IMAGE') 'image label'
Check ($c.LegacyBlockingReasons -contains 'GuardFlag') 'old precheck cause'
$c=Get-RegionClassification 0x1000 1 0x20000
Check $c.NoAccess 'noaccess distinguished'
Check (-not $c.GuardFlag) 'noaccess not guard'
Check ($c.Type -eq 'MEM_PRIVATE') 'private label'
$c=Get-RegionClassification 0x2000 1 0x20000
Check ($c.State -eq 'MEM_RESERVE') 'reserve label'
Check ($null -eq $c.NoAccess) 'undefined reserved protection ignored'
Check ($null -eq $c.Protection) 'no guessed reserved protection'
Check ($c.LegacyBlockingReasons -contains 'NotCommitted') 'reserve old cause'
$c=Get-RegionClassification 0x10000 0x104 0
Check ($c.State -eq 'MEM_FREE') 'free label'
Check ($null -eq $c.GuardFlag) 'undefined free guard ignored'
Check ($c.Type -eq 'NotApplicableForFreeMemory') 'free type ignored'
$c=Get-RegionClassification 0x1000 0x220 0x40000
Check $c.ExecutableProtection 'executable label'
Check ($c.ModifierFlags -contains 'PAGE_NOCACHE') 'nocache modifier'
Check (-not $c.LegacyReadPrecheckWouldBlock) 'nocache not conflated with guard'
$c=Get-RegionClassification 0x1000 0 0
Check ($c.Protection -eq 'UnspecifiedOrUnknown') 'unknown is not noaccess'
$base=[UInt64]0x140000000
$manifest=[pscustomobject]@{Version='SyntheticOnly';MainImageSize=65536;MaximumQueriesPerMethod=16;MaximumQueriesTotal=32
 Methods=@(0..4|ForEach-Object {[pscustomobject]@{Slot=$_;RVA=4096+256*$_;Bytes=64}})}
$script:mode='Normal';$script:called=0
$query={
 param([UInt64]$Address)
 $script:called++
 if($script:mode -eq 'Fail'){throw (New-Object PageStateOnly.QueryFailure -ArgumentList 'RegionQueryFailed',5)}
 $b=$Address;$n=[UInt64]4096
 if($script:mode -eq 'ShortRegions'){$n=[UInt64]16}
 return [pscustomobject]@{Base=$b;Bytes=$n;State=[UInt32]0x1000;Protect=[UInt32]0x104;Type=[UInt32]0x1000000;ReturnedStructureBytes=48}
}
$r=Invoke-PageStateQuery $manifest $base 65536 $query
Check ($r.Status -eq 'PageStatesCollected') 'query normal'
Check ($r.Methods.Count -eq 5) 'five fixed methods'
Check ($r.QueriesAttempted -eq 5) 'query counter'
Check ($r.CodeBytesCollected -eq 0) 'no byte content'
Check (-not $r.Safety.VMReadAccessRequested) 'no VM read right'
Check (-not $r.Safety.ProtectionChanged) 'no page changes'
Check (-not $r.MessageMetadataReadInThisTest) 'no default object reads'
foreach($m in $r.Methods){
 Check ($m.Regions[0].CoveredBytesInThisWindow -eq 64) 'range clipped'
 Check ($m.Regions[0].Classification.GuardFlag) 'guard preserved'
 Check ($m.Regions[0].ProtectValue -eq '0x104') 'raw flag value'
}
$json=$r|ConvertTo-Json -Depth 15
foreach($key in @('Base','AllocationBase','AbsoluteAddress','FilePath','ProcessID','CodeBase64')){
 Check (-not ($json -match ('"'+$key+'"\s*:'))) ('omitted '+$key)
}
$script:mode='Fail';$r=Invoke-PageStateQuery $manifest $base 65536 $query
Check ($r.Status -eq 'PartialOrFailedPageQuery') 'query errors retained'
Check ($r.Methods[0].Failure.ErrorCode -eq 5) 'numeric win32 error'
$script:mode='ShortRegions';$r=Invoke-PageStateQuery $manifest $base 65536 $query
Check ($r.QueriesAttempted -eq 20) 'multi-region bounded iteration'
$manifest.MaximumQueriesTotal=3;$script:mode='Normal'
$r=Invoke-PageStateQuery $manifest $base 65536 $query
Check ($r.QueriesAttempted -eq 3) 'global query cap'
Check ($r.Methods[3].Status -eq 'Stopped') 'global cap refusal'
$script:called=0;$r=Invoke-PageStateQuery $manifest $base 999 $query
Check ($script:called -eq 0) 'wrong image no query'
Check ($r.Status -eq 'Stopped') 'wrong image stop'
Write-Output ('SyntheticPageChecksPassed='+$script:checks)