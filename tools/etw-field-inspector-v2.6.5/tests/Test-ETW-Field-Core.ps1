$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot;. (Join-Path $base 'ETW-Field-Core.ps1')
$script:n=0
function Assert($ok,$message){if(!$ok){throw $message};$script:n++}
$plain='WinHttpSendRequest POST https://telemetry-in.battle.net/private/path?token=PRIVATE_TOKEN Authorization: PRIVATE_AUTH BODY=PRIVATE_BODY'
$s=Get-RMFieldShape $plain;$out=$s|ConvertTo-Json -Depth 6
Assert ($s.URLLikeStringCount -eq 1) 'Detect URL string in arbitrary text field'
Assert ($s.APINameHints -contains 'WinHttpSendRequest') 'Allowlisted API hint'
Assert ($s.KnownDestinationHints -contains 'telemetry-in.battle.net') 'Known destination hint'
Assert ($s.HTTPMethodWordHints -contains 'POST') 'Method word hint'
Assert ($out -notmatch 'PRIVATE_TOKEN|PRIVATE_AUTH|PRIVATE_BODY|private/path|https://') 'No values/URL/path leakage'
$unknown=Get-RMFieldShape 'https://PRIVATE_HOST.example/private?secret=PRIVATE_TOKEN'
Assert ($unknown.URLLikeStringCount -eq 1 -and $unknown.KnownDestinationHints.Count -eq 0) 'Unknown hostname withheld'
$hex=([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($plain))).Replace('-','');$h=Get-RMFieldShape $hex
Assert ($h.APINameHints -contains 'WinHttpSendRequest' -and $h.EncodedHintKinds -contains 'HexUTF8') 'Encoded UTF8 hex hint'
Assert (($h|ConvertTo-Json -Depth 6) -notmatch 'PRIVATE_TOKEN') 'Hex decoding privacy'
$utf16=([BitConverter]::ToString([Text.Encoding]::Unicode.GetBytes('WinHttpOpenRequest https://prod.depot.battle.net/private?q=PRIVATE'))).Replace('-','');$u=Get-RMFieldShape $utf16
Assert ($u.APINameHints -contains 'WinHttpOpenRequest' -and $u.EncodedHintKinds -contains 'HexUTF16LE') 'UTF16 hex hints'
$b=Get-RMFieldShape ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($plain)))
Assert ($b.EncodedHintKinds -contains 'Base64UTF8' -and $b.URLLikeStringCount -eq 1) 'Base64 hints'
Assert ((Get-RMFieldShape '').Kind -eq 'Empty') 'Empty value'
Assert ((Get-RMFieldShape '1692').Kind -eq 'IntegerLike') 'Numeric shape without value'
Assert ((Get-RMFieldShape '0x1234').Kind -eq 'HexNumberLike') 'Pointer-like value not exported'
Assert ((Get-RMFieldShape ('x'*70000)).InspectionTruncated) 'Inspection cap'
Assert ((Get-RMSafeFieldName 'URL') -eq 'URL') 'Keep field name'
Assert ((Get-RMSafeFieldName 'user@example.org') -eq '[unusual-name-omitted]') 'Unusual field name suppressed'
Assert ((Get-RMSafeFieldName ('abcdef0123456789'*2)) -eq '[unusual-name-omitted]') 'Opaque identifier field name suppressed'
$acc=New-RMFieldAccumulator
$e=[pscustomobject]@{Provider='Microsoft-Windows-WinHttp';EventID='59995';Fields=@([pscustomobject]@{Name='Unnamed_1';Value=$plain},[pscustomobject]@{Name='Handle';Value='0x9999'})}
Add-RMFieldEvent $acc $e
Add-RMFieldEvent $acc ([pscustomobject]@{Provider='Microsoft-Windows-WinHttp';EventID='59995';Fields=@()}) 'WinHttpGetProxyForUrl called'
$d=Complete-RMFieldReport $acc;$json=$d|ConvertTo-Json -Depth 14
Assert ($d.EventsInspected -eq 2 -and $d.FieldsInspected -eq 3) 'Event/field aggregation'
Assert ($d.Groups[0].Fields.Name -contains 'RenderedMessage') 'Formatted message shape only'
Assert ($json -notmatch 'PRIVATE_TOKEN|PRIVATE_AUTH|PRIVATE_BODY|private/path|0x9999|GetProxyForUrl called') 'No raw aggregate leaks'
Assert ($json -match 'WinHttpGetProxyForUrl') 'Whitelisted function label retained'
Assert (!$d.RawValuesExported -and !$d.FullURLsExported) 'Explicit privacy status'
$empty=New-RMFieldAccumulator;Add-RMFieldEvent $empty ([pscustomobject]@{Provider='Microsoft-Windows-WinHttp';EventID=59998;Fields=@()});$z=Complete-RMFieldReport $empty
Assert ($z.EventsWithNoFieldValues -eq 1) 'Empty payload distinguished'
$strict=Get-RMFieldShape 'WinHttpOpenRequestFAKE and GETTING'
Assert ($strict.APINameHints.Count -eq 0 -and $strict.HTTPMethodWordHints.Count -eq 0) 'Hint word boundaries'
Write-Output "PASS: $script:n ETW field-shape/encoded-text/privacy checks (synthetic only)"
