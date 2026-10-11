# Structural hints only. Never return raw field values, URLs, paths, headers or body text.
function Get-RMSafeFieldName([string]$Name){
 if(!$Name){return '[unnamed]'}
 if($Name.Length -gt 96 -or $Name -notmatch '^[A-Za-z_][A-Za-z0-9_.:-]*$' -or $Name -match '(?i)[0-9a-f]{16,}'){return '[unusual-name-omitted]'}
 return $Name
}
function Get-RMFieldShape([string]$Value){
 $originalLength=$Value.Length;$cut=$false;if($Value.Length -gt 65536){$Value=$Value.Substring(0,65536);$cut=$true}
 $kind='Text'
 if(!$Value){$kind='Empty'}elseif($Value -match '^\s*[+-]?\d+\s*$'){$kind='IntegerLike'}elseif($Value -match '^\s*0x[0-9a-fA-F]+\s*$'){$kind='HexNumberLike'}elseif($Value -match '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'){$kind='GUIDLike'}elseif($Value.Trim() -match '^[\[{]'){$kind='StructuredTextLike'}elseif($Value -match '^[A-Za-z0-9+/]+={0,2}$' -and $Value.Length -ge 24 -and $Value.Length%4 -eq 0){$kind='Base64OrTokenLike'}
 $versions=New-Object System.Collections.ArrayList;[void]$versions.Add([pscustomobject]@{Kind='DirectText';Text=$Value})
 # Bounded local decoding of encoded fields for hints only. No decoded text is emitted.
 $hex=$Value -replace '^(?:0x)','' -replace '[:\s-]',''
 if($hex.Length -ge 16 -and $hex.Length -le 65536 -and $hex.Length%2 -eq 0 -and $hex -match '^[0-9a-fA-F]+$'){
  $bytes=New-Object byte[] ($hex.Length/2);for($i=0;$i -lt $bytes.Length;$i++){$bytes[$i]=[Convert]::ToByte($hex.Substring($i*2,2),16)}
  [void]$versions.Add([pscustomobject]@{Kind='HexUTF8';Text=[Text.Encoding]::UTF8.GetString($bytes)})
  if($bytes.Length%2 -eq 0){[void]$versions.Add([pscustomobject]@{Kind='HexUTF16LE';Text=[Text.Encoding]::Unicode.GetString($bytes)})}
 }
 if($kind -eq 'Base64OrTokenLike'){try{$bytes=[Convert]::FromBase64String($Value);[void]$versions.Add([pscustomobject]@{Kind='Base64UTF8';Text=[Text.Encoding]::UTF8.GetString($bytes)});if($bytes.Length%2 -eq 0){[void]$versions.Add([pscustomobject]@{Kind='Base64UTF16LE';Text=[Text.Encoding]::Unicode.GetString($bytes)})}}catch{}}
 $knownAPIs=@('WinHttpOpen','WinHttpConnect','WinHttpOpenRequest','WinHttpSendRequest','WinHttpReceiveResponse','WinHttpReadData','WinHttpWriteData','WinHttpCloseHandle','WinHttpGetProxyForUrl','WinHttpGetProxyForUrlEx','WinHttpGetProxyForUrlEx2','WinHttpDetectAutoProxyConfigUrl','WinHttpGetIEProxyConfigForCurrentUser','WinHttpQueryHeaders','WinHttpQueryOption','WinHttpSetOption','WinHttpGetDefaultProxyConfiguration','WinHttpSetDefaultProxyConfiguration')
 $knownDestinations=@('telemetry-in.battle.net','prod.depot.battle.net','eu.account.battle.net','oauth.battle.net','breaking-news.support.blizzard.com','level3.blizzard.com')
 $urls=New-Object 'System.Collections.Generic.HashSet[string]';$apis=New-Object 'System.Collections.Generic.HashSet[string]';$hosts=New-Object 'System.Collections.Generic.HashSet[string]';$methods=New-Object 'System.Collections.Generic.HashSet[string]';$decodedKinds=New-Object 'System.Collections.Generic.HashSet[string]'
 foreach($version in $versions){
  $hit=$false
  foreach($m in [regex]::Matches($version.Text,'(?i)https?://[^\s<>"\x27\x00]+')){
   $u=$null;$url=$m.Value.TrimEnd(')',',',';');if([Uri]::TryCreate($url,[UriKind]::Absolute,[ref]$u) -and $u.Host){[void]$urls.Add($url);$hit=$true;if($u.Host.ToLowerInvariant() -in $knownDestinations){[void]$hosts.Add($u.Host.ToLowerInvariant())}}
  }
  foreach($api in $knownAPIs){if($version.Text -match ('(?i)(?<![A-Za-z0-9_])'+[regex]::Escape($api)+'(?![A-Za-z0-9_])')){[void]$apis.Add($api);$hit=$true}}
  foreach($method in @('GET','POST','HEAD','PUT','PATCH','DELETE','OPTIONS','CONNECT')){if($version.Text -cmatch ('(?<![A-Za-z0-9_])'+$method+'(?![A-Za-z0-9_])')){[void]$methods.Add($method)}}
  if($hit -and $version.Kind -ne 'DirectText'){[void]$decodedKinds.Add($version.Kind)}
 }
 return [pscustomobject]@{Kind=$kind;CharacterLength=$originalLength;InspectionTruncated=$cut;URLLikeStringCount=$urls.Count;KnownDestinationHints=@($hosts|Sort-Object);APINameHints=@($apis|Sort-Object);HTTPMethodWordHints=@($methods|Sort-Object);EncodedHintKinds=@($decodedKinds|Sort-Object);Warning='Hints in a field/message, not proof of API call, request transmission or server receipt'}
}
function New-RMFieldAccumulator {return [pscustomobject]@{Groups=@{};Definitions=0;Events=0;Fields=0;EmptyFieldEvents=0;LimitsReached=$false}}
function Add-RMFieldEvent($Accumulator,$Event,[string]$RenderedMessage=''){
 $provider=if($Event.Provider -in @('Microsoft-Windows-WinHttp','Microsoft-Windows-WinINet')){$Event.Provider}else{'[other-provider]'}
 $eventID=if([string]$Event.EventID -match '^\d{1,5}$'){[string]$Event.EventID}else{'[unusual-event-id]'}
 $key=$provider+'|'+$eventID
 if(!$Accumulator.Groups.ContainsKey($key)){
  if($Accumulator.Groups.Count -ge 512){$Accumulator.LimitsReached=$true;return}
  $Accumulator.Groups[$key]=[pscustomobject]@{Provider=$provider;EventID=$eventID;Events=0;EmptyFieldEvents=0;FieldDefinitions=@{}}
 }
 $g=$Accumulator.Groups[$key];$g.Events++;$Accumulator.Events++
 $fields=@($Event.Fields|Where-Object {$_})
 if($RenderedMessage){$fields+=([pscustomobject]@{Name='RenderedMessage';Value=$RenderedMessage})}
 if(!$fields.Count){$g.EmptyFieldEvents++;$Accumulator.EmptyFieldEvents++}
 $n=0
 foreach($f in $fields){
  $n++;if($n -gt 129){$Accumulator.LimitsReached=$true;break}
  $name=Get-RMSafeFieldName ([string]$f.Name);$shape=Get-RMFieldShape ([string]$f.Value);$Accumulator.Fields++
  if(!$g.FieldDefinitions.ContainsKey($name) -and ($g.FieldDefinitions.Count -ge 256 -or $Accumulator.Definitions -ge 4096)){$Accumulator.LimitsReached=$true;continue}
  if(!$g.FieldDefinitions.ContainsKey($name)){$Accumulator.Definitions++;$g.FieldDefinitions[$name]=[pscustomobject]@{Name=$name;Occurrences=0;MinCharacterLength=$shape.CharacterLength;MaxCharacterLength=$shape.CharacterLength;Kinds=@{};FieldsWithURLHints=0;URLLikeStringOccurrences=0;KnownDestinationHints=@{};APINameHints=@{};HTTPMethodWordHints=@{};EncodedHintKinds=@{};TruncatedFieldOccurrences=0}}
  $a=$g.FieldDefinitions[$name];$a.Occurrences++;$a.MinCharacterLength=[Math]::Min($a.MinCharacterLength,$shape.CharacterLength);$a.MaxCharacterLength=[Math]::Max($a.MaxCharacterLength,$shape.CharacterLength)
  if(!$a.Kinds.ContainsKey($shape.Kind)){$a.Kinds[$shape.Kind]=0};$a.Kinds[$shape.Kind]++
  if($shape.URLLikeStringCount){$a.FieldsWithURLHints++;$a.URLLikeStringOccurrences+=$shape.URLLikeStringCount}
  foreach($h in $shape.KnownDestinationHints){$a.KnownDestinationHints[$h]=$true};foreach($h in $shape.APINameHints){$a.APINameHints[$h]=$true};foreach($h in $shape.HTTPMethodWordHints){$a.HTTPMethodWordHints[$h]=$true};foreach($h in $shape.EncodedHintKinds){$a.EncodedHintKinds[$h]=$true}
  if($shape.InspectionTruncated){$a.TruncatedFieldOccurrences++}
 }
}
function Complete-RMFieldReport($Accumulator){
 $groups=@()
 foreach($g in @($Accumulator.Groups.Values|Sort-Object Provider,EventID)){
  $defs=@()
  foreach($f in @($g.FieldDefinitions.Values|Sort-Object Name)){$defs+=[pscustomobject]@{Name=$f.Name;Occurrences=$f.Occurrences;MinCharacterLength=$f.MinCharacterLength;MaxCharacterLength=$f.MaxCharacterLength;Kinds=$f.Kinds;FieldsWithURLHints=$f.FieldsWithURLHints;URLLikeStringOccurrences=$f.URLLikeStringOccurrences;KnownDestinationHints=@($f.KnownDestinationHints.Keys|Sort-Object);APINameHints=@($f.APINameHints.Keys|Sort-Object);HTTPMethodWordHints=@($f.HTTPMethodWordHints.Keys|Sort-Object);EncodedHintKinds=@($f.EncodedHintKinds.Keys|Sort-Object);TruncatedFieldOccurrences=$f.TruncatedFieldOccurrences}}
  $groups+=[pscustomobject]@{Provider=$g.Provider;EventID=$g.EventID;Events=$g.Events;EmptyFieldEvents=$g.EmptyFieldEvents;Fields=$defs}
 }
 return [pscustomobject]@{Version='2.6.5';ReportKind='ETWFieldStructureDiagnostic';EventsInspected=$Accumulator.Events;FieldsInspected=$Accumulator.Fields;EventsWithNoFieldValues=$Accumulator.EmptyFieldEvents;LimitsReached=$Accumulator.LimitsReached;Groups=$groups;RawValuesExported=$false;FullURLsExported=$false;HeaderAndBodyValuesExported=$false;Warning='Field/API/URL hints only; no proof of actual request sending, telemetry content or server receipt. No keys, TLS bypass or new tracing.'}
}
