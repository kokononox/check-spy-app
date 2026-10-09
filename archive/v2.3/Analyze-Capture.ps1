#requires -Version 5.1
param(
 [Parameter(Mandatory=$true)][string]$CapturePath,
 [Parameter(Mandatory=$true)][string]$ContextPath,
 [Parameter(Mandatory=$true)][string]$OutputPath,
 [string]$KeyLogPath='',
 [string]$TsharkPath='',
 [string]$LaunchStatusPath='',
 [switch]$CompareLocalIdentifiers
)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $OutputPath){Remove-Item -LiteralPath $OutputPath -Force}
if(!$TsharkPath) {
 $cmd=Get-Command tshark.exe -ErrorAction SilentlyContinue
 if($cmd){$TsharkPath=$cmd.Source}else{$TsharkPath=Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'}
}
foreach($p in @($CapturePath,$ContextPath,$TsharkPath)) { if(!(Test-Path -LiteralPath $p -PathType Leaf)){throw "File not found: $p"} }
. (Join-Path $PSScriptRoot 'Capture-Normalize.ps1')
. (Join-Path $PSScriptRoot 'TLS-Key-Status.ps1')
$normalization=Convert-RMCapture $CapturePath
$effectiveCapture=$normalization.EffectivePath
$keyStatus=Get-RMTLSKeyStatus $KeyLogPath
Write-Host ('Capture format: '+$normalization.Reason)
$context=Get-Content -LiteralPath $ContextPath -Raw | ConvertFrom-Json
if(!$context.Connections){throw 'Context has no connection records. Start monitoring before capturing.'}
$rows=@($context.Connections)
$tupleIndex=@{}
foreach($r in $rows) {
 if($r.Source -eq 'Sysmon' -and $r.State -eq 'Inbound event'){continue}
 $at=$r.Local.LastIndexOf(':'); if($at -lt 0){continue}
 $localIP=$r.Local.Substring(0,$at).Trim('[',']'); $localPort=$r.Local.Substring($at+1)
 $addr=$null; if([Net.IPAddress]::TryParse($localIP,[ref]$addr)){$localIP=$addr.ToString()}
 $remote=$null; if(![Net.IPAddress]::TryParse($r.RemoteIP,[ref]$remote)){continue}
 $key=$r.Protocol.ToUpperInvariant()+'|'+$localIP+'|'+$localPort+'|'+$remote.ToString()+'|'+$r.Port
 if(!$tupleIndex.ContainsKey($key)){$tupleIndex[$key]=New-Object System.Collections.ArrayList}
 [void]$tupleIndex[$key].Add($r)
}
$baseline=New-Object System.Collections.ArrayList
if($CompareLocalIdentifiers) {
 foreach($entry in @(@('ComputerName',[Environment]::MachineName),@('WindowsUserName',[Environment]::UserName),@('UserDomain',[Environment]::UserDomainName),@('OSVersion',[Environment]::OSVersion.Version.ToString()))) {
  if($entry[1] -and $entry[1].Length -ge 4){[void]$baseline.Add([pscustomobject]@{Kind=$entry[0];Value=$entry[1]})}
 }
 foreach($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
  $mac=$nic.GetPhysicalAddress().ToString()
  if($mac.Length -eq 12 -and $mac -ne '000000000000') {
   [void]$baseline.Add([pscustomobject]@{Kind='MACAddress';Value=$mac})
   [void]$baseline.Add([pscustomobject]@{Kind='MACAddress';Value=([regex]::Matches($mac,'..').Value -join ':')})
   [void]$baseline.Add([pscustomobject]@{Kind='MACAddress';Value=([regex]::Matches($mac,'..').Value -join '-')})
  }
  foreach($ip in $nic.GetIPProperties().UnicastAddresses) { if(![Net.IPAddress]::IsLoopback($ip.Address)){[void]$baseline.Add([pscustomobject]@{Kind='LocalIPAddress';Value=$ip.Address.ToString()})} }
 }
}
function Decode-Body([string]$v,[bool]$hex) {
 if(!$v){return ''}; if(!$hex){return $v}
 # Only decode genuine FT_BYTES hex fields. Cap inspected text per field at 1 MiB.
 $v=$v -replace '[:,\s]',''; if($v -notmatch '^[0-9a-fA-F]+$' -or $v.Length%2){return ''}
 $len=[Math]::Min($v.Length/2,1048576); $bytes=New-Object byte[] $len
 for($i=0;$i -lt $len;$i++){$bytes[$i]=[Convert]::ToByte($v.Substring($i*2,2),16)}
 return [Text.Encoding]::UTF8.GetString($bytes)
}
function Safe-URI([string]$v) {
 if(!$v){return ''}
 $v=[regex]::Replace($v,'([?&][^=&\s]+)=([^&\s]*)','$1=[redacted]')
 $v=[regex]::Replace($v,'(?i)(token|secret|password|apikey|api_key)/[^/\s?]+','$1/[redacted]')
 return $v
}
$fields=@('frame.time_epoch','ip.src','ipv6.src','tcp.srcport','udp.srcport','ip.dst','ipv6.dst','tcp.dstport','udp.dstport','tcp.stream','udp.stream','tls.handshake.extensions_server_name','http.request.method','http.host','http.request.uri','http.user_agent','http.file_data','data.data','tls.app_data','http2.header.name','http2.header.value','http2.data.data','dns.qry.name','tcp.payload','tcp.len','udp.length','tls.record.content_type','http.content_type','http2.streamid','tls.handshake.random')
# Detect fields first so older tshark releases can degrade explicitly rather than silently fail.
$available=@{}
& $TsharkPath -G fields 2>$null | ForEach-Object { $p=$_ -split "`t"; if($p.Length -gt 2 -and $p[0] -eq 'F'){$available[$p[2]]=$true} }
if($LASTEXITCODE -ne 0){throw 'tshark could not list its fields.'}
$missing=@($fields | Where-Object {!$available.ContainsKey($_)})
$fields=@($fields | Where-Object {$available.ContainsKey($_)})
$argsList=New-Object System.Collections.Generic.List[string]
foreach($a in @('-n','-2','-r',$effectiveCapture,'-T','fields','-E','separator=/t','-E','quote=n','-E','escape=y','-E','occurrence=a')){ $argsList.Add($a) }
$usingKeys=$false
if($KeyLogPath -and $keyStatus.FileExists -and $keyStatus.ValidEntries -gt 0) {
 $usingKeys=$true
 $argsList.Add('-o'); $argsList.Add('tls.keylog_file:'+((Get-Item -LiteralPath $KeyLogPath).FullName))
}
foreach($f in $fields){$argsList.Add('-e');$argsList.Add($f)}
$script:networkFrames=0;$script:readableOverTLS=0;$script:keyMatches=@{};$script:protocolEvidence=New-Object System.Collections.ArrayList;$script:protocolSeen=@{}
$script:allFrames=0; $script:correlatedFrames=0; $script:encryptedFrames=0; $script:readableFrames=0; $script:nonReadableFrames=0
$script:reports=New-Object System.Collections.ArrayList
$script:groups=@{}; $script:reported=@{}; $script:identifierCounts=@{}; $script:bodyCapped=0
$epoch=[datetime]::SpecifyKind([datetime]'1970-01-01',[DateTimeKind]::Utc)
$errPath=$OutputPath+'.tshark-errors.txt'
# Native stderr is routed to disk to avoid PowerShell 5.1 treating stderr as terminating errors.
& $TsharkPath @argsList 2>$errPath | ForEach-Object {
 $script:allFrames++
 $values=$_ -split "`t",0,'SimpleMatch'; $v=@{}
 for($i=0;$i -lt $fields.Count;$i++){$v[$fields[$i]]=if($i -lt $values.Count){$values[$i]}else{''}}
 $src=if($v['ip.src']){$v['ip.src']}else{$v['ipv6.src']}; $dst=if($v['ip.dst']){$v['ip.dst']}else{$v['ipv6.dst']}
 $proto=if($v['tcp.srcport']){'TCP'}elseif($v['udp.srcport']){'UDP'}else{''}
 if($src -and $dst){$script:networkFrames++}
 if(!$src -or !$dst -or !$proto){return}
 $srcPort=if($proto -eq 'TCP'){$v['tcp.srcport']}else{$v['udp.srcport']}; $dstPort=if($proto -eq 'TCP'){$v['tcp.dstport']}else{$v['udp.dstport']}
 $sa=$null;$da=$null
 if(![Net.IPAddress]::TryParse($src,[ref]$sa) -or ![Net.IPAddress]::TryParse($dst,[ref]$da)){return}
 $key=$proto+'|'+$sa.ToString()+'|'+$srcPort+'|'+$da.ToString()+'|'+$dstPort
 if(!$tupleIndex.ContainsKey($key)){return}
 $seconds=0.0
 if(![double]::TryParse($v['frame.time_epoch'],[Globalization.NumberStyles]::Float,[Globalization.CultureInfo]::InvariantCulture,[ref]$seconds)){return}
 $time=$epoch.AddSeconds($seconds)
 $matches=@($tupleIndex[$key] | Where-Object {$time -ge ([datetime]$_.FirstUTC).ToUniversalTime().AddSeconds(-5) -and $time -le ([datetime]$_.LastUTC).ToUniversalTime().AddSeconds(5)})
 if(!$matches.Count){return}; $script:correlatedFrames++
 if($v['tls.handshake.random']){foreach($r in ($v['tls.handshake.random'] -split ',')){$r=$r.Replace(':','').ToLowerInvariant();if($keyStatus.ClientRandoms.ContainsKey($r)){$script:keyMatches[$r]=$true}}}
 $isTLS=!!($v['tls.record.content_type'] -or $v['tls.app_data'])
 if($isTLS){$script:encryptedFrames++}
 $endpoint=$proto+'|'+$dst+':'+$dstPort
 if(!$script:groups.ContainsKey($endpoint)){$script:groups[$endpoint]=[ordered]@{RemoteIP=$dst;Port=$dstPort;Protocol=$proto;CorrelatedOutboundFrames=0;TLSRecognizedFrames=0;ReadableEvidenceFrames=0;SNI=@();Hosts=@()}}
 $g=$script:groups[$endpoint];$g.CorrelatedOutboundFrames++
 if($isTLS){$g.TLSRecognizedFrames++}
 if($v['tls.handshake.extensions_server_name']){$g.SNI=@($g.SNI+$v['tls.handshake.extensions_server_name'] | Select-Object -Unique)}
 if($v['http.host']){$g.Hosts=@($g.Hosts+$v['http.host'] | Select-Object -Unique)}
 $http2Request=($v['http2.header.name'] -match ':method')
 # Only named protocol-dissection fields are interpreted as readable application evidence.
 # Opaque TCP/UDP payload is NOT assumed to be plaintext, even without detected TLS.
 $parts=New-Object System.Collections.ArrayList
 foreach($f in @('http.request.uri','http.user_agent','http2.header.name','http2.header.value')) {
  if($v[$f]){[void]$parts.Add($v[$f].Substring(0,[Math]::Min($v[$f].Length,1048576)))}
 }
 if($v['http.file_data']){[void]$parts.Add((Decode-Body $v['http.file_data'] $true))}
 if($v['http2.data.data']){[void]$parts.Add((Decode-Body $v['http2.data.data'] $true))}
 $text=($parts -join "`n")
 $banner='';if($v['tcp.payload']){$ascii=Decode-Body $v['tcp.payload'] $true;if($ascii -match 'WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2'){$banner='WORLD OF WARCRAFT CONNECTION - CLIENT TO SERVER - V2'}}
 $bannerKey=$dst+'|'+$dstPort+'|'+$v['tcp.stream']
 if($banner -and !$script:protocolSeen.ContainsKey($bannerKey)){$script:protocolSeen[$bannerKey]=$true;[void]$script:protocolEvidence.Add([pscustomobject]@{RemoteIP=$dst;Port=$dstPort;Stream=$v['tcp.stream'];TimeUTC=$time.ToString('o');Kind='Explicit outgoing protocol banner';Banner=$banner;Attribution='Tuple/time correlation'})}
 $hasReadable=!!($v['http.request.method'] -or $http2Request -or $v['http.file_data'] -or $v['http2.data.data'])
 if($hasReadable -and $isTLS){$script:readableOverTLS++}
 if($hasReadable){$script:readableFrames++;$g.ReadableEvidenceFrames++}elseif($v['tcp.payload'] -or $v['udp.length']){$script:nonReadableFrames++}
 $systemFields=@()
 if($hasReadable -and $text) {
  foreach($m in [regex]::Matches($text,'(?i)(?:["\x27]?)(computer[_-]?name|host[_-]?name|user[_-]?name|machine[_-]?id|device[_-]?id|hwid|mac[_-]?(?:address)?|os[_-]?(?:version|name)|cpu|gpu|ram|disk[_-]?serial|email|password|authorization|access[_-]?token|api[_-]?key)(?:["\x27]?)(?:\s*[:=]|%3[dDaA])')){$systemFields+=$m.Groups[1].Value.ToLowerInvariant()}
  $systemFields+=@(($v['http2.header.name'] -split ',') | Where-Object {$_ -match '(?i)(device|machine|hwid|computer|user.?name|mac.?address|os.?version|authorization|token)'})
  $systemFields=@($systemFields | Select-Object -Unique)
 }
 $matchedKinds=@()
 if($hasReadable -and $CompareLocalIdentifiers) {
  $decoded=$text
  try{$decoded=[Uri]::UnescapeDataString($text)}catch{}
  foreach($b in $baseline){if($decoded.IndexOf($b.Value,[StringComparison]::OrdinalIgnoreCase) -ge 0){$matchedKinds+=$b.Kind}}
  $matchedKinds=@($matchedKinds | Select-Object -Unique)
  foreach($kind in $matchedKinds){if(!$script:identifierCounts.ContainsKey($kind)){$script:identifierCounts[$kind]=0};$script:identifierCounts[$kind]++}
 }
 $interesting=$hasReadable -or $v['tls.handshake.extensions_server_name'] -or $v['dns.qry.name']
 if(!$interesting){return}
 $evidence=[pscustomobject]@{
  TimeUTC=$time.ToString('o');RemoteIP=$dst;Port=$dstPort;Protocol=$proto;PIDCandidates=@($matches.PID | Select-Object -Unique)
  Attribution='Outbound tuple + time correlation; not kernel packet-to-process proof'
  Stream=if($proto -eq 'TCP'){$v['tcp.stream']}else{$v['udp.stream']}
  TLSRecognized=$isTLS;SNI=$v['tls.handshake.extensions_server_name'];HTTPMethod=$v['http.request.method'];HTTPHost=$v['http.host'];HTTPUserAgent=$v['http.user_agent'];RequestURI=(Safe-URI $v['http.request.uri'])
  HTTP2RequestHeadersPresent=$http2Request;HTTP2HeaderNames=$v['http2.header.name'];HTTP2Stream=$v['http2.streamid']
  ReadableApplicationEvidence=$hasReadable;ReadableBodyPresent=!!($v['http.file_data'] -or $v['http2.data.data'])
  SystemOrSensitiveFieldNames=$systemFields;LocalIdentifierMatchKinds=$matchedKinds
  DNSQuery=$v['dns.qry.name'];Verdict=if($matchedKinds.Count){'Readable outbound data contains a local identifier string; investigate context'}elseif($systemFields.Count){'Readable outbound data contains field-name indicators; values not established'}elseif($hasReadable){'Readable application metadata/body observed; no tested identifier matched'}else{'Metadata only; application content unknown'}
 }
 # HTTP reassembly/packet capture can duplicate evidence; keep one entry per stream and metadata signature.
 $dedup=$key+'|'+$evidence.Stream+'|'+$evidence.HTTP2Stream+'|'+$evidence.HTTPMethod+'|'+$evidence.RequestURI+'|'+$evidence.SNI+'|'+($matchedKinds -join ',')+'|'+($systemFields -join ',')+'|'+$evidence.ReadableBodyPresent
 if(!$script:reported.ContainsKey($dedup)){$script:reported[$dedup]=$true;[void]$script:reports.Add($evidence)}
}
if($LASTEXITCODE -ne 0){throw "tshark failed; see $errPath"}
$launchDiagnostic=$null
if($LaunchStatusPath -and (Test-Path -LiteralPath $LaunchStatusPath)) {
 try{$raw=Get-Content -LiteralPath $LaunchStatusPath -Raw | ConvertFrom-Json;$launchDiagnostic=[ordered]@{Phase=$raw.Phase;Success=$raw.Success;ValidKeyRecords=$raw.ValidKeyRecords;KeyAssessment=$raw.KeyAssessment;Error=$raw.Error;UTC=$raw.UTC}}catch{}
}
$out=[ordered]@{
 Version='2.3';Target=$context.Target;TargetSHA256AtSessionStart=$context.TargetSHA256;CaptureSHA256=(Get-FileHash -LiteralPath $CapturePath -Algorithm SHA256).Hash;ContextSHA256=(Get-FileHash -LiteralPath $ContextPath -Algorithm SHA256).Hash;Capture=$CapturePath;AnalyzedCapture=$effectiveCapture;Normalization=$normalization;AnalyzedCaptureSHA256=(Get-FileHash -LiteralPath $effectiveCapture -Algorithm SHA256).Hash;GeneratedUTC=[datetime]::UtcNow.ToString('o');KeyLogRequested=!!$KeyLogPath;KeyLogProvided=$usingKeys;LocalIdentifierComparisonEnabled=[bool]$CompareLocalIdentifiers
 LauncherDiagnostic=$launchDiagnostic
 KeyLogFileExists=$keyStatus.FileExists;KeyLogValidRecords=$keyStatus.ValidEntries;KeyLogClientRandomMatches=$script:keyMatches.Count;KeyLogAssessment=$keyStatus.Assessment
 TLSDecryptionAssessment=if($script:readableOverTLS){'Readable HTTP/HTTP2 observed on recognized TLS; some application decoding succeeded'}else{'TLS application-content decryption NOT established'}
 CaptureAssessment=if(!$script:networkFrames){'No IP decoded: capture cannot be assessed'}elseif(!$script:correlatedFrames){'IP decoded but no target tuples matched: attribution cannot be assessed'}else{'Target traffic correlated; encrypted/opaque content may remain unknown'}
 NetworkDecodedFrames=$script:networkFrames;ReadableHTTPOverTLSFrames=$script:readableOverTLS;ProtocolEvidence=@($script:protocolEvidence)
 AllCapturedFrames=$script:allFrames;CorrelatedOutboundFrames=$script:correlatedFrames;TLSRecognizedFrames=$script:encryptedFrames;ReadableEvidenceFrames=$script:readableFrames;OpaquePayloadFrames=$script:nonReadableFrames
 MissingTsharkFields=$missing;LocalIdentifierMatchFrameCounts=$script:identifierCounts;Endpoints=@($script:groups.Values);Evidence=@($script:reports)
 Limitations=@('Only outbound tuples present in context and within observed time +/-5 seconds are analyzed. Unobserved short-lived flows are omitted.',
 'This is time/tuple correlation, not definitive kernel attribution. Port reuse, proxies and packet duplication can affect it. Counts are frames, not unique requests or byte totals.',
 'Pktmon captures all system traffic at NICs, subject to existing pktmon filters. Circular capture can overwrite old packets. Loopback and VPN inner traffic may be absent.',
 'TLS recognition is not complete. Unrecognized or opaque traffic is unknown, not safe. Providing a key file does not establish successful decryption.',
 'Readable HTTP/HTTP2 fields are inspected. Arbitrary binary protocols, compression, application encryption, HTTP3/QUIC and split/custom fields may not be decoded.',
 'Identifier matches are substring indicators, not proof of theft or intent. A username can be part of legitimate login. No match is not evidence of no system data transmission.',
 'Only machine name, Windows user, user domain, OS version, MAC and local IP are compared when opted in; serial numbers, installed-app lists and hardware inventory are not collected.',
 'Body text and field values are not saved in this report; HTTP User-Agent metadata is retained. URI query values are masked, but paths, hostnames and DNS names can still be sensitive. Raw capture/key files are sensitive.',
 'The analyzer must run on the captured computer with the same user to compare correct local identifiers. Text inspected per protocol field is bounded at 1 MiB.')
}
$temp=$OutputPath+'.tmp'
$out | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temp -Encoding UTF8
Move-Item -LiteralPath $temp -Destination $OutputPath -Force
Write-Host ('Key status: '+$keyStatus.Assessment+'; valid entries: '+$keyStatus.ValidEntries+'; matching client randoms: '+$script:keyMatches.Count)
if(!$script:readableOverTLS){Write-Warning 'TLS decryption is NOT established. A key file existing or being selected is not proof.'}
Write-Host "Report saved: $OutputPath"
Write-Host "Outbound correlated frames: $script:correlatedFrames; readable evidence frames: $script:readableFrames"
if(!$script:correlatedFrames){Write-Warning 'No matching traffic: check capture, context, timing, filters and privileges. This does NOT mean no data was sent.'}
