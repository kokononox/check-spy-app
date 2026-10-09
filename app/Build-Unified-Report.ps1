# Combine only already-attributed outgoing facts with distinctly labeled local-only evidence.
function ConvertTo-RM27Unified($Network,$LocalAudit){
 $n=$Network|ConvertTo-Json -Depth 16|ConvertFrom-Json
 # Public report drops values and arbitrary resource paths; raw capture remains private.
 foreach($e in $n.Evidence){
  if($e.HTTPUserAgent){$e.HTTPUserAgent='[present; value not exported]'}
  if($e.RequestURI){$e.RequestURI=if($e.RequestURI -match '^/tpr/wow/config/'){'/tpr/wow/config/[resource]'}else{'[path and query not exported]'}}
  $safeFields=@()
  foreach($field in $e.SystemOrSensitiveFieldNames){
   if($field -match '^(computer[_-]?name|host[_-]?name|user[_-]?name|machine[_-]?id|device[_-]?id|hwid|mac[_-]?(address)?|os[_-]?(version|name)|cpu|gpu|ram|disk[_-]?serial|email|password|authorization|access[_-]?token|api[_-]?key)$'){$safeFields+=$field.ToLowerInvariant()}
   elseif($field -match '(?i)authorization'){$safeFields+='authorization-header'}
   elseif($field -match '(?i)token'){$safeFields+='token-related-header'}
   elseif($field -match '(?i)device|machine|hwid|computer|user.?name|mac.?address|os.?version'){$safeFields+='system-related-header'}
  }
  $e.SystemOrSensitiveFieldNames=@($safeFields|Sort-Object -Unique)
  if($e.HTTP2HeaderNames){$e.HTTP2HeaderNames=(@($e.HTTP2HeaderNames -split ','|Where-Object {$_ -in @(':method',':path',':authority',':scheme','content-type','content-length','user-agent','authorization','cookie')}) -join ',')}
 }
 foreach($prop in @('Capture','AnalyzedCapture','Target')){if($n.$prop){$n.$prop=[IO.Path]::GetFileName($n.$prop)}}
 if($n.Normalization){foreach($prop in @('OriginalPath','EffectivePath')){if($n.Normalization.$prop){$n.Normalization.$prop=[IO.Path]::GetFileName($n.Normalization.$prop)}}}
 if($n.LauncherDiagnostic -and $n.LauncherDiagnostic.Error){$n.LauncherDiagnostic.Error='Launcher reported failure; private diagnostic retained locally'}
 $destinations=@()
 foreach($g in $n.Endpoints){
  $kind=if($g.ReadableEvidenceFrames -gt 0){'Some outgoing HTTP evidence readable; other content may remain unknown'}elseif($g.TLSRecognizedFrames -gt 0){'TLS metadata observed; outgoing content unknown'}else{'Opaque or unrecognized protocol; content unknown'}
  $destinations+=[pscustomobject]@{IP=$g.RemoteIP;Port=$g.Port;Protocol=$g.Protocol;Names=@($g.SNI+$g.Hosts|Where-Object {$_}|Sort-Object -Unique);OutboundFrames=$g.CorrelatedOutboundFrames;InboundFrames=$g.CorrelatedInboundFrames;ObservedOutboundTransportPayloadBytes=$g.ObservedOutboundTransportPayloadBytes;ObservedInboundTransportPayloadBytes=$g.ObservedInboundTransportPayloadBytes;Visibility=$kind;TLSVersionCodes=$g.TLSVersionCodes;KnownALPN=$g.KnownALPN;TLSAlertCodes=$g.TLSAlertCodes;RetransmissionFrames=$g.ObservedRetransmissionFrames;ByteLengthUnknownFrames=$g.ByteLengthUnknownFrames}
 }
 $fieldNames=@($n.Evidence|Where-Object {$_.ReadableApplicationEvidence}|ForEach-Object {$_.SystemOrSensitiveFieldNames}|Where-Object {$_}|Sort-Object -Unique)
 $matches=@($n.LocalIdentifierMatchFrameCounts.PSObject.Properties|Where-Object {$_.Value -gt 0}|ForEach-Object {$_.Name})
 $localKinds=if($LocalAudit){@($LocalAudit.LocalFieldCategories)}else{@()}
 return [pscustomobject][ordered]@{Version='2.7';ReportKind='UnifiedPassiveMonitoring';GeneratedUTC=[datetime]::UtcNow.ToString('o');Target=$n.Target;TargetSHA256=$n.TargetSHA256AtSessionStart;Mode='Passive capture + attributed analysis + fixed-name local-log audit';CertificateInstalled=$false;ProxyChanged=$false;TLSKeyLoggingRequested=$false;Destinations=$destinations;EvidenceLevels=[ordered]@{ReadableOutgoingFieldNameIndicators=$fieldNames;ReadableOutgoingIdentifierHints=$matches;LocalLogOnlyCategories=$localKinds;EncryptedOrOpaqueContent='Unknown, not safe/empty';Assessment='Outgoing field names and string matches are indicators, not proof of exact system values, theft or intent. Local log categories are not transmission evidence.'};LocalLogAudit=$LocalAudit;Network=$n;Limitations=@('No TLS decryption, CA installation, proxy change, memory extraction or pinning bypass is performed by the simple workflow.','Tuple/time attribution is not definitive kernel attribution; short flows, UDP destinations without Sysmon, loopback and VPN inner traffic may be missed.','Transport payload bytes are observed lengths including TLS overhead and possible duplication/retransmission, not unique application bytes.','Only naturally readable supported protocols are inspected; encrypted or binary payload remains unknown.','Destination names/IPs, timing and hashes are still sensitive metadata; review before sharing.','Temporary tshark decoded field output is local and deleted on handled completion/failure; a hard crash may leave private temporary files.')}
}
