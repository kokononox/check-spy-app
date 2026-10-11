# Pure ETW parsing. URL-in-event is not proof of sending or server receipt.
function Get-RMWebEvent([string]$XML){
 if($XML -match '<!DOCTYPE'){throw 'DTD not allowed in ETW event XML'}
 $doc=New-Object Xml.XmlDocument;$doc.XmlResolver=$null;$doc.LoadXml($XML)
 $ns=New-Object Xml.XmlNamespaceManager($doc.NameTable);$ns.AddNamespace('e','http://schemas.microsoft.com/win/2004/08/events/event')
 $system=$doc.SelectSingleNode('/e:Event/e:System',$ns);if(!$system){return $null}
 $time=$system.SelectSingleNode('e:TimeCreated',$ns);$execution=$system.SelectSingleNode('e:Execution',$ns);$provider=$system.SelectSingleNode('e:Provider',$ns);$id=$system.SelectSingleNode('e:EventID',$ns)
 if(!$time -or !$execution){return $null}
 $pidValue=0;if(![int]::TryParse($execution.GetAttribute('ProcessID'),[ref]$pidValue) -or $pidValue -le 0){return $null}
 $utc=[datetime]::Parse($time.GetAttribute('SystemTime'),[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
 $fields=New-Object System.Collections.ArrayList;$truncated=$false;$i=0
 foreach($node in @($doc.SelectNodes('/e:Event/e:EventData/e:Data',$ns))){
  $i++;if($i -gt 128){$truncated=$true;break};$name=$node.GetAttribute('Name');if(!$name){$name='Unnamed_'+$i};$value=[string]$node.InnerText
  if($value.Length -gt 65536){$value=$value.Substring(0,65536);$truncated=$true};[void]$fields.Add([pscustomobject]@{Name=$name;Value=$value})
 }
 # Some providers use manifest UserData instead of EventData.
 if(!$fields.Count){foreach($node in @($doc.SelectNodes('/e:Event/e:UserData//*[not(*)]',$ns))){$i++;if($i -gt 128){$truncated=$true;break};$value=[string]$node.InnerText;if($value.Length -gt 65536){$value=$value.Substring(0,65536);$truncated=$true};[void]$fields.Add([pscustomobject]@{Name=$node.LocalName;Value=$value})}}
 $urls=New-Object System.Collections.ArrayList;$method='';$payloadHint=$false
 foreach($field in $fields){
  $name=$field.Name -replace '[^a-zA-Z0-9]',''
  if($name -match '^(url|uri|requesturl|requesturi|fullurl|fulluri|originalurl|originaluri|effectiveurl|effectiveuri)$'){
   $u=$null;$value=$field.Value.Trim();if([Uri]::TryCreate($value,[UriKind]::Absolute,[ref]$u) -and $u.Scheme -in @('http','https') -and $u.Host){[void]$urls.Add([pscustomobject]@{URL=$value;Host=$u.Host;SourceField=$field.Name})}
  }
  if($name -match '^(method|verb|requestmethod|httpmethod)$' -and $field.Value.ToUpperInvariant() -in @('GET','POST','HEAD','PUT','PATCH','DELETE','OPTIONS','CONNECT')){$method=$field.Value.ToUpperInvariant()}
  if($name -match '(requestbody|requestdata|payload|buffer)'){$payloadHint=$true}
 }
 return [pscustomobject]@{UTC=$utc.ToString('o');PID=$pidValue;Provider=$provider.GetAttribute('Name');EventID=$id.InnerText;Fields=@($fields);URLCandidates=@($urls);MethodCandidate=$method;PayloadNamedFieldPresent=$payloadHint;FieldsTruncated=$truncated}
}
function Get-RMWebAttribution($Event,$Processes){
 $time=[datetime]::Parse($Event.UTC).ToUniversalTime()
 return @($Processes|Where-Object {$_.PID -eq $Event.PID -and $time -ge ([datetime]::Parse($_.CreatedUTC).ToUniversalTime()) -and $time -ge ([datetime]::Parse($_.FirstObservedUTC).ToUniversalTime().AddSeconds(-1)) -and $time -le ([datetime]::Parse($_.LastObservedUTC).ToUniversalTime().AddSeconds(1))})
}
function ConvertTo-RMWebEventSummary($Event){
 return [pscustomobject]@{UTC=$Event.UTC;PID=$Event.PID;Provider=$Event.Provider;EventID=$Event.EventID;MethodCandidate=$Event.MethodCandidate;URLCandidateCount=@($Event.URLCandidates).Count;Hosts=@($Event.URLCandidates|ForEach-Object {$_.Host}|Select-Object -Unique);PathAndQuery='[private; not exported]';PayloadNamedFieldPresent=$Event.PayloadNamedFieldPresent;PayloadAssessment='Field name only; may be buffer/pointer/metadata, not proof of readable request body';FieldsTruncated=$Event.FieldsTruncated;Attribution='Event-header PID + observed process creation/time window, not DLL proof or confirmed server receipt'}
}
