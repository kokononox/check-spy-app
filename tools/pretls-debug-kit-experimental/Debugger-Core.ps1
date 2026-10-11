# Pure command generation and dump parsing. x64 only. No target execution here.
function New-RMCdbCommands([string]$Symbol='sspicli!EncryptMessage'){
 if($Symbol -notin @('sspicli!EncryptMessage','secur32!EncryptMessage')){throw 'Unsupported breakpoint symbol'}
 $handler=@'
r @$t8 = @$t8 + 1; .if ((@rcx != 0) and (@r8 != 0) and (@edx == 0)) { .if ((dwo(@r8+4) > 0) and (dwo(@r8+4) <= 0x10) and (poi(@r8+8) != 0)) { .for (r @$t0 = 0; @$t0 < dwo(@r8+4); r @$t0 = @$t0 + 1) { r @$t1 = poi(@r8+8) + @$t0 * 0x10; .if (((dwo(@$t1+4) and 0x0fffffff) == 1) and ((dwo(@$t1+4) and 0x80000000) == 0) and (poi(@$t1+8) != 0)) { r @$t3 = dwo(@$t1); r @$t4 = poi(@$t1+8); r @$t5 = @$t3; .if (@$t5 > 0x4000) { r @$t5 = 0x4000; }; .if (@$t5 > 0x40000 - @$t9) { r @$t5 = 0x40000 - @$t9; }; .if (@$t5 > 0) { .printf "RM_BEGIN ctx=%p/%p declared=%u captured=%u\n", poi(@rcx), poi(@rcx+8), @$t3, @$t5; db /c 0x10 @$t4 L@$t5; .echo RM_END; r @$t9 = @$t9 + @$t5; }; }; }; }; }; .if ((@$t8 >= 0x40) or (@$t9 >= 0x40000)) { .echo RM_STOP_LIMIT; bc *; .logclose; .detach; q; } .else { g; }
'@
 # Escape printf quotes for the outer breakpoint command string.
 $handler=$handler.Trim().Replace('"','\"')
 return @('.expr /s masm','.echo RM_OBSERVER_EXPERIMENTAL_X64','r @$t8 = 0','r @$t9 = 0',('bu '+$Symbol+' "'+$handler+'"'),'.echo Stop with Ctrl+C then use the detach commands from README','g') -join "`r`n"
}
function Read-RMCdbData([string]$Text){
 if($Text.Length -gt 8388608){throw 'Log exceeds 8 MiB parser limit'}
 $records=New-Object Collections.ArrayList;$current=$null;$errors=0
 foreach($line in ($Text -split '\r?\n')){
  if($line -match '^RM_BEGIN ctx=((?:0x)?[0-9a-fA-F`]+)/((?:0x)?[0-9a-fA-F`]+) declared=(\d+) captured=(\d+)\s*$'){
   if($current){$errors++}
   $declared=[long]$matches[3];$captured=[long]$matches[4]
   if($captured -gt 16384 -or $declared -lt $captured){$errors++;$current=$null;continue}
   $current=[pscustomobject]@{Context=$matches[1]+'/'+$matches[2];Declared=$declared;Captured=$captured;Bytes=(New-Object 'Collections.Generic.List[byte]')};continue
  }
  if($line -match '^RM_END\s*$'){
   if($current){
    if($current.Bytes.Count -eq $current.Captured){[void]$records.Add([pscustomobject]@{Context=$current.Context;Declared=$current.Declared;Captured=$current.Captured;Bytes=$current.Bytes.ToArray();Truncated=($current.Declared -ne $current.Captured)})}else{$errors++}
   }else{$errors++};$current=$null;continue
  }
  if($current -and $line -match '^\s*[0-9a-fA-F`]{8,17}\s{2}(.+)$'){
   $hex=($matches[1] -split '\s{2,}',2)[0] -replace '-',' '
   $tokens=@($hex.Trim() -split '\s+')
   if($tokens.Count -gt 16 -or @($tokens|Where-Object {$_ -notmatch '^[0-9a-fA-F]{2}$'}).Count){$errors++;continue}
   foreach($token in $tokens){if($current.Bytes.Count -ge 16384){$errors++;break};$current.Bytes.Add([Convert]::ToByte($token,16))}
  }
 }
 if($current){$errors++}
 return [pscustomobject]@{Records=@($records);ParseErrors=$errors;LimitStopped=($Text -match '(?m)^RM_STOP_LIMIT\s*$')}
}
function Get-RMHttpCandidates($Records){
 $streams=@{};$candidates=New-Object Collections.ArrayList;$unsupported=0
 foreach($r in $Records){
  if(!$streams.ContainsKey($r.Context)){$streams[$r.Context]=[pscustomobject]@{Bytes=(New-Object 'Collections.Generic.List[byte]');Gap=$false}}
  $s=$streams[$r.Context]
  if($s.Gap){continue}
  if($s.Bytes.Count+$r.Bytes.Length -gt 262144){$s.Gap=$true;continue}
  $s.Bytes.AddRange([byte[]]$r.Bytes)
  if($r.Truncated){$s.Gap=$true}
 }
 foreach($s in $streams.Values){
  $bytes=$s.Bytes.ToArray();$text=[Text.Encoding]::GetEncoding(28591).GetString($bytes);$offset=0
  if($text.StartsWith('PRI * HTTP/2.0')){$unsupported++;continue}
  while($offset -lt $text.Length){
   $rest=$text.Substring($offset)
   $m=[regex]::Match($rest,'\A(GET|POST|HEAD|PUT|PATCH|DELETE|OPTIONS) ([^\r\n ]{1,8192}) HTTP/1\.[01]\r\n')
   if(!$m.Success){break}
   $headerEnd=$rest.IndexOf("`r`n`r`n");if($headerEnd -lt 0 -or $headerEnd -gt 32768){break}
   $headers=$rest.Substring(0,$headerEnd);$hostMatch=[regex]::Match($headers,'(?im)^Host:\s*([^\r\n]+)\s*$')
   $target=$m.Groups[2].Value;$url='';$schemeSource='Absolute request-target literal'
   $u=$null
   if([Uri]::TryCreate($target,[UriKind]::Absolute,[ref]$u) -and $u.Scheme -in @('http','https')){$url=$target}
   elseif($target.StartsWith('/') -and !$target.StartsWith('//') -and $hostMatch.Success){
    $hostText=$hostMatch.Groups[1].Value.Trim();$candidate='https://'+$hostText+$target
    if($hostText -notmatch '[\s/@?#]' -and [Uri]::TryCreate($candidate,[UriKind]::Absolute,[ref]$u) -and $u.Host){$url=$candidate;$schemeSource='HTTPS assumed from intended Schannel observation; Host + request-target literals'}
   }
   if(!$url){break}
   $lengths=@([regex]::Matches($headers,'(?im)^Content-Length:\s*(\d+)\s*$')|ForEach-Object {$_.Groups[1].Value})
   $chunked=[regex]::IsMatch($headers,'(?im)^Transfer-Encoding:');$declared=$null
   if($lengths.Count -eq 1){$n=0L;if([long]::TryParse($lengths[0],[ref]$n) -and $n -le 262144){$declared=$n}}
   $bodyOffset=$offset+$headerEnd+4;$available=[Math]::Max(0,$bytes.Length-$bodyOffset);$body=[byte[]]@();$coverage='Unknown length; body omitted'
   if(!$chunked -and $null -ne $declared){$take=[int][Math]::Min($available,$declared);if($take){$body=[byte[]]$bytes[$bodyOffset..($bodyOffset+$take-1)]};$coverage=if($take -eq $declared -and !$s.Gap){'Captured Content-Length bytes; not proof of send'}else{'Partial or discontinuous capture'}}
   if($chunked){$coverage='Transfer-Encoding unsupported; body omitted'}
   [void]$candidates.Add([pscustomobject]@{Method=$m.Groups[1].Value;URL=$url;URLSource=$schemeSource;Body=$body;DeclaredBodyBytes=$declared;BodyCoverage=$coverage;StreamGap=$s.Gap;Warning='Pre-encryption candidate; generic SSPI breakpoint, not Schannel-context verification, EncryptMessage success or socket-send proof. Context reuse and retries possible.'})
   if($chunked -or $null -eq $declared -or $available -lt $declared -or $s.Gap){break}
   $offset=$bodyOffset+[int]$declared
  }
 }
 return [pscustomobject]@{Candidates=@($candidates);UnsupportedHTTP2Streams=$unsupported}
}
