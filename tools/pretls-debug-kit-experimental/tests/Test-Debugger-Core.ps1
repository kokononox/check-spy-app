$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'Debugger-Core.ps1')
$n=0
function Check($ok,[string]$why){if(!$ok){throw $why};$script:n++}
function Fixture([byte[]]$bytes,[string]$context='0000000000000011/0000000000000022',[int]$declared=-1){
 if($declared -lt 0){$declared=$bytes.Length}
 $lines=@('RM_BEGIN ctx='+$context+' declared='+$declared+' captured='+$bytes.Length)
 for($i=0;$i -lt $bytes.Length;$i+=16){$last=[Math]::Min($i+15,$bytes.Length-1);$part=@($bytes[$i..$last]|ForEach-Object {$_.ToString('x2')});$hex=$part -join ' ';$lines+=('00000000`00100000  '+$hex+'  SYNTHETIC-ASCII')}
 return ($lines+@('RM_END')) -join "`n"
}
$cmd=New-RMCdbCommands
Check ($cmd -match 'bu sspicli!EncryptMessage') 'One explicit symbol'
Check ($cmd -match '0x40000' -and $cmd -match '0x4000' -and $cmd -match '0x40') 'Capture budgets'
Check ($cmd -match 'bc \*; .logclose; .detach; q') 'Detach before quit'
Check ($cmd -match '0x80000000') 'Readonly data excluded'
Check ($cmd -notmatch '(?m)^\.echo .*;') 'No accidental initial detach from echo text'
Check ($cmd -notmatch '(?i)\.writemem|^eb |^eq |\.shell|\.call|\.symfix') 'No write commands/helper injection/shell'
$caught=$false;try{New-RMCdbCommands 'bad!symbol;g'|Out-Null}catch{$caught=$true};Check $caught 'Symbol injection rejected'
$text="POST /upload/full?token=PRIVATE_TOKEN HTTP/1.1`r`nHost: telemetry-in.battle.net`r`nAuthorization: Bearer PRIVATE_AUTH`r`nContent-Length: 4`r`n`r`nDATA"
$raw=Fixture ([Text.Encoding]::ASCII.GetBytes($text));$d=Read-RMCdbData $raw
Check ($d.Records.Count -eq 1 -and $d.ParseErrors -eq 0) 'WinDbg db record parsed'
$h=Get-RMHttpCandidates $d.Records
Check ($h.Candidates.Count -eq 1) 'HTTP1 candidate'
Check ($h.Candidates[0].URL -eq 'https://telemetry-in.battle.net/upload/full?token=PRIVATE_TOKEN') 'Private URL candidate reconstructed'
Check ([Text.Encoding]::ASCII.GetString($h.Candidates[0].Body) -eq 'DATA') 'Body bytes preserved locally'
Check ($h.Candidates[0].URLSource -like '*assumed*') 'Scheme assumption explicit'
$bytes=[Text.Encoding]::ASCII.GetBytes($text);$split=40
$two=(Fixture ([byte[]]$bytes[0..($split-1)]))+"`n"+(Fixture ([byte[]]$bytes[$split..($bytes.Length-1)]))
$joined=Get-RMHttpCandidates (Read-RMCdbData $two).Records
Check ($joined.Candidates.Count -eq 1 -and $joined.Candidates[0].URL -eq $h.Candidates[0].URL) 'Bounded same-context split header replay'
$capped=Get-RMHttpCandidates (Read-RMCdbData (Fixture $bytes '11/22' ($bytes.Length+30))).Records
Check ($capped.Candidates[0].StreamGap -and $capped.Candidates[0].BodyCoverage -like 'Partial*') 'Capped stream not complete'
$bad=Read-RMCdbData ($raw.Replace('captured='+$bytes.Length,'captured='+($bytes.Length+1)))
Check ($bad.ParseErrors -gt 0 -and $bad.Records.Count -eq 0) 'Missing bytes detected'
$h2=Get-RMHttpCandidates (Read-RMCdbData (Fixture ([Text.Encoding]::ASCII.GetBytes("PRI * HTTP/2.0`r`n`r`nSM`r`n`r`n")))).Records
Check ($h2.Candidates.Count -eq 0 -and $h2.UnsupportedHTTP2Streams -eq 1) 'HTTP2 not treated as HTTP1'
$spoof=Get-RMHttpCandidates (Read-RMCdbData (Fixture ([Text.Encoding]::ASCII.GetBytes('BINARY '+$text)))).Records
Check ($spoof.Candidates.Count -eq 0) 'No scanning arbitrary body for fake request'
$dup=$text.Replace('Content-Length: 4',"Content-Length: 4`r`nContent-Length: 4")
$dupResult=Get-RMHttpCandidates (Read-RMCdbData (Fixture ([Text.Encoding]::ASCII.GetBytes($dup)))).Records
Check ($dupResult.Candidates[0].Body.Length -eq 0) 'Ambiguous Content-Length body omitted'
$chunked=$text.Replace('Content-Length: 4','Transfer-Encoding: chunked')
$chunkResult=Get-RMHttpCandidates (Read-RMCdbData (Fixture ([Text.Encoding]::ASCII.GetBytes($chunked)))).Records
Check ($chunkResult.Candidates[0].BodyCoverage -like '*unsupported*') 'Transfer encoding not invented'
$work=Join-Path ([IO.Path]::GetTempPath()) ('rm-preTLS-test-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($work)
try{
 $log=Join-Path $work 'PRIVATE-test.txt';[IO.File]::WriteAllText($log,$raw)
 & (Join-Path (Split-Path -Parent $PSScriptRoot) 'Read-Private-Log.ps1') -LogPath $log
 $safePath=Join-Path $work 'local-results/Report-to-share.json';$safe=Get-Content -LiteralPath $safePath -Raw
 Check ($safe -notmatch 'PRIVATE_TOKEN|PRIVATE_AUTH|telemetry-in|/upload|"DATA"|0011') 'Share report contains no values/URL/context'
 Check (@(Get-ChildItem -LiteralPath (Join-Path $work 'local-results') -Filter '*.bin').Count -eq 0) 'No body files by default'
 & (Join-Path (Split-Path -Parent $PSScriptRoot) 'Read-Private-Log.ps1') -LogPath $log -SavePrivateBodies
 Check (([IO.File]::ReadAllBytes((Join-Path $work 'local-results/body-1.bin'))|ForEach-Object {$_}) -join ',' -eq '68,65,84,65') 'Opt-in private body bytes'
}finally{Remove-Item -LiteralPath $work -Recurse -Force}
Write-Output "PASS: $n synthetic debugger-command/parser/privacy checks. Live CDB not tested."
