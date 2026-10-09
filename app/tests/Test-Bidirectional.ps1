$ErrorActionPreference='Stop';$base=Split-Path -Parent $PSScriptRoot
$work=Join-Path ([IO.Path]::GetTempPath()) ('rm27-net-'+[guid]::NewGuid().ToString('N'));[void][IO.Directory]::CreateDirectory($work)
try{
 $capture=Join-Path $work 'fixture.pcapng';[IO.File]::WriteAllText($capture,'synthetic')
 $ctx=Join-Path $work 'context.json';$report=Join-Path $work 'report.json'
 $connections=@()
 foreach($spec in @(@('192.0.2.1:50000','203.0.113.10',80,'TCP'),@('2001:db8::1:50001','2001:db8::2',80,'TCP'),@('192.0.2.1:50003','203.0.113.11',9999,'UDP'))){$connections+=@{FirstUTC='2026-01-01T00:00:00Z';LastUTC='2026-01-01T00:00:10Z';Local=$spec[0];RemoteIP=$spec[1];Port=$spec[2];Protocol=$spec[3];Source='Snapshot';State='Established';PID=100}}
 @{Target='fixture.exe';Connections=$connections}|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $ctx -Encoding UTF8
 & (Join-Path $base 'Analyze-Capture.ps1') -CapturePath $capture -ContextPath $ctx -OutputPath $report -TsharkPath (Join-Path $PSScriptRoot 'Mock-Tshark-Bidirectional.ps1')
 $d=Get-Content -LiteralPath $report -Raw|ConvertFrom-Json
 if($d.CorrelatedOutboundFrames -ne 4 -or $d.CorrelatedInboundFrames -ne 1 -or $d.ReadableEvidenceFrames -ne 2){throw 'Directional or readable counters failed'}
 $g=@($d.Endpoints|Where-Object {$_.RemoteIP -eq '203.0.113.10'})[0]
 if($g.ObservedOutboundTransportPayloadBytes -ne 200 -or $g.ObservedInboundTransportPayloadBytes -ne 50){throw 'TCP byte counts failed'}
 if($g.TLSAlertCodes -notcontains '48' -or $g.KnownALPN -notcontains 'h2' -or $g.TLSVersionCodes -notcontains '0x0304' -or $g.ObservedRetransmissionFrames -ne 1){throw 'TLS/retransmission metadata failed'}
 $udp=@($d.Endpoints|Where-Object {$_.Protocol -eq 'UDP'})[0];if($udp.ObservedOutboundTransportPayloadBytes -ne 22){throw 'UDP header subtraction failed'}
 if(@($d.Evidence|Where-Object {$_.TimeUTC -and $_.TLSRecognized}).Count -gt 1){throw 'Inbound content incorrectly treated as outgoing'}
 if((Get-Content -LiteralPath $report -Raw) -match 'PRIVATE_ALPN'){throw 'Arbitrary ALPN leaked'}
 'PASS: inbound reverse tuple/time attribution, TCP/UDP observed payload counts, retransmissions, advertised TLS codes/allowlisted ALPN/alerts, no inbound-outgoing evidence confusion'
}finally{Remove-Item -LiteralPath $work -Recurse -Force}
