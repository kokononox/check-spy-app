# Synthetic protocol fixture; never captures network traffic.
$global:LASTEXITCODE=0
$names=@('frame.number','frame.time_epoch','ip.src','ipv6.src','tcp.srcport','udp.srcport','ip.dst','ipv6.dst','tcp.dstport','udp.dstport','tcp.stream','udp.stream','tls.handshake.extensions_server_name','http.request.method','http.host','http.request.uri','http.user_agent','http.file_data','data.data','tls.app_data','http2.header.name','http2.header.value','http2.data.data','dns.qry.name','tcp.payload','tcp.len','udp.length','tls.record.content_type','http.content_type')
if($args -contains '-G'){foreach($n in $names){"F`tFixture`t$n`tFT_STRING"};return}
if($env:RM_TEST_FATAL -eq '1'){[Console]::Error.WriteLine('Synthetic fatal tool error');exit 2}
if($env:RM_TEST_WARNING -eq '1'){[Console]::Error.WriteLine('** [Epan WARNING] -- Dissector bug, protocol X509AF, in packet 2: failed assertion synthetic-fixture')}
$selected=@();for($i=0;$i -lt $args.Count;$i++){if($args[$i] -ceq '-e'){$selected+=$args[$i+1]}}
$body=@{computer_name=[Environment]::MachineName;username=[Environment]::UserName;cpu='SyntheticCPU'} | ConvertTo-Json -Compress
$hex=([BitConverter]::ToString([Text.Encoding]::UTF8.GetBytes($body))).Replace('-','').ToLowerInvariant()
$base=@{'frame.time_epoch'='1767225602';'ip.src'='192.0.2.1';'tcp.srcport'='50000';'ip.dst'='203.0.113.10';'tcp.dstport'='80';'tcp.stream'='1';'tcp.len'='100'}
$p1=$base.Clone();$p1['http.request.method']='POST';$p1['http.host']='fixture.invalid';$p1['http.request.uri']='/report?token=SECRET_FIXTURE&cpu=Value';$p1['http.file_data']=$hex
$p2=$base.Clone();$p2['tls.app_data']='aabb';$p2['tls.record.content_type']='23';$p2['tcp.payload']='aabb';$p2['tcp.stream']='2'
$p3=$p1.Clone();$p3['tcp.srcport']='1'
$p4=@{'frame.time_epoch'='1767225602';'ipv6.src'='2001:db8::1';'tcp.srcport'='50001';'ipv6.dst'='2001:db8::2';'tcp.dstport'='80';'tcp.stream'='3';'http.request.method'='GET';'http.request.uri'='/test'}
$p5=$p1.Clone();$p5['tcp.srcport']='50002'
$p6=$p1.Clone();$p6['frame.time_epoch']='1767225702'
$p7=@{'frame.time_epoch'='1767225602';'ip.src'='192.0.2.1';'udp.srcport'='50003';'ip.dst'='203.0.113.11';'udp.dstport'='9999';'udp.length'='30';'data.data'='aabb'}
$number=0;foreach($p in @($p1,$p2,$p3,$p4,$p5,$p6,$p7)){$number++;$p['frame.number']=[string]$number;($selected | ForEach-Object {[string]$p[$_]}) -join "`t"}
