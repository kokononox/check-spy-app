#requires -Version 5.1
param([string]$TargetPath = '',[switch]$Advanced)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
$root = Join-Path $env:LOCALAPPDATA 'ExeRouteMonitor'
New-Item -ItemType Directory -Force -Path $root | Out-Null
$script:running=$false; $script:worker=$null; $script:handle=$null
$script:rows=New-Object System.Collections.ArrayList
$script:dnsRows=New-Object System.Collections.ArrayList
$script:seen=@{}; $script:alerted=@{}; $script:domains=@{}; $script:known=@{}
$script:lastRecord=0L; $script:sysmon=$false; $script:session=''; $script:logFile=''
$script:lastProbe=[datetime]::MinValue
# Background collector. No packet interception, TLS interception or firewall changes.
$collector = {
 param($target,$known,$lastRecord,$useSysmon,$since)
 $errs=New-Object System.Collections.ArrayList
 $all=@(); $tcp=@(); $udpCount=0; $events=New-Object System.Collections.ArrayList
 try { $all=@(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,ExecutablePath,Name,CreationDate) } catch { [void]$errs.Add('Process query: '+$_.Exception.Message) }
 $ids=@{}
 foreach($p in $all) {
   if($p.ExecutablePath -and [string]::Equals($p.ExecutablePath,$target,[StringComparison]::OrdinalIgnoreCase)) { $ids[[int]$p.ProcessId]=$true }
 }
 # Retain known descendants only if their creation time matches (protect against PID reuse).
 foreach($p in $all) {
   $k=[string]$p.ProcessId
   if($known.ContainsKey($k) -and $known[$k] -eq $p.CreationDate.ToUniversalTime().ToString('o')) { $ids[[int]$p.ProcessId]=$true }
 }
 do {
   $added=$false
   foreach($p in $all) { if($ids.ContainsKey([int]$p.ParentProcessId) -and !$ids.ContainsKey([int]$p.ProcessId)) { $ids[[int]$p.ProcessId]=$true; $added=$true } }
 } while($added)
 $procs=@($all | Where-Object { $ids.ContainsKey([int]$_.ProcessId) })
 try { $tcp=@(Get-NetTCPConnection -ErrorAction Stop | Where-Object { $ids.ContainsKey([int]$_.OwningProcess) -and $_.RemotePort -gt 0 -and $_.RemoteAddress -notin @('0.0.0.0','::') } | Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State) } catch { if($_.FullyQualifiedErrorId -notmatch 'NoMatching') { [void]$errs.Add('TCP query: '+$_.Exception.Message) } }
 try { $udpCount=@(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object { $ids.ContainsKey([int]$_.OwningProcess) }).Count } catch {}
 $cursor=[long]$lastRecord
 if($useSysmon) {
   try {
     $newest=Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop
     if($newest.RecordId -lt $cursor) { $cursor=0L; [void]$errs.Add('Sysmon log reset detected; cursor restarted.') }
     # Ascending bounded pages: the next pass continues from the last processed record.
     $xpath='*[System[(EventID=1 or EventID=3 or EventID=22) and EventRecordID > '+$cursor+']]'
     $ev=@(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -FilterXPath $xpath -Oldest -MaxEvents 1000 -ErrorAction Stop)
     foreach($e in $ev) {
       if($e.RecordId -gt $cursor) { $cursor=$e.RecordId }
       if($e.TimeCreated -lt $since) { continue }
       $x=[xml]$e.ToXml(); $d=@{}
       foreach($n in $x.Event.EventData.Data) { $d[$n.Name]=[string]$n.'#text' }
       [void]$events.Add([pscustomobject]@{Id=$e.Id;Time=$e.TimeCreated.ToUniversalTime().ToString('o');Data=$d})
     }
   } catch {
     if($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { [void]$errs.Add('Sysmon: '+$_.Exception.Message) }
   }
 }
 [pscustomobject]@{Processes=$procs;TCP=$tcp;UDPCount=$udpCount;Events=@($events);Cursor=$cursor;Errors=@($errs)}
}
$form=New-Object Windows.Forms.Form
$form.Text='Exe Route Monitor 2.3.1 | Windows 11'; $form.Size=New-Object Drawing.Size(1280,820)
$form.MinimumSize=New-Object Drawing.Size(1000,680); $form.StartPosition='CenterScreen'
$form.BackColor=[Drawing.Color]::FromArgb(20,26,36); $form.ForeColor=[Drawing.Color]::White
$form.Font=New-Object Drawing.Font('Segoe UI',10)
$top=New-Object Windows.Forms.Panel; $top.Dock='Top'; $top.Height=168; $form.Controls.Add($top)
$title=New-Object Windows.Forms.Label; $title.Text='EXE ROUTE MONITOR'; $title.Font=New-Object Drawing.Font('Segoe UI',20,[Drawing.FontStyle]::Bold); $title.SetBounds(20,12,640,40); $top.Controls.Add($title)
$subtitle=New-Object Windows.Forms.Label; $subtitle.Text='Per-executable monitoring | Child processes | DNS | Auditable history'; $subtitle.SetBounds(22,55,1000,25); $subtitle.ForeColor=[Drawing.Color]::LightSteelBlue; $top.Controls.Add($subtitle)
$pathBox=New-Object Windows.Forms.TextBox; $pathBox.SetBounds(22,90,760,29); $pathBox.Text=$TargetPath; $top.Controls.Add($pathBox)
function New-Button($text,$x,$y,$w,$parent) { $b=New-Object Windows.Forms.Button; $b.Text=$text; $b.SetBounds($x,$y,$w,30); $b.FlatStyle='Flat'; $b.BackColor=[Drawing.Color]::FromArgb(40,55,75); $b.ForeColor=[Drawing.Color]::White; $parent.Controls.Add($b); return $b }
$browse=New-Button 'Browse EXE' 795 88 120 $top
$start=New-Button 'Start' 925 88 95 $top
$stop=New-Button 'Stop' 1030 88 95 $top; $stop.Enabled=$false
$alerts=New-Object Windows.Forms.CheckBox; $alerts.Text='Alert on a new destination'; $alerts.Checked=$true; $alerts.SetBounds(22,132,245,26); $top.Controls.Add($alerts)
$source=New-Object Windows.Forms.Label; $source.Text='Source: not started'; $source.SetBounds(285,133,900,26); $source.ForeColor=[Drawing.Color]::LightSteelBlue; $top.Controls.Add($source)
$bottom=New-Object Windows.Forms.Panel; $bottom.Dock='Bottom'; $bottom.Height=93; $form.Controls.Add($bottom)
$exportCsv=New-Button 'Export CSV' 20 10 120 $bottom
$exportJson=New-Button 'Export JSON' 150 10 120 $bottom
$openLogs=New-Button 'Open logs' 280 10 120 $bottom
$filter=New-Object Windows.Forms.TextBox; $filter.SetBounds(430,12,310,26); $bottom.Controls.Add($filter)
$filterLabel=New-Object Windows.Forms.Label; $filterLabel.Text='Filter IP / domain / process'; $filterLabel.SetBounds(750,15,350,24); $bottom.Controls.Add($filterLabel)
$status=New-Object Windows.Forms.Label; $status.Text='Ready. Select an executable, then Start. Running as administrator improves visibility.'; $status.SetBounds(20,53,1200,34); $bottom.Controls.Add($status)
$tabs=New-Object Windows.Forms.TabControl; $tabs.Dock='Fill'; $form.Controls.Add($tabs); $tabs.BringToFront()
function New-Grid($name,$columns) {
 $tab=New-Object Windows.Forms.TabPage; $tab.Text=$name; $tabs.TabPages.Add($tab)
 $g=New-Object Windows.Forms.DataGridView; $g.Dock='Fill'; $g.ReadOnly=$true; $g.AllowUserToAddRows=$false; $g.AllowUserToDeleteRows=$false; $g.RowHeadersVisible=$false
 $g.AutoSizeColumnsMode='Fill'; $g.BackgroundColor=[Drawing.Color]::FromArgb(25,33,45); $g.DefaultCellStyle.BackColor=[Drawing.Color]::FromArgb(25,33,45); $g.DefaultCellStyle.ForeColor=[Drawing.Color]::White
 $g.DefaultCellStyle.SelectionBackColor=[Drawing.Color]::FromArgb(30,95,130); $g.EnableHeadersVisualStyles=$false; $g.ColumnHeadersDefaultCellStyle.BackColor=[Drawing.Color]::FromArgb(40,55,75); $g.ColumnHeadersDefaultCellStyle.ForeColor=[Drawing.Color]::White
 foreach($c in $columns) { [void]$g.Columns.Add($c,$c) }; $tab.Controls.Add($g); return ,$g
}
$grid=New-Grid 'Connections / History' @('FirstUTC','LastUTC','Process','PID','Protocol','RemoteIP','Port','Domain','Local','State','Source')
$dnsGrid=New-Grid 'DNS queries' @('TimeUTC','Process','PID','Query','Results','Status')
$procGrid=New-Grid 'Tracked processes' @('Process','PID','ParentPID','Path','CreatedUTC')
$helpTab=New-Object Windows.Forms.TabPage; $helpTab.Text='Coverage / Help'; $tabs.TabPages.Add($helpTab)
$help=New-Object Windows.Forms.RichTextBox; $help.Dock='Fill'; $help.ReadOnly=$true; $help.BackColor=[Drawing.Color]::FromArgb(25,33,45); $help.ForeColor=[Drawing.Color]::White; $help.Font=New-Object Drawing.Font('Segoe UI',11)
$help.Text=@'
COVERAGE

Basic mode: polls Windows TCP tables approximately every 2 seconds (query duration may extend this interval). Includes IPv4 and IPv6 connections owned by the selected EXE or observed descendants. Short-lived connections between polls may be missed. UDP tables reveal local listeners, NOT remote destinations; their count is shown in the status bar and is never presented as a remote connection.

Enhanced mode: reads Sysmon events 1 (process creation), 3 (network connections), and 22 (DNS). Sysmon must already be installed, and those event types must be enabled. This captures more short-lived connections and UDP destinations. UDP and DNS capture still depend on Sysmon/Windows coverage and configuration; this is not a guarantee of every packet or destination.

The label "Sysmon readable" confirms access to its log, NOT that event IDs 1, 3, and 22 are enabled. If installed during monitoring, stop and restart monitoring. A configuration template and installation instructions are included in this package.

Process ancestry is tracked from snapshots and Sysmon ProcessGuid lineage. PID reuse is guarded by creation time / GUID. Children whose parent exited before discovery may be missed without Sysmon process-create events. A separate system service, browser, proxy, or broker making requests on behalf of the EXE is not necessarily its descendant and is outside this scope.

DNS association is evidence-based, not reverse-DNS guessing. IP-to-domain associations come only from tracked DNS results and are labeled observed. Multiple domains may share an IP. Cached lookups, encrypted DNS, hard-coded IPs, and proxies may leave the domain unknown. HTTPS full URLs, request bodies, VPN inner traffic, packet sizes and byte totals are not decoded.

HISTORY / PRIVACY

A new session starts when you press Start. The displayed history is this session only. Old session files remain in %LOCALAPPDATA%\ExeRouteMonitor. Each session has a metadata JSON file and an append-only JSONL event log. No external upload, analytics, automatic Sysmon installation, or firewall changes are performed. DNS names and executable paths can be sensitive: protect exports and logs.

New-destination alerts are tray notifications, once per protocol / IP / port per session. Windows notification settings may suppress them. Sorting and the text filter affect the display only; CSV and JSON exports include the full session. Connection states are snapshots; "Not seen" does not mean a proven close. Sysmon events show connection occurrence, not a live socket state.

Start this utility before launching the target for the best ancestry coverage. Elevation is recommended. Monitoring does not launch, block or modify the target. Stop cancels the collector; the last in-flight sample can be discarded. If a target executable is renamed or replaced, the rule still matches its path, not its hash.
'@
$helpTab.Controls.Add($help)
$tray=New-Object Windows.Forms.NotifyIcon; $tray.Icon=[Drawing.SystemIcons]::Information; $tray.Text='Exe Route Monitor'; $tray.Visible=$true
function Write-Log($type,$data) {
 if(!$script:logFile) { return }
 $obj=[ordered]@{Type=$type;LoggedUTC=[datetime]::UtcNow.ToString('o');Data=$data}
 $json=$obj | ConvertTo-Json -Depth 8 -Compress
 try { [IO.File]::AppendAllText($script:logFile,$json+[Environment]::NewLine,(New-Object Text.UTF8Encoding($false))) } catch { $status.Text='Log write failed: '+$_.Exception.Message }
}
function Add-Connection($time,$proc,$processId,$proto,$ip,$port,$local,$state,$origin,$discriminator) {
 if(!$ip -or !$port) { return }
 # Sysmon retains each event separately. Snapshot rows summarize the same tuple.
 $key=$origin+'|'+$processId+'|'+$proto+'|'+$local+'|'+$ip+'|'+$port+'|'+$discriminator
 if($script:seen.ContainsKey($key)) { $r=$script:seen[$key]; $r.LastUTC=$time; $r.State=$state; return }
 $domain='Unknown'
 if($script:domains.ContainsKey($ip)) { $domain=(@($script:domains[$ip].Keys) -join '; ')+' [observed DNS]' }
 $r=[pscustomobject]@{FirstUTC=$time;LastUTC=$time;Process=$proc;PID=$processId;Protocol=$proto;RemoteIP=$ip;Port=$port;Domain=$domain;Local=$local;State=$state;Source=$origin}
 [void]$script:rows.Add($r); $script:seen[$key]=$r; Write-Log 'connection' $r
 $a=$proto+'|'+$ip+'|'+$port
 if(!$script:alerted.ContainsKey($a)) {
  $script:alerted[$a]=$true
  if($alerts.Checked) { $tray.ShowBalloonTip(5000,'New destination',($proc+' -> '+$ip+':'+$port+' ('+$proto+')'),[Windows.Forms.ToolTipIcon]::Info) }
 }
}
function Refresh-Grids {
 if($script:simpleMode){return}
 $q=$filter.Text.Trim(); $grid.SuspendLayout(); $grid.Rows.Clear()
 # Bound the UI, not the event log or exports.
 $visible=@($script:rows | Where-Object { !$q -or (($_.PSObject.Properties.Value -join ' ').IndexOf($q,[StringComparison]::OrdinalIgnoreCase) -ge 0) } | Select-Object -Last 2000)
 foreach($r in $visible) { [void]$grid.Rows.Add([object[]]@($r.FirstUTC,$r.LastUTC,$r.Process,$r.PID,$r.Protocol,$r.RemoteIP,$r.Port,$r.Domain,$r.Local,$r.State,$r.Source)) }
 $grid.ResumeLayout(); $dnsGrid.Rows.Clear()
 foreach($r in @($script:dnsRows | Select-Object -Last 2000)) { [void]$dnsGrid.Rows.Add([object[]]@($r.TimeUTC,$r.Process,$r.PID,$r.Query,$r.Results,$r.Status)) }
}
$script:guids=@{}
function Apply-Sample($sample) {
 $script:known=@{}
 foreach($p in @($sample.Processes)) { $script:known[[string]$p.ProcessId]=$p.CreationDate.ToUniversalTime().ToString('o') }
 $procGrid.Rows.Clear()
 foreach($p in @($sample.Processes)) { [void]$procGrid.Rows.Add([object[]]@($p.Name,$p.ProcessId,$p.ParentProcessId,$p.ExecutablePath,$p.CreationDate.ToUniversalTime().ToString('o'))) }
 $newCursor=[long]$sample.Cursor
 if($newCursor -lt $script:lastRecord) { Write-Log 'warning' 'Sysmon cursor moved backwards; log may have been cleared.' }
 $script:lastRecord=$newCursor
 foreach($ev in @($sample.Events)) {
  $d=$ev.Data
  if($ev.Id -eq 1) {
   if([string]::Equals($d.Image,$script:target,[StringComparison]::OrdinalIgnoreCase) -or $script:guids.ContainsKey($d.ParentProcessGuid)) {
    if($d.ProcessGuid) { $script:guids[$d.ProcessGuid]=$true; Write-Log 'process-create' $d }
   }; continue
  }
  $tracked=[string]::Equals($d.Image,$script:target,[StringComparison]::OrdinalIgnoreCase) -or ($d.ProcessGuid -and $script:guids.ContainsKey($d.ProcessGuid))
  # Snapshot lineage is acceptable only when this event is not older than that PID's creation.
  if(!$tracked -and $script:known.ContainsKey([string]$d.ProcessId)) { $tracked=([datetime]$ev.Time -ge [datetime]$script:known[[string]$d.ProcessId]) }
  if(!$tracked) { continue }
  if($d.ProcessGuid) { $script:guids[$d.ProcessGuid]=$true }
  if($ev.Id -eq 22) {
   $r=[pscustomobject]@{TimeUTC=$ev.Time;Process=$d.Image;PID=$d.ProcessId;Query=$d.QueryName;Results=$d.QueryResults;Status=$d.QueryStatus}
   [void]$script:dnsRows.Add($r); Write-Log 'dns' $r
   foreach($part in ($d.QueryResults -split ';')) {
    $v=$part.Trim() -replace '^::ffff:',''; $addr=$null
    if([Net.IPAddress]::TryParse($v,[ref]$addr) -and $d.QueryName) {
     $ip=$addr.ToString(); if(!$script:domains.ContainsKey($ip)) { $script:domains[$ip]=@{} }; $script:domains[$ip][$d.QueryName]=$true
     foreach($row in $script:rows) { if($row.RemoteIP -eq $ip) { $row.Domain=(@($script:domains[$ip].Keys) -join '; ')+' [observed DNS]' } }
    }
   }
  } elseif($ev.Id -eq 3) {
   $direction=if($d.Initiated -eq 'false'){'Inbound event'}else{'Outbound event'}
   if($d.Initiated -eq 'false') {
    Add-Connection $ev.Time $d.Image $d.ProcessId $d.Protocol.ToUpperInvariant() $d.SourceIp $d.SourcePort ($d.DestinationIp+':'+$d.DestinationPort) $direction 'Sysmon' ($d.ProcessGuid+'|'+$ev.Time)
   } else {
    Add-Connection $ev.Time $d.Image $d.ProcessId $d.Protocol.ToUpperInvariant() $d.DestinationIp $d.DestinationPort ($d.SourceIp+':'+$d.SourcePort) $direction 'Sysmon' ($d.ProcessGuid+'|'+$ev.Time)
   }
  }
 }
 foreach($r in $script:rows) { if($r.Source -eq 'Snapshot') { $r.State='Not seen' } }
 $now=[datetime]::UtcNow.ToString('o')
 foreach($t in @($sample.TCP)) {
  $p=@($sample.Processes | Where-Object { $_.ProcessId -eq $t.OwningProcess } | Select-Object -First 1)
  $name=if($p.Count){$p[0].ExecutablePath}else{''}
  $created=if($script:known.ContainsKey([string]$t.OwningProcess)){$script:known[[string]$t.OwningProcess]}else{''}
  Add-Connection $now $name $t.OwningProcess 'TCP' $t.RemoteAddress $t.RemotePort ($t.LocalAddress+':'+$t.LocalPort) ([string]$t.State) 'Snapshot' $created
 }
 Write-Log 'snapshot' ([ordered]@{TimeUTC=$now;Processes=@($sample.Processes);TCP=@($sample.TCP);UDPLocalEndpointCount=$sample.UDPCount})
 Refresh-Grids
 $status.Text=('Processes: {0} | Records: {1} | DNS: {2} | UDP local endpoints: {3} | Display: last 2000 | {4}' -f @($sample.Processes).Count,$script:rows.Count,$script:dnsRows.Count,$sample.UDPCount,($sample.Errors -join '; '))
 foreach($err in @($sample.Errors)) { Write-Log 'warning' $err }
}
$timer=New-Object Windows.Forms.Timer; $timer.Interval=300
$timer.Add_Tick({
 if(!$script:running) { return }
 try {
  if($script:handle -and $script:handle.IsCompleted) {
   $result=$script:worker.EndInvoke($script:handle)
   $script:worker.Dispose(); $script:worker=$null; $script:handle=$null
   if($result.Count -gt 0) { Apply-Sample $result[$result.Count-1] }
   $script:lastProbe=[datetime]::UtcNow
  }
  if(!$script:handle -and (([datetime]::UtcNow-$script:lastProbe).TotalSeconds -ge 2)) {
   $k=@{}; foreach($key in $script:known.Keys) { $k[$key]=$script:known[$key] }
   $script:worker=[PowerShell]::Create()
   [void]$script:worker.AddScript($collector.ToString()).AddArgument($script:target).AddArgument($k).AddArgument($script:lastRecord).AddArgument($script:sysmon).AddArgument($script:since)
   $script:handle=$script:worker.BeginInvoke()
  }
 } catch { $status.Text='Collector error: '+$_.Exception.Message; Write-Log 'error' $_.Exception.Message; if($script:worker){$script:worker.Dispose()}; $script:worker=$null; $script:handle=$null; $script:lastProbe=[datetime]::UtcNow }
})
$browse.Add_Click({ $d=New-Object Windows.Forms.OpenFileDialog; $d.Filter='Executable (*.exe)|*.exe'; if($d.ShowDialog() -eq 'OK'){$pathBox.Text=$d.FileName}; $d.Dispose() })
function Start-MonitorSession {
 try {
  if($script:setupBusy){throw 'Dependency installation is in progress.'}
  if($script:captureOwned){throw 'Stop the active packet capture before starting a new session.'}
  $candidate=$pathBox.Text.Trim().Trim('"')
  if(!(Test-Path -LiteralPath $candidate -PathType Leaf) -or [IO.Path]::GetExtension($candidate) -ne '.exe') { throw 'Choose an existing .exe file.' }
  $script:target=(Get-Item -LiteralPath $candidate).FullName
  if(!@(Get-Service -Name 'Sysmon','Sysmon64','Sysmon64a' -ErrorAction SilentlyContinue).Count){[void](RM-InstallSysmon)}
  $script:targetHash=(Get-FileHash -LiteralPath $script:target -Algorithm SHA256).Hash
  if(!$script:simpleMode -and $script:rows.Count -gt 0) { if([Windows.Forms.MessageBox]::Show('Start a new session? The display will reset; previous logs remain on disk.','New session','YesNo') -ne 'Yes'){return} }
  $script:rows.Clear(); $script:dnsRows.Clear(); $script:seen=@{}; $script:alerted=@{}; $script:domains=@{}; $script:known=@{}; $script:guids=@{}
  $script:lastRecord=0L; $script:sysmon=$false
  try { $latest=Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 1 -ErrorAction Stop; $script:lastRecord=$latest.RecordId; $script:sysmon=$true } catch {}
  $script:since=[datetime]::UtcNow
  $script:session=([datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6))
  $script:logFile=Join-Path $root ($script:session+'.jsonl')
  [ordered]@{Session=$script:session;Target=$script:target;TargetSHA256=$script:targetHash;StartedUTC=$script:since.ToString('o');SysmonReadable=$script:sysmon;PollSeconds=2;Version='2.3.1'} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $root ($script:session+'.metadata.json')) -Encoding UTF8
  Write-Log 'session-start' $script:target
  $source.Text=if($script:sysmon){'Source: TCP snapshots + Sysmon readable (verify events 1 / 3 / 22 enabled)'}else{'Source: TCP snapshots only | DNS / UDP destinations require Sysmon'}
  $script:running=$true; $script:lastProbe=[datetime]::MinValue
  $start.Enabled=$false; $stop.Enabled=$true; $browse.Enabled=$false; $pathBox.Enabled=$false; $timer.Start(); Refresh-Grids
 } catch { [void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'Cannot start') }
}
$start.Add_Click({Start-MonitorSession})
function Stop-Monitor {
 if($script:captureOwned){try {RM-StopCapture}catch{Write-Log 'capture-error' $_.Exception.Message}}
 $script:running=$false; $timer.Stop()
 if($script:worker){ try {$script:worker.Stop()}catch{}; $script:worker.Dispose(); $script:worker=$null; $script:handle=$null }
 Write-Log 'session-stop' ([datetime]::UtcNow.ToString('o'))
 $start.Enabled=$true; $stop.Enabled=$false; $browse.Enabled=$true; $pathBox.Enabled=$true
}
$stop.Add_Click({ Stop-Monitor; $status.Text='Stopped. History retained; exports include all session records.' })
$filter.Add_TextChanged({ Refresh-Grids })
function Export-Session($format) {
 $d=New-Object Windows.Forms.SaveFileDialog; $d.Filter=if($format -eq 'csv'){'CSV (*.csv)|*.csv'}else{'JSON (*.json)|*.json'}; $d.FileName='ExeRouteMonitor-'+$script:session+'.'+$format
 if($d.ShowDialog() -eq 'OK') {
  try {
   if($format -eq 'csv') {
    # Spreadsheet-formula injection guard for untrusted DNS/path text.
    $safe=@($script:rows | ForEach-Object { $obj=[ordered]@{}; foreach($p in $_.PSObject.Properties) { $v=$p.Value; if($v -is [string] -and $v -match '^\s*[=+@-]'){$v="'"+$v}; $obj[$p.Name]=$v }; [pscustomobject]$obj })
    if($safe.Count){$safe | Export-Csv -LiteralPath $d.FileName -NoTypeInformation -Encoding UTF8}else{'FirstUTC,LastUTC,Process,PID,Protocol,RemoteIP,Port,Domain,Local,State,Source' | Set-Content -LiteralPath $d.FileName -Encoding UTF8}
   } else { [ordered]@{Version='2.3.1';Target=$script:target;TargetSHA256=$script:targetHash;ExportedUTC=[datetime]::UtcNow.ToString('o');Connections=@($script:rows);DNS=@($script:dnsRows)} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $d.FileName -Encoding UTF8 }
   $status.Text='Exported: '+$d.FileName
  } catch { [void][Windows.Forms.MessageBox]::Show($_.Exception.Message,'Export failed') }
 }; $d.Dispose()
}
$exportCsv.Add_Click({ Export-Session 'csv' }); $exportJson.Add_Click({ Export-Session 'json' })
$openLogs.Add_Click({ Start-Process explorer.exe -ArgumentList ('"'+$root+'"') })
$form.Add_FormClosing({param($sender,$e)
 if($script:setupBusy -or $script:autoPreparing){$e.Cancel=$true;return}
 Stop-Monitor; $tray.Visible=$false; $tray.Dispose(); $timer.Dispose() })
. (Join-Path $PSScriptRoot 'Evidence-UI.ps1')
if(!$Advanced){. (Join-Path $PSScriptRoot 'Simple-UI.ps1')}
[void]$form.ShowDialog(); $form.Dispose()
