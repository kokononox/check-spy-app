# Dot-sourced by Monitor.ps1. Uses its current session and controls.
$script:captureOwned=$false; $script:captureFile=''; $script:captureContext=''; $script:tlsFile=''
$evTab=New-Object Windows.Forms.TabPage; $evTab.Text='Traffic / System data'; $tabs.TabPages.Add($evTab)
$evTab.BackColor=[Drawing.Color]::FromArgb(25,33,45); $evTab.ForeColor=[Drawing.Color]::White; $evTab.AutoScroll=$true
$evTitle=New-Object Windows.Forms.Label; $evTitle.Text='What is sent? Evidence first, no guessing.'; $evTitle.Font=New-Object Drawing.Font('Segoe UI',16,[Drawing.FontStyle]::Bold); $evTitle.SetBounds(22,18,1100,40); $evTab.Controls.Add($evTitle)
$evInfo=New-Object Windows.Forms.Label; $evInfo.SetBounds(22,66,1130,90); $evInfo.Text="1. Start EXE monitoring.  2. Capture briefly.  3. Stop capture.  4. Analyze with tshark.`nCapture is SYSTEM-WIDE at NICs; analysis correlates outbound tuples to the monitored EXE.`nHTTPS content remains unknown unless the app supports TLS key logging and decryption works.`nNo certificates, MITM proxy, firewall changes, process injection or automatic installation."; $evTab.Controls.Add($evInfo)
$evCheck=New-Button 'Check Sysmon' 22 169 165 $evTab
$evConfig=New-Button 'Open Sysmon template' 202 169 195 $evTab
$evInstall=New-Button 'Install official Sysmon' 412 169 200 $evTab
$evCapture=New-Button 'Start packet capture' 22 218 180 $evTab
$evStop=New-Button 'Stop + convert' 217 218 165 $evTab; $evStop.Enabled=$false
$evFolder=New-Button 'Open evidence folder' 397 218 190 $evTab
$evLaunch=New-Button 'Create TLS launch script' 22 268 285 $evTab
$evArgs=New-Object Windows.Forms.TextBox; $evArgs.SetBounds(322,270,500,27); $evTab.Controls.Add($evArgs)
$evArgsLabel=New-Object Windows.Forms.Label; $evArgsLabel.Text='Optional target arguments'; $evArgsLabel.SetBounds(832,271,270,25); $evTab.Controls.Add($evArgsLabel)
$evCompare=New-Object Windows.Forms.CheckBox; $evCompare.Text='Compare readable outbound data with this PC/user identifiers (opt-in)'; $evCompare.SetBounds(22,318,1010,30); $evCompare.Checked=$false; $evTab.Controls.Add($evCompare)
$evAnalyze=New-Button 'Analyze last capture' 22 363 190 $evTab
$evImport=New-Button 'Analyze existing PCAP' 227 363 190 $evTab
$evWireshark=New-Button 'Open capture in Wireshark' 432 363 230 $evTab
$evKeys=New-Button 'Select TLS key file' 677 363 175 $evTab
$evText=New-Object Windows.Forms.RichTextBox; $evText.SetBounds(22,416,1110,260); $evText.ReadOnly=$true; $evText.BackColor=[Drawing.Color]::FromArgb(20,26,36); $evText.ForeColor=[Drawing.Color]::LightSteelBlue; $evTab.Controls.Add($evText)
$evText.Text="Ready. Optional tools are not bundled: official Sysmon for events, Wireshark/tshark for analysis. Pktmon is built into Windows 11.`nA field name is a clue, not proof of a value. A local identifier string in readable outbound data is stronger evidence, but does not establish malicious intent."
function RM-Message([string]$text){$evText.AppendText("`n"+$text)}
function RM-IsAdmin { $id=[Security.Principal.WindowsIdentity]::GetCurrent(); $pr=New-Object Security.Principal.WindowsPrincipal($id); return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function RM-SaveContext {
 if(!$script:session){throw 'Start a monitoring session first.'}
 $script:captureContext=$script:captureFile+'.connections.json'
 [ordered]@{Version='2.0';Target=$script:target;TargetSHA256=$script:targetHash;ExportedUTC=[datetime]::UtcNow.ToString('o');Connections=@($script:rows);DNS=@($script:dnsRows)} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:captureContext -Encoding UTF8
}
function RM-StopCapture {
 if(!$script:captureOwned){return}
 $pkt=Join-Path $env:WINDIR 'System32\pktmon.exe'
 $output=& $pkt stop 2>&1 | Out-String
 if($LASTEXITCODE -ne 0){RM-Message ('Stop failed: '+$output);return}
 $script:captureOwned=$false; $evCapture.Enabled=$true; $evStop.Enabled=$false
 RM-SaveContext
 $pcap=[IO.Path]::ChangeExtension($script:captureFile,'.pcapng')
 $output=& $pkt etl2pcap $script:captureFile --out $pcap 2>&1 | Out-String
 if($LASTEXITCODE -eq 0){RM-Message ('Saved capture: '+$pcap); $script:capturePCAP=$pcap}else{RM-Message ('Conversion failed. ETL retained: '+$output)}
 Write-Log 'capture-stop' ([ordered]@{Capture=$script:captureFile;Context=$script:captureContext})
}
$evCheck.Add_Click({
 try {
  $services=@(Get-Service -Name '*Sysmon*' -ErrorAction SilentlyContinue)
  RM-Message ('Sysmon services: '+(($services | ForEach-Object {$_.Name+'='+$_.Status}) -join '; '))
  $startTime=(Get-Date).AddHours(-24); $check=@()
  foreach($id in @(1,3,22)) {
   try { $e=Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=$id;StartTime=$startTime} -MaxEvents 1 -ErrorAction Stop; $check+=('Event '+$id+': observed at '+$e.TimeCreated) }
   catch { $check+=('Event '+$id+': not observed/readable in last 24h; absence does not prove disabled') }
  }
  RM-Message ($check -join "`n")
  RM-Message 'This checks observed events, not the full effective Sysmon configuration. Restart monitoring after installing/configuring Sysmon.'
 } catch {RM-Message $_.Exception.Message}
})
$evConfig.Add_Click({Start-Process notepad.exe -ArgumentList ('"'+(Join-Path $PSScriptRoot 'Sysmon-config.xml')+'"')})
$evInstall.Add_Click({
 try {
  if(!(RM-IsAdmin)){throw 'Run the utility as Administrator for fresh Sysmon installation.'}
  if(@(Get-Service -Name 'Sysmon','Sysmon64' -ErrorAction SilentlyContinue).Count){throw 'Sysmon is already installed. This utility will NOT overwrite its policy. Review/merge the template with your administrator.'}
  $d=New-Object Windows.Forms.OpenFileDialog; $d.Title='Select official Microsoft Sysmon64.exe';$d.Filter='Sysmon executable|Sysmon64.exe;Sysmon.exe'
  if($d.ShowDialog() -ne 'OK'){$d.Dispose();return};$exe=$d.FileName;$d.Dispose()
  $signature=Get-AuthenticodeSignature -LiteralPath $exe
  if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'A valid Microsoft Corporation digital signature is required. Download only official Sysmon.'}
  if([Windows.Forms.MessageBox]::Show("Read Microsoft Sysmon's EULA (link in README). Yes means you accept that EULA and authorize installing its system service with the included template. This records ALL system process creation, network and DNS events in Windows Event Log, not just this EXE. Sensitive data and increased log volume are possible. No existing Sysmon policy is replaced.",'Accept EULA and install Sysmon?','YesNo','Warning') -ne 'Yes'){return}
  $output=& $exe -accepteula -i (Join-Path $PSScriptRoot 'Sysmon-config.xml') 2>&1 | Out-String
  if($LASTEXITCODE -ne 0){throw ('Sysmon install failed: '+$output)}
  RM-Message ('Sysmon installation command succeeded. Stop/Start monitoring and use Check Sysmon. '+$output)
 } catch {RM-Message $_.Exception.Message}
})
$evCapture.Add_Click({
 try {
  if(!$script:running){throw 'Start EXE monitoring first.'}; if(!(RM-IsAdmin)){throw 'Restart this utility as Administrator to use pktmon.'}
  if([Windows.Forms.MessageBox]::Show("Capture ALL system traffic at NICs? Existing pktmon filters are kept and can limit coverage. Raw packets may contain passwords/tokens, browsing activity and private data. Store locally and do not share publicly. Circular capture requests a 256 MB limit; old packets can be overwritten. Stop after a short test.",'Sensitive system-wide capture','YesNo','Warning') -ne 'Yes'){return}
  # Do not stop/replace a packet monitor already running on the machine.
  $old=$ErrorActionPreference; $ErrorActionPreference='Continue'
  $active=& logman.exe query PktMon -ets 2>&1; $activeCode=$LASTEXITCODE; $ErrorActionPreference=$old
  if($activeCode -eq 0){throw 'A PktMon ETW session already exists. This tool will not replace it.'}
  $folder=Join-Path $root ('evidence-'+$script:session); New-Item -ItemType Directory -Force -Path $folder | Out-Null
  $script:captureFile=Join-Path $folder ('capture-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.etl')
  $script:capturePCAP=''
  $pkt=Join-Path $env:WINDIR 'System32\pktmon.exe'
  & $pkt filter list 2>&1 | Out-File -LiteralPath ($script:captureFile+'.filters.txt') -Encoding UTF8
  $output=& $pkt start --capture --comp nics --pkt-size 0 --file-name $script:captureFile --file-size 256 --log-mode circular 2>&1 | Out-String
  if($LASTEXITCODE -ne 0){throw ('Pktmon start failed: '+$output)}
  $script:captureOwned=$true; $evCapture.Enabled=$false; $evStop.Enabled=$true
  RM-Message ('Capturing. Start/perform the target action now, then Stop + convert. '+$script:captureFile)
  Write-Log 'capture-start' ([ordered]@{Path=$script:captureFile;Scope='System-wide NICs, existing filters retained';PacketSize='full';RequestedLimitMB=256;Mode='circular'})
 } catch {RM-Message $_.Exception.Message}
})
$evStop.Add_Click({try {RM-StopCapture}catch{RM-Message $_.Exception.Message}})
$evFolder.Add_Click({Start-Process explorer.exe -ArgumentList ('"'+$root+'"')})
$evLaunch.Add_Click({
 try {
  if(!$script:running){throw 'Select the target and Start monitoring first.'}
  if([Windows.Forms.MessageBox]::Show("Create a launch script that sets SSLKEYLOGFILE only for the selected EXE and its descendants? It works only if supported by the target. Key files can decrypt sessions and must remain private. Close the existing target. For safety the target will NOT be launched with this utility's elevated rights. Run the generated Launch-Target.cmd yourself from ordinary Explorer.",'Optional TLS keys','YesNo','Warning') -ne 'Yes'){return}
  $folder=Join-Path $root ('evidence-'+$script:session); New-Item -ItemType Directory -Force -Path $folder | Out-Null
  $script:tlsFile=Join-Path $folder ('tls-keys-'+[datetime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.log')
  [ordered]@{Target=$script:target;Arguments=$evArgs.Text;KeyFile=$script:tlsFile} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $folder 'Launch-Target.json') -Encoding UTF8
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Launch-Target.ps1') -Destination (Join-Path $folder 'Launch-Target.ps1') -Force
  Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Launch-Target.cmd') -Destination (Join-Path $folder 'Launch-Target.cmd') -Force
  Start-Process explorer.exe -ArgumentList ('"'+$folder+'"')
  RM-Message ('Launch files created in '+$folder+'. Start capture FIRST, then double-click Launch-Target.cmd in ordinary Explorer. No key file means key logging was not produced; check app support.')
 } catch {RM-Message $_.Exception.Message}
})
$evKeys.Add_Click({$d=New-Object Windows.Forms.OpenFileDialog; $d.Filter='TLS key files|*.log;*.txt;*.*';if($d.ShowDialog() -eq 'OK'){$script:tlsFile=$d.FileName;RM-Message ('Key file selected: '+$script:tlsFile)};$d.Dispose()})
function RM-Analyze([string]$cap,[string]$context) {
 if($script:captureOwned){throw 'Stop capture before analysis.'}
 if(!(Test-Path -LiteralPath $cap -PathType Leaf)){throw 'No PCAPNG available. Capture and convert first.'}
 $tshark=Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'; $cmd=Get-Command tshark.exe -ErrorAction SilentlyContinue;if($cmd){$tshark=$cmd.Source}
 if(!(Test-Path -LiteralPath $tshark)){throw 'Install official Wireshark with tshark, then retry. No tool is downloaded automatically.'}
 $analyzer=Join-Path $PSScriptRoot 'Analyze-Capture.ps1'; $out=$cap+'.evidence.json'
 $arg='-NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -File "'+$analyzer+'" -CapturePath "'+$cap+'" -ContextPath "'+$context+'" -OutputPath "'+$out+'" -TsharkPath "'+$tshark+'"'
 if($script:tlsFile -and (Test-Path -LiteralPath $script:tlsFile -PathType Leaf)){$arg+=' -KeyLogPath "'+$script:tlsFile+'"'}
 if($evCompare.Checked){$arg+=' -CompareLocalIdentifiers'}
 Start-Process powershell.exe -ArgumentList $arg
 RM-Message ('Analysis started in a separate console. Check the console for errors. On success open: '+$out+'. Raw payload values are not copied into the report.')
 $script:lastEvidence=$out
}
$evAnalyze.Add_Click({try {RM-Analyze $script:capturePCAP $script:captureContext}catch{RM-Message $_.Exception.Message}})
$evImport.Add_Click({
 try {
  $d=New-Object Windows.Forms.OpenFileDialog; $d.Title='Select PCAP/PCAPNG';$d.Filter='Packet capture|*.pcap;*.pcapng';if($d.ShowDialog() -ne 'OK'){$d.Dispose();return};$cap=$d.FileName;$d.Dispose()
  $d=New-Object Windows.Forms.OpenFileDialog;$d.Title='Select matching session JSON (connection export)';$d.Filter='Connection context|*.json';if($d.ShowDialog() -ne 'OK'){$d.Dispose();return};$ctx=$d.FileName;$d.Dispose()
  RM-Analyze $cap $ctx
 } catch {RM-Message $_.Exception.Message}
})
$evWireshark.Add_Click({
 try {
  $ws=Join-Path $env:ProgramFiles 'Wireshark\Wireshark.exe';if(!(Test-Path -LiteralPath $ws)){throw 'Install official Wireshark first.'}
  if(!$script:capturePCAP){throw 'No converted capture available.'}
  Start-Process $ws -ArgumentList ('"'+$script:capturePCAP+'"')
  RM-Message 'Wireshark opened. For readable request values use Follow HTTP/TLS Stream where supported. Raw capture is system-wide: use the target tuples and timestamps. Set TLS key file manually if needed; do not publish it.'
 } catch {RM-Message $_.Exception.Message}
})
$evReport=New-Button 'Open analysis report' 22 693 200 $evTab
$evReport.Add_Click({if($script:lastEvidence -and (Test-Path -LiteralPath $script:lastEvidence)){Start-Process notepad.exe -ArgumentList ('"'+$script:lastEvidence+'"')}else{RM-Message 'Report not yet available. Check the analysis console.'}})
$form.Add_FormClosing({if($script:captureOwned){try {RM-StopCapture}catch{RM-Message $_.Exception.Message}}})
