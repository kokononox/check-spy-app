# Dependency setup. Dot-source from UI. Downloads only approved official endpoints.
$script:setupBusy=$false
function RM-Architecture {
 $a=[Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
 if(!$a){$a=[Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE')}
 if($a -eq 'ARM64'){return 'arm64'}
 if($a -eq 'AMD64' -or [Environment]::Is64BitOperatingSystem){return 'x64'}
 throw 'Only Windows 11 x64/ARM64 is supported.'
}
function RM-FindWireshark([string]$name='tshark.exe') {
 $roots=@($env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramW6432')) | Where-Object {$_} | Select-Object -Unique
 foreach($r in $roots){$p=Join-Path $r ('Wireshark\'+$name);if(Test-Path -LiteralPath $p -PathType Leaf){return $p}}
 $c=Get-Command $name -ErrorAction SilentlyContinue;if($c){return $c.Source};return ''
}
function RM-VerifyBinary([string]$path,[string]$organization,[string]$expectedHash='') {
 if(!(Test-Path -LiteralPath $path -PathType Leaf)){throw ('Installer not found: '+$path)}
 if($expectedHash -and (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ne $expectedHash){throw 'Installer SHA256 mismatch. Installation blocked; download a fresh official package.'}
 $s=Get-AuthenticodeSignature -LiteralPath $path
 if($s.Status -ne 'Valid' -or !$s.SignerCertificate -or $s.SignerCertificate.Subject -notmatch ('(?:^|,\s*)O='+[regex]::Escape($organization)+'(?:,|$)')){throw ('Valid '+$organization+' Authenticode signature required. Do not disable signature verification. Windows may need Internet access to validate the certificate chain.')}
}
function RM-Download([string]$url,[string]$destination) {
 if($url -notmatch '^https://(download\.sysinternals\.com/files/Sysmon\.zip|2\.na\.dl\.wireshark\.org/win64/Wireshark-4\.6\.9-(x64|arm64)\.exe)$'){throw 'Unapproved dependency URL.'}
 New-Item -ItemType Directory -Force -Path ([IO.Path]::GetDirectoryName($destination)) | Out-Null
 $part=$destination+'.part';$client=New-Object Net.WebClient
 $oldTLS=[Net.ServicePointManager]::SecurityProtocol
 try {
  [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
  RM-Message ('Downloading from official source: '+$url)
  $task=$client.DownloadFileTaskAsync([Uri]$url,$part)
  while(!$task.IsCompleted){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 200}
  if($task.IsFaulted){throw $task.Exception.GetBaseException()};if($task.IsCanceled){throw 'Download cancelled.'}
  Move-Item -LiteralPath $part -Destination $destination -Force
 } finally {$client.Dispose();[Net.ServicePointManager]::SecurityProtocol=$oldTLS;if(Test-Path -LiteralPath $part){Remove-Item -LiteralPath $part -Force}}
}
function RM-InstallWireshark {
 $found=RM-FindWireshark;if($found){RM-Message ('tshark already available: '+$found);return $true}
 if($script:setupBusy){RM-Message 'Another setup is in progress.';return $false}
 if($script:captureOwned){RM-Message 'Stop packet capture before installing dependencies.';return $false}
 if(!(RM-IsAdmin)){throw 'Restart this utility as Administrator for dependency installation.'}
 $script:setupBusy=$true
 try {
  $arch=RM-Architecture
  $file='Wireshark-4.6.9-'+$arch+'.exe'
  $manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'tools\manifest.json') -Raw | ConvertFrom-Json
  $entry=@($manifest.files | Where-Object {$_.file -eq $file})[0]
  if(!$entry){throw 'Installer manifest entry missing.'}
  Start-Process notepad.exe -ArgumentList ('"'+(Join-Path $PSScriptRoot 'tools\Wireshark-COPYING.txt')+'"')
  if([Windows.Forms.MessageBox]::Show("Wireshark/tshark is not installed. The license has opened in Notepad. Accept its terms and authorize installation with default components in silent mode? Npcap is not installed in silent mode and is not required for this utility's Pktmon/file-analysis workflow. Existing Wireshark installations are not automatically upgraded. If the bundled file is missing, it will be downloaded from the official URL.",'Install Wireshark / tshark?','YesNo','Information') -ne 'Yes'){return $false}
  $path=Join-Path $PSScriptRoot ('tools\'+$file)
  if(!(Test-Path -LiteralPath $path -PathType Leaf)){$path=Join-Path $root ('tools-cache\'+$file);RM-Download $entry.url $path}
  RM-VerifyBinary $path 'Wireshark Foundation' $entry.sha256
  RM-Message 'Installing official Wireshark/tshark silently with default components. Please wait; monitoring can continue. Npcap is not installed.'
  $p=Start-Process -FilePath $path -ArgumentList '/S' -PassThru
  while(!$p.HasExited){[Windows.Forms.Application]::DoEvents();Start-Sleep -Milliseconds 200;$p.Refresh()}
  $code=$p.ExitCode;$p.Dispose();$found=RM-FindWireshark
  if(!$found){RM-Message ('tshark not detected. Installer exit code: '+$code+'. Install the TShark component or place it in PATH.');return $false}
  RM-Message ('Ready: '+$found);return $true
 } finally {$script:setupBusy=$false}
}
function RM-InstallSysmon {
 $services=@(Get-Service -Name 'Sysmon','Sysmon64','Sysmon64a' -ErrorAction SilentlyContinue)
 if($services.Count){RM-Message 'Sysmon already installed. Existing policy is preserved; use Check Sysmon and review events 1/3/22.';return $true}
 if($script:setupBusy){RM-Message 'Another setup is in progress.';return $false}
 if($script:captureOwned){RM-Message 'Stop packet capture before installing dependencies.';return $false}
 if(!(RM-IsAdmin)){throw 'Restart this utility as Administrator for Sysmon installation.'}
 if([Windows.Forms.MessageBox]::Show("Sysmon is not installed. Download it directly from Microsoft, review/accept the Microsoft Sysinternals EULA, and install with this utility's template? This creates a persistent system service and logs ALL system process creation, network and DNS events, not only the selected EXE. Logs may contain sensitive data and consume disk. No existing policy is replaced. Internet is required for this official download.",'Download and install Sysmon?','YesNo','Warning') -ne 'Yes'){return $false}
 $script:setupBusy=$true
 try {
  $dir=Join-Path $root 'tools-cache\Sysmon';$zip=Join-Path $root 'tools-cache\Sysmon.zip'
  RM-Download 'https://download.sysinternals.com/files/Sysmon.zip' $zip
  Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
  $name=if((RM-Architecture) -eq 'arm64'){'Sysmon64a.exe'}else{'Sysmon64.exe'}
  $exe=Join-Path $dir $name;RM-VerifyBinary $exe 'Microsoft Corporation'
  $eula=Join-Path $dir 'Eula.txt';if(!(Test-Path -LiteralPath $eula)){throw 'Microsoft license file missing.'}
  Start-Process notepad.exe -ArgumentList ('"'+$eula+'"')
  if([Windows.Forms.MessageBox]::Show('The actual Microsoft EULA has opened in Notepad. Have you read and accepted it, and do you authorize installation with system-wide event logging? No cancels installation.','Accept Microsoft EULA?','YesNo','Warning') -ne 'Yes'){return $false}
  $old=$ErrorActionPreference
  try{$ErrorActionPreference='Continue';$output=& $exe -accepteula -i (Join-Path $PSScriptRoot 'Sysmon-config.xml') 2>&1 | Out-String;$code=$LASTEXITCODE}finally{$ErrorActionPreference=$old}
  if($code -ne 0){throw ('Sysmon installation failed: '+$output)}
  RM-Message ('Sysmon installed. Stop/Start monitoring to enable reading its events. '+$output);return $true
 } finally {$script:setupBusy=$false}
}
