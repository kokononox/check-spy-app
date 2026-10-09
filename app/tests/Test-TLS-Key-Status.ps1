$ErrorActionPreference='Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'TLS-Key-Status.ps1')
$dir=Join-Path ([IO.Path]::GetTempPath()) ('RM22-key-test-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $dir | Out-Null
try {
 $p=Join-Path $dir 'synthetic.log'
 $s=Get-RMTLSKeyStatus $p;if($s.FileExists -or $s.ValidEntries){throw 'Absent-file test failed'}
 [IO.File]::WriteAllText($p,'');$s=Get-RMTLSKeyStatus $p;if(!$s.FileExists -or $s.ValidEntries){throw 'Empty-file test failed'}
 [IO.File]::WriteAllText($p,'not a key file');$s=Get-RMTLSKeyStatus $p;if($s.ValidEntries){throw 'Wrong-format test failed'}
 # Synthetic placeholders, not secrets from any real TLS session.
 $random='a'*64;$secret='b'*96
 [IO.File]::WriteAllText($p,"# synthetic fixture`nCLIENT_RANDOM $random $secret`nCLIENT_TRAFFIC_SECRET_0 $random $secret`n")
 $s=Get-RMTLSKeyStatus $p;if($s.ValidEntries -ne 2 -or $s.ClientRandoms.Count -ne 1){throw 'Valid-format test failed'}
 if(($s | Select-Object -ExcludeProperty ClientRandoms | ConvertTo-Json) -match $secret){throw 'Secret appeared in diagnostic result'}
 Write-Host 'PASS: no-file, empty-file, non-key-file, supported synthetic records and secret-free diagnostics.'
} finally {Remove-Item -LiteralPath $dir -Recurse -Force}
