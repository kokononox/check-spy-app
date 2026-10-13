# Only official vendor download + owned loopback fixtures. Never run a user's game.
$ErrorActionPreference='Stop'
if($env:OS -ne 'Windows_NT'){throw 'Windows integration runner required.'}
if(!$env:RUNNER_TEMP){throw 'This launcher is restricted to a GitHub hosted integration runner.'}
$work=Join-Path $env:RUNNER_TEMP ('owned-tls-vendor-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($work)
try {
 $archive=Join-Path $work 'official-vendor.zip';$exe=Join-Path $work 'mitmdump.exe'
 $client=New-Object Net.WebClient
 try {$client.DownloadFile('https://downloads.mitmproxy.org/12.2.3/mitmproxy-12.2.3-windows-x86_64.zip',$archive)} finally {$client.Dispose()}
 if((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne '04A01EA95AE96DF75058A893E774957D294E69012DAB1F4E256CE2B0C6725483'){throw 'Official vendor archive hash mismatch.'}
 Add-Type -AssemblyName System.IO.Compression.FileSystem
 $zip=[IO.Compression.ZipFile]::OpenRead($archive)
 try {
  $entry=$zip.GetEntry('mitmdump.exe');if(!$entry){throw 'Vendor EXE missing from archive.'}
  [IO.Compression.ZipFileExtensions]::ExtractToFile($entry,$exe,$false)
 } finally {$zip.Dispose()}
 if((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne '36A45AADEB842185B8064B8F0BE3730E079C9F9C125BC8BE22363332969857BF'){throw 'Official vendor EXE hash mismatch.'}
 $output=Join-Path $PSScriptRoot 'out/windows-tls-integration-safe.json'
 & python (Join-Path $PSScriptRoot 'test_windows_tls_integration.py') --mitmdump $exe --output $output
 if($LASTEXITCODE -ne 0){throw 'Owned Windows TLS integration test failed.'}
} finally {
 # Fixture helper already closes its own child proxy and servers. Do not terminate unrelated processes.
 if(Test-Path -LiteralPath $work){Remove-Item -LiteralPath $work -Recurse -Force}
}
