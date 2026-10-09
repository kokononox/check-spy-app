# Does not install or run vendor binaries. Checks bundled hashes/signatures on Windows.
$ErrorActionPreference='Stop'
$manifest=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'tools\manifest.json') -Raw | ConvertFrom-Json
foreach($e in $manifest.files){
 $p=Join-Path $PSScriptRoot ('tools\'+$e.file)
 if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $e.sha256){throw ('Hash mismatch: '+$e.file)}
 Write-Host ('PASS SHA256: '+$e.file)
 if($e.file -like '*.exe'){
  $s=Get-AuthenticodeSignature -LiteralPath $p
  if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch 'O=Wireshark Foundation'){throw ('Signature check failed: '+$e.file)}
  Write-Host ('PASS Authenticode: '+$e.file)
 }
}
