# No key material is returned or printed. Only format/count/availability diagnostics.
function Get-RMTLSKeyStatus([string]$Path) {
 $s=[ordered]@{FileExists=$false;FileBytes=0;ValidEntries=0;ClientRandoms=@{};Assessment='No key file selected'}
 if(!$Path){return [pscustomobject]$s}
 if(!(Test-Path -LiteralPath $Path -PathType Leaf)){$s.Assessment='Requested key file was not created/found';return [pscustomobject]$s}
 $f=Get-Item -LiteralPath $Path;$s.FileExists=$true;$s.FileBytes=$f.Length
 if($f.Length -gt 33554432){$s.Assessment='Key file exceeds 32 MiB diagnostic limit';return [pscustomobject]$s}
 try{$stream=New-Object IO.FileStream($f.FullName,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite);$r=New-Object IO.StreamReader($stream)}catch{$s.Assessment='Key file exists but cannot be read now; retry after the target finishes writing';return [pscustomobject]$s}
 try {
  while(($line=$r.ReadLine()) -ne $null) {
   if($line -match '^\s*(CLIENT_RANDOM|(?:CLIENT|SERVER)_(?:EARLY_|HANDSHAKE_)?TRAFFIC_SECRET(?:_\d+)?|(?:EARLY_)?EXPORTER_SECRET)\s+([0-9A-Fa-f]{64})\s+([0-9A-Fa-f]{32,})\s*$') {
    if($matches[3].Length%2 -eq 0){$s.ValidEntries++;$s.ClientRandoms[$matches[2].ToLowerInvariant()]=$true}
   }
  }
 } finally {$r.Dispose()}
 $s.Assessment=if($s.ValidEntries){'Supported key-log records found; matching and decryption still need verification'}elseif(!$s.FileBytes){'Key file is empty; no TLS key logging established'}else{'No supported key-log records; wrong format, unsupported logging, or non-key file'}
 return [pscustomobject]$s
}
