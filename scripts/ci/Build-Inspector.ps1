#requires -Version 5.1
param(
 [string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
 [string]$OutputDirectory = ''
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
if(!$OutputDirectory){$OutputDirectory = Join-Path $root '.ci-artifacts'}
$source = Join-Path $root 'tools/etw-field-inspector-v2.6.5'
# Only source/docs and synthetic tests are packaged. Never enumerate captures, reports or app/tools binaries.
$allowed = @(
 'ETW-Field-Core.ps1','WebTrace-Core.ps1','Inspect-ETW-Fields.ps1','Inspect-ETW-Fields.cmd',
 'START-HERE-fa.md','QA.md','LICENSE.txt',
 'tests/Test-ETW-Field-Core.ps1','tests/parse-results.txt','tests/test-results.txt'
)
$manifest = @{}
foreach($line in Get-Content -LiteralPath (Join-Path $source 'SHA256SUMS.txt')){
 if($line -notmatch '^([0-9a-fA-F]{64})  (.+)$'){throw 'Invalid source checksum manifest'}
 $manifest[$matches[2]] = $matches[1].ToLowerInvariant()
}
foreach($relative in $allowed){
 $file = Join-Path $source $relative
 if(!(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing package source: $relative"}
 $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
 if(!$manifest.ContainsKey($relative) -or $manifest[$relative] -ne $hash){
  throw "Reviewed source checksum mismatch: $relative"
 }
}
[void][IO.Directory]::CreateDirectory($OutputDirectory)
$staging = Join-Path ([IO.Path]::GetTempPath()) ('rm-ci-package-'+[guid]::NewGuid().ToString('N'))
$package = Join-Path $staging 'ExeRouteMonitor-ETW-Inspector-v2.6.5'
try{
 foreach($relative in $allowed + @('SHA256SUMS.txt')){
  $dest = Join-Path $package $relative
  [void][IO.Directory]::CreateDirectory((Split-Path -Parent $dest))
  Copy-Item -LiteralPath (Join-Path $source $relative) -Destination $dest
 }
 $zip = Join-Path $OutputDirectory 'ExeRouteMonitor-ETW-Inspector-v2.6.5.zip'
 Compress-Archive -LiteralPath $package -DestinationPath $zip -Force
 $checksum = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
 [IO.File]::WriteAllText((Join-Path $OutputDirectory 'SHA256SUMS.txt'),$checksum+'  '+[IO.Path]::GetFileName($zip)+[Environment]::NewLine,[Text.Encoding]::ASCII)
 Write-Host 'Built inspector source ZIP and SHA-256. Not a compiled EXE or game payload recorder.'
}finally{
 if(Test-Path -LiteralPath $staging){Remove-Item -LiteralPath $staging -Recurse -Force}
}