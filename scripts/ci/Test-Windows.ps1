#requires -Version 5.1
param([string]$RepositoryRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)))
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$parseFailures = 0
$count = 0
foreach($folder in @('app','tools/etw-field-inspector-v2.6.5','scripts/ci')){
 foreach($file in Get-ChildItem -LiteralPath (Join-Path $root $folder) -Filter '*.ps1' -Recurse){
  $tokens = $null; $errors = $null; $count++
  [void][Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors)
  if($errors.Count){$parseFailures++; Write-Host ('FAIL syntax: '+$file.Name)}
 }
}
if($parseFailures){throw "Syntax check failed: $parseFailures file(s)"}
Write-Host "PASS: parsed $count scripts"
# Explicit synthetic-test allowlist. Do not run UI, trace, target launch, proxy or CA scripts.
$tests = @(
 'app/tests/Test-Analyzer.ps1',
 'app/tests/Test-Bidirectional.ps1',
 'app/tests/Test-Local-Audit.ps1',
 'app/tests/Test-TLS-Key-Status.ps1',
 'tools/etw-field-inspector-v2.6.5/tests/Test-ETW-Field-Core.ps1'
)
$hostPath = [Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
foreach($test in $tests){
 Write-Host ('Running synthetic test: '+$test)
 & $hostPath -NoLogo -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root $test)
 if($LASTEXITCODE -ne 0){throw "Synthetic test failed: $test"}
}
Write-Host ('PASS: synthetic suite on '+$PSVersionTable.PSVersion.ToString())
Write-Host 'Not tested: target/game execution, real ETL, interactive UI, full HTTPS URL/body recovery.'