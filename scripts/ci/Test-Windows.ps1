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
  if($errors.Count){
   $parseFailures++
   foreach($error in $errors){
    $message = $error.Message.Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A')
    Write-Host ('::error title=PowerShell syntax '+$file.Name+'::Line '+$error.Extent.StartLineNumber+': '+$message)
   }
  }
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
. (Join-Path $root 'app/Native-Tool-IO.ps1')
foreach($test in $tests){
 Write-Host ('Running synthetic test: '+$test)
 $temp = Join-Path ([IO.Path]::GetTempPath()) ('rm-ci-test-'+[guid]::NewGuid().ToString('N'))
 [void][IO.Directory]::CreateDirectory($temp)
 try{
  $stdout = Join-Path $temp 'stdout.txt'; $stderr = Join-Path $temp 'stderr.txt'
  $exitCode = Invoke-RMNativeTool $hostPath @('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',(Join-Path $root $test)) $stdout $stderr
  Get-Content -LiteralPath $stdout | ForEach-Object {Write-Host $_}
  if($exitCode -ne 0){
   $message = ((Get-Content -LiteralPath $stderr | Select-Object -First 16) -join ' ').Replace('%','%25').Replace("`r",'%0D').Replace("`n",'%0A')
   Write-Host ('::error title=Synthetic test '+$test+'::'+$message)
   throw "Synthetic test failed: $test"
  }
 }finally{if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force}}
}
Write-Host ('PASS: synthetic suite on '+$PSVersionTable.PSVersion.ToString())
Write-Host 'Not tested: target/game execution, real ETL, interactive UI, full HTTPS URL/body recovery.'