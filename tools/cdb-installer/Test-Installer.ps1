$ErrorActionPreference='Stop'
$source=[IO.File]::ReadAllText((Join-Path $PSScriptRoot 'Install-CDB-x64.cmd'),[Text.Encoding]::UTF8)
$marker='#PS_PAYLOAD_START';$payload=$source.Substring($source.LastIndexOf($marker)+$marker.Length)
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($payload,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Installer payload parse failed'}
if($payload -notmatch '/features OptionId.WindowsDesktopDebuggers /passive /norestart'){throw 'Only-debuggers selection absent'}
$folder=Join-Path $env:TEMP ('cdb-installer-check-'+[guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($folder)
try{
 $path=Join-Path $folder 'winsdksetup.exe'
 Invoke-WebRequest 'https://go.microsoft.com/fwlink/?linkid=2382321' -OutFile $path -UseBasicParsing -TimeoutSec 180
 if((Get-FileHash $path -Algorithm SHA256).Hash -ne 'B0BDBAD38AE74C40CCAE8CDBCF229807627FBA2BC3100BE28301C4BA884F755E'){throw 'Official bootstrapper hash mismatch'}
 $s=Get-AuthenticodeSignature -LiteralPath $path
 if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw 'Official Microsoft Authenticode verification failed'}
 $function=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Test-MicrosoftX64Cdb'},$true)
 . ([scriptblock]::Create($function.Extent.Text))
 $cdb=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Debuggers\x64\cdb.exe'
 if(!(Test-MicrosoftX64Cdb $cdb)){throw 'CI existing CDB verifier failed'}
 if(Test-MicrosoftX64Cdb $path){throw 'Installer EXE incorrectly accepted as CDB'}
 Write-Host 'PASS: payload parse, official download hash/signature, installed CDB PE/signature checks. No installer executed; end-user install not tested.'
}finally{Remove-Item $folder -Recurse -Force -ErrorAction SilentlyContinue}
