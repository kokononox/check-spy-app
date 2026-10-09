$ErrorActionPreference='Stop';$bad=$false
Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -Recurse | ForEach-Object {
 $tokens=$null;$errors=$null
 [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
 if($errors.Count){$bad=$true;$errors | ForEach-Object {Write-Host ($_.Extent.File+':'+$_.Extent.StartLineNumber+' '+$_.Message)}}else{Write-Host ('PASS: '+$_.Name)}
}
if($bad){exit 1}
