#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$LogPath,[switch]$SavePrivateBodies)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Debugger-Core.ps1')
$file=Get-Item -LiteralPath $LogPath
if($file.Length -gt 8388608){throw 'Log exceeds 8 MiB'}
. (Join-Path $PSScriptRoot 'Diagnostic-Core.ps1')
$text=Read-RMLiveLog $file.FullName
$diagnostics=Get-RMDiagnostics $text
$endEvidence=Get-RMEndEvidence $file.DirectoryName
$parsed=Read-RMCdbData $text
$http=Get-RMHttpCandidates $parsed.Records
$folder=Join-Path $file.DirectoryName 'local-results';[void][IO.Directory]::CreateDirectory($folder)
$private=@();$index=0
foreach($r in $http.Candidates){
 $index++;$bodyFile=$null
 if($SavePrivateBodies -and $r.Body.Length){$bodyFile=('body-'+$index+'.bin');[IO.File]::WriteAllBytes((Join-Path $folder $bodyFile),$r.Body)}
 $private+=[pscustomobject]@{Index=$index;Method=$r.Method;URL=$r.URL;URLSource=$r.URLSource;DeclaredBodyBytes=$r.DeclaredBodyBytes;BodyCoverage=$r.BodyCoverage;PrivateBodyFile=$bodyFile;Warning=$r.Warning}
}
ConvertTo-Json -InputObject @($private) -Depth 6|Set-Content -LiteralPath (Join-Path $folder 'PRIVATE-URL-candidates.json') -Encoding UTF8
$safe=[pscustomobject]@{Version='0.4-startup-gated-experimental';DebuggerDiagnostics=$diagnostics;EndEvidence=$endEvidence;ParsedDataBuffers=$parsed.Records.Count;ParseErrors=$parsed.ParseErrors;CandidateHTTP1Requests=$http.Candidates.Count;UnsupportedHTTP2Streams=$http.UnsupportedHTTP2Streams;StoppedAtLimit=$parsed.LimitStopped;PartialStreams=@($http.Candidates|Where-Object {$_.StreamGap}).Count;URLsExported=$false;HeaderValuesExported=$false;BodiesExported=$false;Assessment='Candidates observed at generic SSPI EncryptMessage entry; no Schannel-context verification or successful send established.'}
$safe|Add-Member -NotePropertyName CaptureOutcome -NotePropertyValue $(if($parsed.Records.Count){'DataObservedNotProofOfSend'}elseif($diagnostics.ContinuationAfterFaultObserved){'NoDataObservedContinuationAfterFault'}elseif($diagnostics.InitialWaiting -and !$diagnostics.InitialContinueAllowed){'NoDataObservedInitialGateBlocked'}elseif($diagnostics.ExceptionPausePossible){'NoDataObservedExceptionPausePossible'}elseif($diagnostics.DebuggerCommandErrorObserved){'NoDataObservedDebuggerCommandError'}elseif(!$diagnostics.ObserverInitialized){'NoDataObservedInitializationUnconfirmed'}else{'NoDataObservedCauseNotEstablished'})
$safe|ConvertTo-Json -Depth 6|Set-Content -LiteralPath (Join-Path $folder 'Report-to-share.json') -Encoding UTF8
Write-Host 'Read complete. Review PRIVATE-URL-candidates.json locally. Share only Report-to-share.json.'
