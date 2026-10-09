# Builds a local .NET Framework GUI launcher. It runs Monitor.ps1 alongside it.
$ErrorActionPreference='Stop'
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if(!(Test-Path $compiler)){throw 'The Windows .NET Framework C# compiler was not found. Use Start.cmd instead.'}
$src=Join-Path $PSScriptRoot 'Launcher.cs'
$out=Join-Path $PSScriptRoot 'ExeRouteMonitor.exe'
& $compiler /nologo /target:winexe /platform:x64 /reference:System.Windows.Forms.dll "/out:$out" $src
if($LASTEXITCODE -ne 0){throw 'Build failed.'}
Write-Host "Built: $out"
Write-Host 'Keep Monitor.ps1 alongside the EXE. Use Run as administrator for best coverage.'
