[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$TargetPath,[Parameter(Mandatory=$true)][string]$OutputPath,[string]$SelectedLogPath)
$ErrorActionPreference='Stop'
if(!(Test-Path -LiteralPath $TargetPath -PathType Leaf) -or [IO.Path]::GetExtension($TargetPath) -ine '.exe'){throw 'Choose an existing EXE.'}
# No target execution, configuration changes, certificate installation, or external requests.
if(-not ('RMDiagnostic24' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;
public static class RMDiagnostic24 {
 static uint U32(byte[] b,int o){if(o<0||o>b.Length-4)throw new InvalidDataException("PE bounds");return BitConverter.ToUInt32(b,o);}
 static ushort U16(byte[] b,int o){if(o<0||o>b.Length-2)throw new InvalidDataException("PE bounds");return BitConverter.ToUInt16(b,o);}
 static int Map(byte[] b,uint r,int sections,int n,uint headers){if(r<headers&&r<b.Length)return (int)r;for(int i=0;i<n;i++){int s=sections+i*40;uint va=U32(b,s+12),raw=U32(b,s+20),len=U32(b,s+16);if(r>=va&&(ulong)r-va<len){ulong o=(ulong)raw+r-va;if(o<(ulong)b.Length)return (int)o;}}throw new InvalidDataException("Unmapped RVA");}
 public static string[] Imports(byte[] b){if(b.Length<64||b[0]!=77||b[1]!=90)throw new InvalidDataException("Not PE");int p=checked((int)U32(b,60));if(U32(b,p)!=0x4550)throw new InvalidDataException("Not PE");int n=U16(b,p+6),opt=p+24,sz=U16(b,p+20),magic=U16(b,opt);if(n>96)throw new InvalidDataException("Sections limit");int dd=magic==0x10b?96:magic==0x20b?112:0;if(dd==0||sz<dd+16)throw new InvalidDataException("Unsupported optional header");if(U32(b,opt+dd-4)<2)return new string[0];uint r=U32(b,opt+dd+8),length=U32(b,opt+dd+12);if(r==0)return new string[0];uint headers=U32(b,opt+60);var names=new List<string>();for(int i=0;i<Math.Min(512,length/20);i++){int d=Map(b,checked(r+(uint)i*20),opt+sz,n,headers);uint name=U32(b,d+12);if(name==0)break;int o=Map(b,name,opt+sz,n,headers),j=o;while(j<b.Length&&j-o<260&&b[j]!=0)j++;if(j==b.Length||j-o==260)throw new InvalidDataException("Import name bounds");string s=Encoding.ASCII.GetString(b,o,j-o).ToLowerInvariant();if(!names.Contains(s))names.Add(s);}return names.ToArray();}
 public static string[] Markers(byte[] b,string[] terms){string a=Encoding.ASCII.GetString(b);var found=new List<string>();foreach(string t in terms){byte[] wide=Encoding.Unicode.GetBytes(t);string w=Encoding.ASCII.GetString(wide);if(a.IndexOf(t,StringComparison.OrdinalIgnoreCase)>=0||a.IndexOf(w,StringComparison.OrdinalIgnoreCase)>=0)found.Add(t);}return found.ToArray();}
 public static string[] ReadImports(string path){return Imports(File.ReadAllBytes(path));}
}
'@
}
$info=Get-Item -LiteralPath $TargetPath
if($info.Length -gt 256MB){throw 'EXE is larger than the 256 MB diagnostic limit.'}
$bytes=[IO.File]::ReadAllBytes($info.FullName)
$imports=@();$peError=$false
try{$imports=@([RMDiagnostic24]::Imports($bytes))}catch{$peError=$true}
$terms=@('SSLKEYLOGFILE','SSL_CTX_set_keylog_callback','SSL_set_keylog_callback','CLIENT_RANDOM','libssl','OpenSSL','BoringSSL','libcurl','WinHttp','InternetOpen','Schannel','telemetry','diagnostic','logging')
$markers=@([RMDiagnostic24]::Markers($bytes,[string[]]$terms));$bytes=$null
$signature='Not checked (no online certificate validation)'
$dir=$info.DirectoryName;$inventory=@();$inventoryTruncated=$false
$folders=@([pscustomobject]@{Path=$dir;Label='Target folder'},[pscustomobject]@{Path=(Join-Path $dir 'Logs');Label='Logs subfolder'},[pscustomobject]@{Path=(Join-Path $dir 'Diagnostics');Label='Diagnostics subfolder'})
$errors=0
foreach($folder in $folders){if(!(Test-Path -LiteralPath $folder.Path -PathType Container)){continue};try {
 $items=@(Get-ChildItem -LiteralPath $folder.Path -File -Filter '*.log' -ErrorAction Stop | Select-Object -First 201)
 if($items.Count -gt 200){$inventoryTruncated=$true}
 foreach($item in ($items|Select-Object -First 200)) {$inventory+=[ordered]@{Location=$folder.Label;Index=$inventory.Count+1;SizeBytes=$item.Length;LastWriteUTC=$item.LastWriteTimeUtc.ToString('o')}}
}catch{$errors++}}
$logSummary=$null
if($SelectedLogPath){
 $log=Get-Item -LiteralPath $SelectedLogPath -ErrorAction Stop
 if($log.PSIsContainer -or $log.Extension -notin @('.log','.txt')){throw 'Select a .log or .txt file.'}
 if($log.Length -gt 16MB){throw 'Selected log exceeds the 16 MB safety limit.'}
 $text=[IO.File]::ReadAllText($log.FullName)
 # Only predeclared names and their counts leave this function. Never raw values, lines, or URLs.
 $fields=[ordered]@{};foreach($term in @('telemetry','diagnostic','upload','send','http','https','username','computername','hostname','machineid','deviceid','hardware','cpu','gpu','memory','osversion','authorization','cookie','access_token')){
  $fields[$term]=[regex]::Matches($text,'(?i)(?<![a-z0-9_])'+[regex]::Escape($term)+'(?![a-z0-9_])').Count
 }
 $logSummary=[ordered]@{SizeBytes=$log.Length;FieldNameOccurrenceCounts=$fields;Assessment='Word occurrences only; no values retained. Not proof of transmission, absence, or a supported logging mode.'};$text=$null
}
$report=[ordered]@{
 Version='2.4';ReportKind='ReadOnlyTargetDiagnostics';GeneratedUTC=[datetime]::UtcNow.ToString('o');Target=$info.Name;TargetSHA256=(Get-FileHash -LiteralPath $info.FullName -Algorithm SHA256).Hash;TargetSizeBytes=$info.Length;FileVersion=$info.VersionInfo.FileVersion;SignatureStatus=$signature
 PEImportInspectionFailed=$peError;RecognizedNetworkImports=@($imports|Where-Object {$_ -match '^(winhttp|wininet|secur32|sspicli|crypt32|ws2_32|wldap32|libssl[^\\/]*|libcrypto[^\\/]*|libcurl[^\\/]*)\.dll$'})
 StaticMarkerNames=$markers;LogInventory=$inventory;LogInventoryTruncated=$inventoryTruncated;LogInventoryReadErrors=$errors;SelectedLogSummary=$logSummary
 SupportAssessment='Static clues only. Presence does not prove a feature is active or supported; absence does not rule out dynamic or bundled TLS libraries. No new logging options were enabled.'
 PrivacyAssessment='No target execution, network request, process memory access, certificate installation or settings changes. Log inventory is metadata only. Optional selected log inspection returns only allowlisted word counts, not contents.'
 Limits=@('Only the selected EXE is scanned; imported DLL contents and running modules are not inspected.','Log inventory checks .log files in target folder, Logs, and Diagnostics only; no recursive or system-wide search.','Optional log scan searches literal allowlisted words; different encodings, languages, spelling, or field names may be missed.','Does not decrypt traffic or establish which data was transmitted.','Report reveals target hash, version and activity timestamps; review before sharing.')
}
$parent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($OutputPath));[void][IO.Directory]::CreateDirectory($parent)
$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $OutputPath -Encoding UTF8
Write-Output $OutputPath
