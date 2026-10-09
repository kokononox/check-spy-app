function Set-ProxyStartupStatus([string]$phase,[string]$message='') {
 if(!$script:ProxyStartupPath){return}
 $safe=$message -replace '(?i)[A-Z]:\\[^\r\n"]+','[local path]'
 if($safe.Length -gt 1800){$safe=$safe.Substring(0,1800)}
 $data=[ordered]@{Version='2.5.1';Phase=$phase;Message=$safe;UTC=[datetime]::UtcNow.ToString('o')}
 $temp=$script:ProxyStartupPath+'.tmp'
 $data|ConvertTo-Json|Set-Content -LiteralPath $temp -Encoding UTF8
 Move-Item -LiteralPath $temp -Destination $script:ProxyStartupPath -Force
}
