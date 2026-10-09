# Use OS pipes directly. Native stderr never enters PowerShell's error pipeline.
if(-not ('RMNativeIO231' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
public static class RMNativeIO231 {
 public static string Quote(string value) {
  if(value==null)value="";var b=new StringBuilder();b.Append('"');int slashes=0;
  foreach(char c in value) {
   if(c=='\\'){slashes++;continue;}
   if(c=='"'){b.Append('\\',slashes*2+1);b.Append('"');slashes=0;continue;}
   b.Append('\\',slashes);slashes=0;b.Append(c);
  }
  b.Append('\\',slashes*2);b.Append('"');return b.ToString();
 }
 public static int Run(string executable,string[] args,string stdoutPath,string stderrPath) {
  var pieces=new string[args.Length];for(int i=0;i<args.Length;i++)pieces[i]=Quote(args[i]);
  var info=new ProcessStartInfo(executable,String.Join(" ",pieces));info.UseShellExecute=false;info.CreateNoWindow=true;
  info.RedirectStandardOutput=true;info.RedirectStandardError=true;
  using(var p=new Process())using(var output=File.Create(stdoutPath))using(var error=File.Create(stderrPath)) {
   p.StartInfo=info;p.Start();
   Task a=p.StandardOutput.BaseStream.CopyToAsync(output),b=p.StandardError.BaseStream.CopyToAsync(error);
   p.WaitForExit();Task.WaitAll(a,b);output.Flush();error.Flush();return p.ExitCode;
  }
 }
}
'@
}
function Invoke-RMNativeTool([string]$Executable,[string[]]$Arguments,[string]$StdoutPath,[string]$StderrPath) {
 # .ps1 is used only by the synthetic test fixture; actual tshark.exe runs directly.
 if([IO.Path]::GetExtension($Executable) -eq '.ps1'){
  $hostPath=[Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
  $Arguments=@('-NoLogo','-NoProfile','-ExecutionPolicy','Bypass','-File',$Executable)+$Arguments;$Executable=$hostPath
 }
 return [RMNativeIO231]::Run($Executable,$Arguments,$StdoutPath,$StderrPath)
}
