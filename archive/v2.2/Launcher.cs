using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;
internal static class Launcher {
 [STAThread] static void Main() {
  try {
   string path=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"Monitor.ps1");
   if(!File.Exists(path))throw new FileNotFoundException("Keep Monitor.ps1 beside ExeRouteMonitor.exe.");
   string ps=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),@"WindowsPowerShell\v1.0\powershell.exe");
   var info=new ProcessStartInfo(ps,"-NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File \""+path+"\"");
   info.UseShellExecute=false;
   info.CreateNoWindow=true;
   info.WorkingDirectory=AppDomain.CurrentDomain.BaseDirectory;
   Process.Start(info);
  } catch(Exception e){MessageBox.Show(e.Message,"Exe Route Monitor",MessageBoxButtons.OK,MessageBoxIcon.Error);}
 }
}
