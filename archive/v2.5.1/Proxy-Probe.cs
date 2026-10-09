using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;

public sealed class RMProxyEvent25 {
 public string TimeUTC, Host, Method, Outcome;
 public int Port, ClientPID;
 public long BytesToServer, BytesFromServer;
}
public sealed class RMProxyProbe25 : IDisposable {
 TcpListener listener; volatile bool running; Thread acceptThread;
 ConcurrentDictionary<int,TcpClient> sockets=new ConcurrentDictionary<int,TcpClient>();
 ConcurrentDictionary<int,Task> tasks=new ConcurrentDictionary<int,Task>();
 ConcurrentQueue<RMProxyEvent25> events=new ConcurrentQueue<RMProxyEvent25>();
 SemaphoreSlim slots=new SemaphoreSlim(32,32); int nextID, eventCount;
 string target; public int ListenPort {get;private set;}
 public int RejectedOtherProcesses, PIDLookupFailures, OverloadRejections, MetadataLimitRejections;
 // Test-only injection is used by offline QA, never set by production scripts.
 public Func<int,int> TestPIDResolver=null;
 public bool TestAllowLoopback=false;
 [DllImport("iphlpapi.dll",SetLastError=true)] static extern uint GetExtendedTcpTable(IntPtr buf,ref int size,bool order,int family,int tableClass,uint reserved);
 static int NetPort(int value){return ((value&255)<<8)|((value>>8)&255);}
 int FindPID(int sourcePort){
  int size=0;GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0);
  if(size<=0||size>16777216)return 0;
  IntPtr b=Marshal.AllocHGlobal(size);
  try {if(GetExtendedTcpTable(b,ref size,false,2,5,0)!=0)return 0;
   int n=Marshal.ReadInt32(b);if(n<0||n>(size-4)/24)return 0;
   for(int i=0;i<n;i++) {int o=4+i*24;
    if(NetPort(Marshal.ReadInt32(b,o+8))==sourcePort&&NetPort(Marshal.ReadInt32(b,o+16))==ListenPort&&Marshal.ReadInt32(b,o+12)==0x0100007f)return Marshal.ReadInt32(b,o+20);
   }return 0;
  } finally{Marshal.FreeHGlobal(b);}
 }
 int Attribute(int port){
  if(TestPIDResolver!=null)return TestPIDResolver(port);
  int pid=0;try{for(int i=0;i<4;i++){pid=FindPID(port);if(pid!=0)break;Thread.Sleep(50);}if(pid==0){Interlocked.Increment(ref PIDLookupFailures);return -1;}
   using(Process p=Process.GetProcessById(pid)) {string path=p.MainModule.FileName;return String.Equals(Path.GetFullPath(path),target,StringComparison.OrdinalIgnoreCase)?pid:0;}
  }catch{Interlocked.Increment(ref PIDLookupFailures);return -1;}
 }
 public void Start(string exePath){if(running)throw new InvalidOperationException("Already started");target=Path.GetFullPath(exePath);listener=new TcpListener(IPAddress.Loopback,0);listener.Start(32);ListenPort=((IPEndPoint)listener.LocalEndpoint).Port;running=true;acceptThread=new Thread(Accept);acceptThread.IsBackground=true;acceptThread.Start();}
 void Accept(){while(running){TcpClient c=null;try {c=listener.AcceptTcpClient();if(!running){c.Close();break;}if(!slots.Wait(0)){Interlocked.Increment(ref OverloadRejections);c.Close();continue;}
   int id=Interlocked.Increment(ref nextID);sockets[id]=c;TcpClient owned=c;
   Task t=Task.Factory.StartNew(()=>{try{Handle(owned);}finally{TcpClient ignored;sockets.TryRemove(id,out ignored);owned.Close();slots.Release();}},TaskCreationOptions.LongRunning);tasks[id]=t;
   // Bound task bookkeeping too.
   foreach(var pair in tasks){if(pair.Value.IsCompleted){Task ignored;tasks.TryRemove(pair.Key,out ignored);}}
  }catch{if(c!=null)c.Close();if(running)Thread.Sleep(50);}}
 }
 static void Reply(NetworkStream s,int code,string reason){byte[] b=Encoding.ASCII.GetBytes("HTTP/1.1 "+code+" "+reason+"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");s.Write(b,0,b.Length);}
 static byte[] Header(NetworkStream s){using(var m=new MemoryStream()){int last=0;while(m.Length<32768){int b=s.ReadByte();if(b<0)throw new IOException("Incomplete header");m.WriteByte((byte)b);last=(last<<8)|b;if(m.Length>=4&&last==0x0d0a0d0a)return m.ToArray();}throw new IOException("Header limit");}}
 static bool PublicIP(IPAddress a){if(IPAddress.IsLoopback(a))return false;if(a.AddressFamily==AddressFamily.InterNetwork){byte[] b=a.GetAddressBytes();return b[0]!=0&&b[0]!=10&&b[0]!=127&&b[0]<224&&!(b[0]==169&&b[1]==254)&&!(b[0]==172&&b[1]>=16&&b[1]<=31)&&!(b[0]==192&&b[1]==168)&&!(b[0]==100&&b[1]>=64&&b[1]<=127);}if(a.IsIPv4MappedToIPv6)return PublicIP(a.MapToIPv4());byte[] v=a.GetAddressBytes();return !a.Equals(IPAddress.IPv6Any)&&!a.IsIPv6LinkLocal&&!a.IsIPv6Multicast&&!(v[0]>=0xfc&&v[0]<=0xfd);}
 public static string[] ParseRequestLine(string line){
  string[] p=line.Split(' ');if(p.Length!=3||(p[2]!="HTTP/1.1"&&p[2]!="HTTP/1.0"))throw new IOException("Request line");
  Uri u;if(p[0]=="CONNECT"){if(p[1].IndexOfAny(new char[]{'/','?','#','@','\\'})>=0)throw new IOException("CONNECT authority");if(!Uri.TryCreate("https://"+p[1],UriKind.Absolute,out u))throw new IOException("CONNECT URI");}
  else {if(Array.IndexOf(new string[]{"GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"},p[0])<0||!Uri.TryCreate(p[1],UriKind.Absolute,out u)||u.Scheme!="http")throw new IOException("Only absolute HTTP or CONNECT");}
  if(u.UserInfo.Length!=0||u.Host.Length==0||u.Host.Length>253)throw new IOException("Host limit");
  int port=u.Port;if(port!=80&&port!=443&&port!=1119)throw new IOException("Port not allowed");
  return new string[]{p[0],u.DnsSafeHost,port.ToString(),p[0]=="CONNECT"?"":u.PathAndQuery,p[2]};
 }
 void Handle(TcpClient client){
  RMProxyEvent25 e=null;TcpClient upstream=null;int upID=0;
  try{
   int pid=Attribute(((IPEndPoint)client.Client.RemoteEndPoint).Port);
   if(pid<=0){if(pid==0)Interlocked.Increment(ref RejectedOtherProcesses);return;}
   if(Interlocked.Increment(ref eventCount)>2048){Interlocked.Increment(ref MetadataLimitRejections);return;}
   e=new RMProxyEvent25 {TimeUTC=DateTime.UtcNow.ToString("o"),ClientPID=pid,Host="",Outcome="Request not parsed"};events.Enqueue(e);
   client.ReceiveTimeout=15000;client.SendTimeout=15000;NetworkStream input=client.GetStream();byte[] h=Header(input);string header=Encoding.ASCII.GetString(h);int cr=header.IndexOf("\r\n");string[] p=ParseRequestLine(header.Substring(0,cr));e.Method=p[0];e.Host=p[1];e.Port=Int32.Parse(p[2]);
   Task<IPAddress[]> dns=Dns.GetHostAddressesAsync(e.Host);if(!dns.Wait(5000))throw new IOException("DNS timeout");IPAddress address=null;
   foreach(IPAddress a in dns.Result){if(PublicIP(a)||(TestAllowLoopback&&IPAddress.IsLoopback(a))){address=a;break;}}
   if(address==null){e.Outcome="Blocked nonpublic destination";Reply(input,403,"Forbidden");return;}
   if(!running)throw new IOException("Stopped");upstream=new TcpClient(address.AddressFamily);upID=Interlocked.Increment(ref nextID);sockets[upID]=upstream;
   Task connect=upstream.ConnectAsync(address,e.Port);if(!connect.Wait(8000))throw new IOException("Connect timeout");if(!running)throw new IOException("Stopped");
   NetworkStream output=upstream.GetStream();upstream.SendTimeout=15000;e.Outcome="Relay established (content not inspected)";
   if(e.Method=="CONNECT"){byte[] ok=Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");input.Write(ok,0,ok.Length);}
   else {
    // Forward headers in memory, excluding proxy credentials. Never retain headers, path or body.
    StringBuilder rewritten=new StringBuilder(e.Method+" "+p[3]+" "+p[4]+"\r\n");string[] lines=header.Substring(cr+2).Split(new string[]{"\r\n"},StringSplitOptions.None);
    foreach(string line in lines){if(line.Length==0)continue;if(line.StartsWith("Proxy-Authorization:",StringComparison.OrdinalIgnoreCase)||line.StartsWith("Proxy-Connection:",StringComparison.OrdinalIgnoreCase)||line.StartsWith("Connection:",StringComparison.OrdinalIgnoreCase))continue;rewritten.Append(line).Append("\r\n");}
    rewritten.Append("Connection: close\r\n\r\n");byte[] wire=Encoding.ASCII.GetBytes(rewritten.ToString());output.Write(wire,0,wire.Length);Interlocked.Add(ref e.BytesToServer,wire.Length);
   }
   client.ReceiveTimeout=0;Task aPump=Pump(input,output,e,true,upstream);Task bPump=Pump(output,input,e,false,client);Task.WaitAll(aPump,bPump);
  }catch {if(e!=null&&running&&e.Outcome=="Request not parsed")e.Outcome="Request/DNS/connect failed";else if(e!=null&&running&&e.Outcome=="Relay established (content not inspected)")e.Outcome="Relay established; ended or interrupted";}
  finally{if(upstream!=null)upstream.Close();if(upID!=0){TcpClient ignored;sockets.TryRemove(upID,out ignored);}}
 }
 static async Task Pump(NetworkStream source,NetworkStream dest,RMProxyEvent25 e,bool outbound,TcpClient receiver){
  byte[] buffer=new byte[16384];try{int n;while((n=await source.ReadAsync(buffer,0,buffer.Length).ConfigureAwait(false))>0){await dest.WriteAsync(buffer,0,n).ConfigureAwait(false);if(outbound)Interlocked.Add(ref e.BytesToServer,n);else Interlocked.Add(ref e.BytesFromServer,n);}}catch{}finally{try{receiver.Client.Shutdown(SocketShutdown.Send);}catch{}}
 }
 public RMProxyEvent25[] Snapshot(){return events.ToArray();}
 public int PendingTasks {get{int count=0;foreach(Task t in tasks.Values)if(!t.IsCompleted)count++;return count;}}
 public void Stop(){running=false;if(listener!=null)listener.Stop();foreach(TcpClient c in sockets.Values){try{c.Close();}catch{}}if(acceptThread!=null)acceptThread.Join(1000);Task[] pending=new List<Task>(tasks.Values).ToArray();try{Task.WaitAll(pending,2000);}catch{}}
 public void Dispose(){Stop();}
}
