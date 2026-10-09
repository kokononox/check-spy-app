$ErrorActionPreference='Stop'
 $qaCode=@'
public static class RMProxyQA25 {
 static void Assert(bool ok,string why){if(!ok)throw new Exception(why);}
 static string Header(NetworkStream n){var b=new StringBuilder();while(b.Length<32768){int v=n.ReadByte();if(v<0)break;b.Append((char)v);if(b.ToString().EndsWith("\r\n\r\n"))break;}return b.ToString();}
 public static void Run(){
  string[] parsed=RMProxyProbe25.ParseRequestLine("CONNECT example.com:443 HTTP/1.1");Assert(parsed[1]=="example.com"&&parsed[2]=="443","CONNECT parse");
  parsed=RMProxyProbe25.ParseRequestLine("GET http://example.com/a?token=PRIVATE HTTP/1.1");Assert(parsed[3]=="/a?token=PRIVATE","HTTP target preservation");
  foreach(string bad in new string[]{"CONNECT user@host:443 HTTP/1.1","CONNECT host:443/path HTTP/1.1","CONNECT host:22 HTTP/1.1","GET https://host/path HTTP/1.1","GET /path HTTP/1.1"}){bool failed=false;try{RMProxyProbe25.ParseRequestLine(bad);}catch{failed=true;}Assert(failed,"Malformed parser rejection");}
  var server=new TcpListener(IPAddress.Loopback,443);server.Start();
  var echo=Task.Run(()=>{using(TcpClient c=server.AcceptTcpClient()){var s=c.GetStream();byte[] b=new byte[1024];int n=s.Read(b,0,b.Length);s.Write(b,0,n);}});
  var proxy=new RMProxyProbe25();proxy.TestPIDResolver=(port)=>123;proxy.TestAllowLoopback=true;proxy.Start("/data/qa/v25/target.exe");int listener=proxy.ListenPort;
  using(var c=new TcpClient()){c.Connect(IPAddress.Loopback,listener);c.ReceiveTimeout=5000;var n=c.GetStream();byte[] connect=Encoding.ASCII.GetBytes("CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n");n.Write(connect,0,connect.Length);Assert(Header(n).StartsWith("HTTP/1.1 200"),"Tunnel established");byte[] secret=Encoding.ASCII.GetBytes("PRIVATE_PAYLOAD_SENTINEL");n.Write(secret,0,secret.Length);byte[] recv=new byte[secret.Length];int length=0;while(length<recv.Length){int count=n.Read(recv,length,recv.Length-length);if(count==0)break;length+=count;}Assert(Encoding.ASCII.GetString(recv)=="PRIVATE_PAYLOAD_SENTINEL","Tunnel byte identity");}
  Assert(echo.Wait(5000),"Echo complete");proxy.Stop();server.Stop();var ev=proxy.Snapshot();Assert(ev.Length==1&&ev[0].BytesToServer==24&&ev[0].BytesFromServer==24,"Bidirectional byte counts");Assert(ev[0].Host=="127.0.0.1"&&ev[0].Method=="CONNECT","Metadata only");proxy.Dispose();
  // Actual TLS passthrough, using an ephemeral sandbox-only origin certificate; no trust store writes.
  using(var rsa=System.Security.Cryptography.RSA.Create(2048)){
   var request=new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=localhost",rsa,System.Security.Cryptography.HashAlgorithmName.SHA256,System.Security.Cryptography.RSASignaturePadding.Pkcs1);
   using(var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1),DateTimeOffset.UtcNow.AddHours(1))){
    var origin=new TcpListener(IPAddress.Loopback,443);origin.Start();
    var originTask=Task.Run(()=>{using(var c=origin.AcceptTcpClient())using(var tls=new System.Net.Security.SslStream(c.GetStream(),false)){tls.AuthenticateAsServer(cert,false,System.Security.Authentication.SslProtocols.Tls12,false);byte[] b=new byte[64];int n=tls.Read(b,0,b.Length);tls.Write(b,0,n);}});
    var tunnel=new RMProxyProbe25();tunnel.TestPIDResolver=(port)=>123;tunnel.TestAllowLoopback=true;tunnel.Start("/data/qa/v25/target.exe");
    using(var c=new TcpClient()){c.Connect(IPAddress.Loopback,tunnel.ListenPort);c.ReceiveTimeout=5000;byte[] connect=Encoding.ASCII.GetBytes("CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n");c.GetStream().Write(connect,0,connect.Length);Assert(Header(c.GetStream()).StartsWith("HTTP/1.1 200"),"TLS tunnel CONNECT");
     using(var tls=new System.Net.Security.SslStream(c.GetStream(),false,(sender,presented,chain,errors)=>presented!=null&&String.Equals(presented.GetCertHashString(),cert.GetCertHashString(),StringComparison.OrdinalIgnoreCase))){
      tls.AuthenticateAsClient("localhost",null,System.Security.Authentication.SslProtocols.Tls12,false);byte[] message=Encoding.ASCII.GetBytes("TLS_PRIVATE_TEST_MESSAGE");tls.Write(message,0,message.Length);byte[] recv=new byte[message.Length];int n=0;while(n<recv.Length){int count=tls.Read(recv,n,recv.Length-n);if(count==0)break;n+=count;}Assert(Encoding.ASCII.GetString(recv)=="TLS_PRIVATE_TEST_MESSAGE","Actual TLS payload passthrough");Assert(tls.RemoteCertificate.GetCertHashString()==cert.GetCertHashString(),"Origin certificate unchanged");}
    }
    Assert(originTask.Wait(5000),"TLS origin complete");tunnel.Stop();origin.Stop();Assert(tunnel.Snapshot()[0].BytesToServer>24&&tunnel.Snapshot()[0].BytesFromServer>24,"Encrypted wire counts");tunnel.Dispose();
   }
  }
  var blocked=new RMProxyProbe25();blocked.TestPIDResolver=(port)=>123;blocked.Start("/data/qa/v25/target.exe");using(var c=new TcpClient()){c.Connect(IPAddress.Loopback,blocked.ListenPort);c.ReceiveTimeout=5000;byte[] q=Encoding.ASCII.GetBytes("CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n");c.GetStream().Write(q,0,q.Length);Assert(Header(c.GetStream()).StartsWith("HTTP/1.1 403"),"Production private destination blocked");}blocked.Dispose();
  var denied=new RMProxyProbe25();denied.TestPIDResolver=(port)=>0;denied.Start("/data/qa/v25/target.exe");using(var c=new TcpClient()){c.Connect(IPAddress.Loopback,denied.ListenPort);c.ReceiveTimeout=5000;Assert(c.GetStream().ReadByte()==-1,"Unrelated process closed");}denied.Dispose();Assert(denied.RejectedOtherProcesses==1&&denied.Snapshot().Length==0,"No unrelated process logging");
  var pending=new RMProxyProbe25();pending.TestPIDResolver=(port)=>123;pending.Start("/data/qa/v25/target.exe");using(var c=new TcpClient()){c.Connect(IPAddress.Loopback,pending.ListenPort);Thread.Sleep(100);pending.Stop();Assert(pending.PendingTasks==0,"Stop pending header socket");}pending.Dispose();
  var httpServer=new TcpListener(IPAddress.Loopback,80);httpServer.Start();string received=null;
  var httpTask=Task.Run(()=>{using(var c=httpServer.AcceptTcpClient()){var stream=c.GetStream();received=Header(stream);byte[] response=Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nOK");stream.Write(response,0,response.Length);}});
  var httpProxy=new RMProxyProbe25();httpProxy.TestPIDResolver=(port)=>123;httpProxy.TestAllowLoopback=true;httpProxy.Start("/data/qa/v25/target.exe");
  using(var c=new TcpClient()){c.Connect(IPAddress.Loopback,httpProxy.ListenPort);c.ReceiveTimeout=5000;byte[] q=Encoding.ASCII.GetBytes("GET http://127.0.0.1/secret?token=PRIVATE HTTP/1.1\r\nHost: 127.0.0.1\r\nProxy-Authorization: PRIVATE_CREDENTIAL\r\n\r\n");var stream=c.GetStream();stream.Write(q,0,q.Length);Assert(Header(stream).StartsWith("HTTP/1.1 200"),"HTTP relay");Assert(stream.ReadByte()==79&&stream.ReadByte()==75,"HTTP body unchanged");}
  Assert(httpTask.Wait(5000),"HTTP task complete");httpProxy.Stop();httpServer.Stop();Assert(received.StartsWith("GET /secret?token=PRIVATE HTTP/1.1"),"Absolute URI rewritten");Assert(!received.Contains("PRIVATE_CREDENTIAL"),"Proxy credentials removed");var httpEvent=httpProxy.Snapshot()[0];Assert(httpEvent.Host=="127.0.0.1"&&!httpEvent.Outcome.Contains("PRIVATE"),"HTTP metadata excludes path and secrets");httpProxy.Dispose();
 }
}
'@
Add-Type -TypeDefinition ((Get-Content ../app/Proxy-Probe.cs -Raw)+[Environment]::NewLine+$qaCode)
[RMProxyQA25]::Run()
'PASS: request parsing, CONNECT byte identity, byte counters, private destination blocking, unrelated process rejection, cleanup, HTTP relay, credential removal, metadata privacy, actual TLS passthrough with unchanged origin certificate'
