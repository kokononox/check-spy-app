#requires -Version 5.1
# Detect the observed Pktmon raw 802.11/LLC framing issue, never rewrite original evidence.
if(-not ('RM22Capture' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
public class RM22CaptureResult {
 public string OriginalPath; public string EffectivePath; public bool Changed;
 public long PacketCount; public long ConvertedPackets; public string Reason;
}
public static class RM22Capture {
 private class Info { public ushort Link; public long Count; public long Wifi; }
 private static uint U32(byte[] b,int o) { return BitConverter.ToUInt32(b,o); }
 private static int A4(int n) { return (n+3)&~3; }
 private static byte[] Block(BinaryReader r) {
  byte[] head=r.ReadBytes(8); if(head.Length==0)return null;
  if(head.Length!=8)throw new InvalidDataException("Truncated PCAPNG header");
  uint n=U32(head,4); if(n<12 || n>16*1024*1024 || (n&3)!=0)throw new InvalidDataException("Unsupported block size/endian");
  byte[] tail=r.ReadBytes((int)n-8);if(tail.Length!=n-8)throw new InvalidDataException("Truncated PCAPNG block");
  byte[] b=new byte[n];Buffer.BlockCopy(head,0,b,0,8);Buffer.BlockCopy(tail,0,b,8,tail.Length);
  if(U32(b,b.Length-4)!=n)throw new InvalidDataException("Invalid PCAPNG block trailer");return b;
 }
 private static bool Wifi(byte[] b,int cap) {
  int s=28; if(cap<52 || b[s]!=8 || (b[s+1]&3)==3)return false;
  byte[] llc={0xaa,0xaa,3,0,0,0};for(int i=0;i<6;i++)if(b[s+24+i]!=llc[i])return false;
  ushort proto=(ushort)((b[s+30]<<8)|b[s+31]);int ver=b[s+32]>>4;
  return (proto==0x0800 && ver==4 && (b[s+32]&15)>=5) || (proto==0x86dd && ver==6) || (proto==0x0806 && cap>=60);
 }
 public static RM22CaptureResult Normalize(string input) {
  string full=Path.GetFullPath(input);var result=new RM22CaptureResult {OriginalPath=full,EffectivePath=full,Reason="No normalization needed"};
  var infos=new List<Info>();int sections=0;
  using(var r=new BinaryReader(File.OpenRead(full))) {
   if(r.BaseStream.Length<12){result.Reason="No PCAPNG header; left unchanged for tshark";return result;}
   if(r.ReadUInt32()!=0x0a0d0d0a){result.Reason="Not PCAPNG; left unchanged for tshark";return result;}r.BaseStream.Position=0;
   byte[] b;
   while((b=Block(r))!=null) {
    uint t=U32(b,0);
    if(t==0x0a0d0d0a) {
     sections++;if(sections>1){result.Reason="Multiple sections: normalization not supported; original retained";return result;}
     if(U32(b,8)!=0x1a2b3c4d){result.Reason="Big-endian PCAPNG not normalized";return result;}
    } else if(t==1){if(b.Length<20)throw new InvalidDataException("Invalid interface block");infos.Add(new Info{Link=BitConverter.ToUInt16(b,8)});}
    else if(t==6) {
     if(b.Length<32)throw new InvalidDataException("Invalid packet block");uint idx=U32(b,8);uint cap=U32(b,20);
     if(idx>=infos.Count || cap>16*1024*1024 || 28L+A4((int)cap)+4>b.Length)throw new InvalidDataException("Invalid packet lengths/interface");
     var info=infos[(int)idx];info.Count++;result.PacketCount++;
     if((info.Link==1 || info.Link==105) && Wifi(b,(int)cap))info.Wifi++;
    } else if(t==2 || t==3){result.Reason="Legacy/simple packet blocks: not normalized";return result;}
   }
  }
  var targets=new HashSet<int>();for(int i=0;i<infos.Count;i++)if(infos[i].Count>0 && infos[i].Wifi==infos[i].Count)targets.Add(i);
  if(targets.Count==0){result.Reason="No uniformly matching raw 802.11 interfaces; original retained";return result;}
  string output=full+".normalized.pcapng",temp=output+".tmp-"+Guid.NewGuid().ToString("N");
  try {
   using(var r=new BinaryReader(File.OpenRead(full)))using(var w=new BinaryWriter(File.Create(temp))) {
    int iface=-1;byte[] b;
    while((b=Block(r))!=null) {
     uint t=U32(b,0);
     if(t==1){iface++;if(targets.Contains(iface)){b[8]=1;b[9]=0;}}
     else if(t==6 && targets.Contains((int)U32(b,8))) {
      int cap=(int)U32(b,20),orig=(int)U32(b,24);int ds=b[29]&3;
      int dest=ds==1?44:32,source=ds==2?44:38; // packet offset28 + 802.11 addr offsets16/4/10
      int nc=cap-18;int optsStart=28+A4(cap),optsLen=b.Length-4-optsStart;int total=28+A4(nc)+optsLen+4;
      byte[] n=new byte[total];Buffer.BlockCopy(b,0,n,0,28);
      Buffer.BlockCopy(BitConverter.GetBytes((uint)total),0,n,4,4);
      Buffer.BlockCopy(BitConverter.GetBytes((uint)nc),0,n,20,4);
      Buffer.BlockCopy(BitConverter.GetBytes((uint)Math.Max(nc,orig-18)),0,n,24,4);
      Buffer.BlockCopy(b,dest,n,28,6);Buffer.BlockCopy(b,source,n,34,6);Buffer.BlockCopy(b,58,n,40,cap-30);
      Buffer.BlockCopy(b,optsStart,n,28+A4(nc),optsLen);Buffer.BlockCopy(BitConverter.GetBytes((uint)total),0,n,total-4,4);
      b=n;result.ConvertedPackets++;
     }
     w.Write(b);
    }
   }
   if(File.Exists(output))File.Delete(output);File.Move(temp,output);
  } catch {if(File.Exists(temp))File.Delete(temp);throw;}
  result.Changed=true;result.EffectivePath=output;result.Reason="Uniform raw 802.11 + LLC/SNAP converted to Ethernet in a derived copy. Network payload, packet order, timestamps and packet options retained; original untouched.";
  return result;
 }
}
'@
}
function Convert-RMCapture([string]$Path){return [RM22Capture]::Normalize($Path)}
