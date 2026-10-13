'use strict';
// Observes exported APIs only. No RVA guessing, interception replacement, or TLS validation changes.
const MAX_BUFFER = 65536, MAX_TOTAL = 20 * 1024 * 1024;
let bytesSent = 0, sequence = 0;
const installed = new Set(), connections = new Map(), requests = new Map();
function emit(type, fields, data) { send(Object.assign({type, sequence: ++sequence}, fields || {}), data || null); }
function text(p, wide) {
  if (p.isNull()) return null;
  let chars=[];
  try {
    for(let i=0;i<4096;i++) { const v=wide?p.add(i*2).readU16():p.add(i).readU8();if(v===0)break;chars.push(v); }
    if(wide)return String.fromCharCode.apply(null,chars);
    // Hostnames/verbs/URL strings are overwhelmingly ASCII; preserve bytes otherwise.
    return String.fromCharCode.apply(null,chars);
  } catch (_) { return null; }
}
function buffer(p, length, fields) {
  if (p.isNull() || length <= 0) return;
  const n = Math.min(length, MAX_BUFFER, MAX_TOTAL - bytesSent);
  if (n <= 0) return;
  try {
    const data = p.readByteArray(n); bytesSent += n;
    emit('plaintext', Object.assign({originalBytes:length, capturedBytes:n, truncated:n<length}, fields), data);
  } catch (_) { emit('read_unavailable', {api:fields.api}); }
}
function hook(m, name, callbacks) {
  let address; try { address = m.findExportByName(name); } catch (_) { return; }
  if (address === null) return;
  const k=address.toString() + ':' + name;
  if (installed.has(k)) return;
  try { Interceptor.attach(address, callbacks); installed.add(k); emit('hook_installed', {module:m.name, api:name}); }
  catch (e) { emit('hook_unavailable', {module:m.name, api:name}); }
}
function scan(m) {
  const lower=m.name.toLowerCase();
  if (lower==='winhttp.dll') {
    hook(m,'WinHttpConnect',{
      onEnter(a){this.host=text(a[1],true);this.port=a[2].toUInt32()&65535;},
      onLeave(r){if(!r.isNull())connections.set(r.toString(),{host:this.host,port:this.port});}
    });
    hook(m,'WinHttpOpenRequest',{
      onEnter(a){this.parent=a[0].toString();this.method=text(a[1],true)||'GET';this.path=text(a[2],true)||'/';this.secure=(a[6].toUInt32()&0x800000)!==0;},
      onLeave(r){
        if(r.isNull())return;
        const c=connections.get(this.parent);let url=null;
        if(c && c.host){const h=c.host.includes(':')&&!c.host.startsWith('[')?'['+c.host+']':c.host;const standard=this.secure?443:80;url=(this.secure?'https':'http')+'://'+h+(c.port===standard?'':':'+c.port)+this.path;}
        requests.set(r.toString(),{method:this.method,url,path:this.path,secure:this.secure});
      }
    });
    hook(m,'WinHttpSendRequest',{
      onEnter(a){this.id='winhttp-'+(++sequence);this.handle=a[0].toString();const r=requests.get(this.handle)||{};emit('request_attempt',Object.assign({api:'WinHttpSendRequest',callId:this.id,requestHandle:this.handle,urlSource:'WinHTTP construction; redirects not tracked'},r));buffer(a[3],a[4].toUInt32(),Object.assign({api:'WinHttpSendRequest',callId:this.id,requestHandle:this.handle},r));},
      onLeave(r){emit('call_result',{api:'WinHttpSendRequest',callId:this.id,accepted:r.toInt32()!==0,evidence:'API return only, not server receipt'});}
    });
    hook(m,'WinHttpWriteData',{
      onEnter(a){this.id='write-'+(++sequence);const r=requests.get(a[0].toString())||{};buffer(a[1],a[2].toUInt32(),Object.assign({api:'WinHttpWriteData',callId:this.id,requestHandle:a[0].toString()},r));},
      onLeave(r){emit('call_result',{api:'WinHttpWriteData',callId:this.id,accepted:r.toInt32()!==0,evidence:'API return only, not server receipt'});}
    });
    hook(m,'WinHttpCloseHandle',{onEnter(a){connections.delete(a[0].toString());requests.delete(a[0].toString());}});
  }
  // Export names, not embedded strings, establish candidate hook addresses.
  if (/ssl|crypto|curl|libhttp|wow_loader|myapp|battlenet/.test(lower) || m.enumerateExports().some(e=>e.name==='SSL_write')) {
    hook(m,'SSL_write',{
      onEnter(a){this.id='ssl-'+(++sequence);this.module=m.name;this.length=a[2].toInt32();buffer(a[1],this.length,{api:'SSL_write',module:m.name,callId:this.id,stream:a[0].toString(),layer:'TLS input'});},
      onLeave(r){emit('call_result',{api:'SSL_write',callId:this.id,accepted:r.toInt32()>0,acceptedBytes:Math.max(0,r.toInt32()),evidence:'TLS API return only, not server receipt'});}
    });
    hook(m,'SSL_write_ex',{
      onEnter(a){this.id='sslex-'+(++sequence);const n=Number(a[2].toString());buffer(a[1],Number.isSafeInteger(n)?n:0,{api:'SSL_write_ex',module:m.name,callId:this.id,stream:a[0].toString(),layer:'TLS input'});},
      onLeave(r){emit('call_result',{api:'SSL_write_ex',callId:this.id,accepted:r.toInt32()===1,evidence:'TLS API return only, not server receipt'});}
    });
  }
  if(lower==='secur32.dll'||lower==='sspicli.dll') {
    hook(m,'EncryptMessage',{
      onEnter(a){
        this.id='sspi-'+(++sequence);
        try {
          const desc=a[2], count=desc.add(4).readU32();const list=desc.add(8).readPointer();
          if(count>64)return;
          for(let i=0;i<count;i++){const entry=list.add(i*(Process.pointerSize===8?16:12));const n=entry.readU32(), type=entry.add(4).readU32()&0x0fffffff;
            if(type===1)buffer(entry.add(8).readPointer(),n,{api:'EncryptMessage',module:m.name,callId:this.id,stream:a[0].toString(),layer:'SSPI data input; TLS backend not established'});
          }
        }catch(_){emit('read_unavailable',{api:'EncryptMessage'});}
      },
      onLeave(r){emit('call_result',{api:'EncryptMessage',callId:this.id,accepted:r.toInt32()===0,evidence:'SSPI API return only, not server receipt'});}
    });
  }
}
Process.attachModuleObserver({onAdded(m){try{scan(m);}catch(_){emit('module_scan_unavailable',{module:m.name});}}});
emit('ready',{exportedApisOnly:true,bufferLimit:MAX_BUFFER,totalLimit:MAX_TOTAL});
