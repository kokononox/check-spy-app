import os,sys,time,json,threading,pathlib,base64,datetime
from analyze import summarize
ROOT=pathlib.Path(__file__).resolve().parent

def save(events,out,status='Stopped',error=None):
    safe,private=summarize(events)
    safe['CollectorStatus']=status
    if error:safe['ErrorClass']=error
    out.mkdir(parents=True,exist_ok=True)
    (out/'Report-to-share.json').write_text(json.dumps(safe,indent=2,ensure_ascii=False),encoding='utf-8')
    (out/'PRIVATE-requests.json').write_text(json.dumps(private,indent=2,ensure_ascii=False),encoding='utf-8')
    lines=['PRIVATE: Do not upload this file without reviewing URLs and payloads.','API acceptance does not prove receipt by the server.','Stage labels are your manual markers.','']
    for r in private:
        lines.extend([f"Request {r['id']}: {r.get('method') or '?'} {r.get('url') or '[URL unavailable]'}",f"Stage: {r.get('stage')} | Source: {r.get('urlSource')}",f"Captured body: {len(base64.b64decode(r['bodyBase64']))} bytes",''])
    (out/'PRIVATE-URLs.txt').write_text('\n'.join(lines),encoding='utf-8')
    return safe

class Recorder:
    def __init__(self,out):
        self.events=[];self.start=time.monotonic();self.stage='before_login';self.lock=threading.Lock();self.detached=False
        out.mkdir(parents=True,exist_ok=True);self.raw=(out/'PRIVATE-events.jsonl').open('w',encoding='utf-8');self.output=out
    def on_message(self,message,data):
        if message.get('type')=='send':e=dict(message['payload'])
        else:e={'type':'script_error','errorClass':'InstrumentationScriptError','privateDetail':message.get('description','')}
        with self.lock:
            e['stage']=self.stage;e['elapsedSeconds']=round(time.monotonic()-self.start,3);e['timeUtc']=datetime.datetime.now(datetime.timezone.utc).isoformat()
            if data:e['dataBase64']=base64.b64encode(data).decode('ascii')
            self.events.append(e);self.raw.write(json.dumps(e,ensure_ascii=False)+'\n');self.raw.flush()
        if e.get('type')=='hook_installed':print('  Hook available:',e.get('module'),e.get('api'),flush=True)
        elif e.get('type')=='request_attempt':print('  Request API observed (URL saved privately).',flush=True)
        elif e.get('type')=='plaintext':print('  Plaintext input observed:',e.get('api'),e.get('capturedBytes'),'bytes',flush=True)
    def on_detached(self,*args):self.detached=True
    def close(self):self.raw.close()

def attach_capture(device,pid,rec):
    session=device.attach(pid);session.on('detached',rec.on_detached)
    try:
        script=session.create_script((ROOT/'capture.js').read_text(encoding='utf-8'));script.on('message',rec.on_message);script.load()
        return session,script
    except Exception:
        session.detach();raise

def main():
    if sys.platform!='win32' or sys.maxsize<2**32:print('Windows x64 is required.');return 2
    print('PRE-TLS REQUEST CAPTURE 1.0 - EXPERIMENTAL\n')
    print('WARNING: Frida attaches and temporarily instruments the selected process.')
    print('This may crash it or conflict with anti-cheat / game rules. Account sanctions cannot be ruled out.')
    print('Use only where instrumentation is allowed. Do not continue on a protected/live account if unsure.')
    print('PRIVATE outputs may contain passwords, tokens, cookies, URLs and system data.')
    print('No uploads, no TLS validation changes, no privilege escalation, no anti-cheat bypass.\n')
    if input('Type YES to accept and continue; anything else exits: ').strip()!='YES':return 0
    try:import frida
    except Exception as e:print('Bundled runtime failed:',type(e).__name__);return 2
    stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S');out=ROOT/'Results'/stamp
    rec=Recorder(out);session=None;script=None;status='Stopped';error=None
    try:
        device=frida.get_local_device();processes=[p for p in device.enumerate_processes() if p.pid!=os.getpid() and p.pid>4]
        processes.sort(key=lambda p:(not any(s in p.name.lower() for s in ('myapp','wow','warcraft')),p.name.lower(),p.pid))
        print('\nSelect the GAME process, not this tool or its launcher:')
        for n,p in enumerate(processes,1):print(f'{n:3d}. {p.name} (PID {p.pid})')
        i=int(input('\nEnter its list number (0 cancels): ').strip())
        if i==0:rec.close();return 0
        if not 1<=i<=len(processes):raise ValueError('Invalid selection')
        target=processes[i-1]
        if input('Attach to '+target.name+'? Type YES: ').strip()!='YES':rec.close();return 0
        session,script=attach_capture(device,target.pid,rec)
        print('\nCapturing for up to 120 seconds FROM NOW, not from process startup.')
        print('Keep the game at login first. Press 2 when starting login; 3 after login; Q to finish.')
        print('Stage markers do not detect login automatically. A missing hook/data is not success.\n')
        import msvcrt
        end=time.monotonic()+120
        while time.monotonic()<end and not rec.detached:
            if msvcrt.kbhit():
                key=msvcrt.getwch().lower()
                if key=='q':break
                if key in ('1','2','3'):
                    rec.stage={'1':'before_login','2':'login_started','3':'after_login'}[key];print('Stage:',rec.stage)
            time.sleep(.1)
        if rec.detached:status='TargetDetachedOrExited'
    except KeyboardInterrupt:status='UserStopped'
    except Exception as e:
        error=type(e).__name__;status='AttachOrCaptureFailed';print('\nCapture stopped:',error)
        (out/'PRIVATE-error.txt').write_text(str(e),encoding='utf-8')
        print('Do not bypass protections or retry with guessed code addresses.')
    finally:
        if script:
            try:script.unload()
            except Exception:pass
        if session:
            try:session.detach()
            except Exception:pass
        rec.close();safe=save(rec.events,out,status,error)
    print('\nSaved to:',out)
    print('Result:',safe['Status'],'| plaintext buffers:',safe['PlaintextBufferEvents'],'| parsed requests:',safe['ParsedRequestRecords'])
    print('Send ONLY Report-to-share.json. Keep every PRIVATE-* file on your own computer.')
    print('Full captured URLs: PRIVATE-URLs.txt; raw bodies: PRIVATE-requests.json.')
    return 0 if error is None else 1

if __name__=='__main__':sys.exit(main())
