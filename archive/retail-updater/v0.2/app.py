import json, queue, threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox
import stage_core as core

BASE=Path(__file__).resolve().parent
root=tk.Tk();root.title('WoW Retail EU — Staging Test 0.2');root.geometry('720x480')
events=queue.Queue();cancel=threading.Event();busy=False;local=None;target=None;entry=None;blobs=None
intro='دریافت آزمایشی یک فایل — این برنامه نصب بازی را آپدیت نمی‌کند.'
tk.Label(root,text=intro,font=('Arial',13),wraplength=690).pack(pady=12)
tk.Label(root,text='EU Retail / Windows x64 — No administrator access needed').pack()
output=tk.Text(root,wrap='word',height=16);output.pack(padx=15,pady=12,expand=True,fill='both')
def show(text): output.delete('1.0','end');output.insert('end',text)
def state(value):
    global busy
    busy=value;check.config(state='disabled' if value else 'normal');stop.config(state='normal' if value else 'disabled')
def launch(fn):
    state(True);cancel.clear()
    def worker():
        try: fn()
        except core.StageError as exc: events.put(('error',str(exc)))
        except Exception as exc: events.put(('error',type(exc).__name__+' — operation failed; no update was applied.'))
    threading.Thread(target=worker,daemon=True).start()
def inspect():
    global local
    name=filedialog.askopenfilename(title='Select the installed game .build.info',filetypes=[('Build info','.build.info'),('All files','*')])
    if not name:return
    try:
        local=core.local_info(name)
        if BASE.is_relative_to(local['installation']):
            raise core.StageError('Extract the program outside the game installation.')
    except Exception: messagebox.showerror('Cannot continue','Select an active Windows x64 EU Retail .build.info and extract this program OUTSIDE the game installation.');return
    show('Checking the official EU build and install manifest…\nNo game files are being changed.')
    def work():
        t=core.discover()
        if cancel.is_set(): raise core.StageError('Cancelled. No game files changed.')
        e,config,manifest=core.sample_plan(t)
        if cancel.is_set(): raise core.StageError('Cancelled. No game files changed.')
        events.put(('plan',(t,e,config,manifest)))
    launch(work)
def stage():
    destination=filedialog.askdirectory(title='Choose staging folder OUTSIDE the game installation')
    if not destination:return
    try: run=core.stage_directory(destination,local['installation'])
    except core.StageError as exc: messagebox.showerror('Unsafe location',str(exc));return
    def work():
        report={'tool':'WoW Retail EU Staging 0.2','mode':'single_file_staging_no_install_update','product':'wow','region':'eu','local_version':local['version'],'target_version':target['version'],'target_build_config':target['build'],'target_cdn_config':target['cdn'],'installed_files_changed':False,'installed_integrity_verified':False,'sample_executed':False,'source':core.META+'versions','tacttool_release':'0.2.0-alpha1','status':'started'}
        def save(): (run/'Retail-Staging-to-share.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        save()
        try:
            (run/'build.config').write_bytes(blobs[0]);(run/'install.decoded').write_bytes(blobs[1])
            pin=json.loads((BASE/'vendor/tool-integrity.json').read_text())
            result=core.extract(BASE/'vendor/TACTTool.exe',run,target,entry,cancel,lambda s:events.put(('progress',s)),pin['sha256'])
            report.update(status='sample_downloaded_and_content_verified',sample=result);save()
            events.put(('done',run))
        except core.StageError as exc:
            report.update(status='failed_or_cancelled',error=str(exc));save();events.put(('error',str(exc)+'\nReport is in the staging folder.'))
        except Exception as exc:
            report.update(status='failed',error_type=type(exc).__name__);save();events.put(('error',type(exc).__name__+' — Report is in the staging folder.'))
    show('TACTTool is downloading metadata and one sample.\nThis can take several minutes; no percentage estimate is available.\nNo game installation changes.\nOutput: '+str(run)+'\n\nDo NOT run or copy candidate-Wow.exe into the game.')
    launch(work)
def poll():
    global target,entry,blobs
    try:
        while True:
            kind,data=events.get_nowait()
            if kind=='plan':
                target,entry,config,manifest=data;blobs=(config,manifest);state(False)
                if cancel.is_set():
                    show('Cancelled. No game files changed.')
                    continue
                show('Installed: '+local['version']+'\nPublished EU: '+target['version']+'\n\nSample: Wow.exe (EU Windows x64)\nSample size: '+str(round(entry['size']/1024**2,1))+' MiB\n\nThis is ONE FILE, not a complete update. Metadata may add hundreds of MB or more.\n2 GiB free space required. The upstream tool is an alpha release.\nFile content will be checked against the official install manifest.')
                if messagebox.askyesno('Staging test only','Download metadata and one Wow.exe sample into a separate folder?\n\nThis will NOT update the game. It can consume hundreds of MB or more.\nDo not execute or install the sample.'):
                    stage()
            elif kind=='error': state(False);show('Stopped / unsuccessful:\n'+data+'\n\nNo game update was applied. Keep partial files in staging only.')
            elif kind=='done':
                state(False);show('Sample download and content-hash check passed.\nNo game update was applied.\nDo NOT run or install the sample.\n\nFolder: '+str(data)+'\n\nShare only Retail-Staging-to-share.json, not the private log.')
            elif kind=='progress': output.insert('end','\n'+data)
    except queue.Empty:pass
    root.after(150,poll)
def close():
    if busy:
        if messagebox.askyesno('Stop','Request cancellation? Keep this window open until it stops.'):
            cancel.set();show('Cancellation requested. Metadata requests can take up to their timeout to finish.\nWait for the stopped message.');return
        return
    root.destroy()
check=tk.Button(root,text='انتخاب .build.info و آماده‌سازی تست',command=inspect);check.pack(pady=5)
stop=tk.Button(root,text='توقف دریافت',command=lambda:cancel.set(),state='disabled');stop.pack(pady=5)
show('First choose the installed game .build.info.\nNo Battle.net login is needed.\nThis prototype only tests official EU metadata + one-file TACTTool extraction.');root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
