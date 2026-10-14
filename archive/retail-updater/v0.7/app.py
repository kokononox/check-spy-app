import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import pilot,common,metadata
from encoding import EncodingError
root=tk.Tk();root.title('WoW Retail EU — Limited CDN Pilot 0.7');root.geometry('800x550')
q=queue.Queue();cancel=threading.Event();busy=False;base=Path(__file__).resolve().parent
view=tk.Text(root,wrap='word');view.pack(padx=16,pady=16,fill='both',expand=True)
def show(s):view.delete('1.0','end');view.insert('end',s)
def state(value):
 global busy
 busy=value;start.config(state='disabled' if value else 'normal');stop.config(state='normal' if value else 'disabled')
def worker_prepare(rp,bi):
 try:q.put(('plan',pilot.prepare(rp,bi,cancel,lambda s:q.put(('progress',s)))))
 except Exception as exc:q.put(('error',safe_error(exc)))
def safe_error(exc):
 if isinstance(exc,(pilot.PilotError,common.StageError,metadata.ContentError,EncodingError)):return str(exc)
 if isinstance(exc,pilot.urllib.error.URLError):return 'Official metadata could not be reached: DNS/TLS/network problem. No sample downloaded.'
 return type(exc).__name__+' — preparation failed. No sample download or installation.'
def launch():
 if sys.maxsize<=2**32:messagebox.showerror('Python','Existing 64-bit Python 3.9+ required.');return
 rp=filedialog.askopenfilename(title='Select ORIGINAL v0.6 Retail-Payload-Diagnostic-to-share.json',filetypes=[('JSON','*.json')])
 if not rp:return
 if not (Path(rp).parent/'payload-verify-private.sqlite').is_file():messagebox.showerror('Original report needed','Select original report beside payload-verify-private.sqlite; do not upload the database.');return
 bi=filedialog.askopenfilename(title='Select installed .build.info',filetypes=[('Build info','.build.info'),('All files','*')])
 if not bi:return
 try:
  installation=common.local_info(bi)['installation']
  if base==installation or base.is_relative_to(installation):raise ValueError()
 except Exception:messagebox.showerror('Cannot continue','Extract outside game and select EU Windows x64 Retail .build.info.');return
 if not messagebox.askyesno('Prepare a bounded sample plan','Close WoW and Battle.net.\n\nReads existing local target metadata and candidate report. Queries two small official HTTPS metadata endpoints (each less than 256 KiB).\nNo asset download until the NEXT confirmation. No installation or decryption.\nContinue?'):return
 state(True);cancel.clear();show('Preparing plan; no game asset download yet.');threading.Thread(target=worker_prepare,args=(rp,bi),daemon=True).start()
def worker_download(plan):
 try:q.put(('done',pilot.download(plan,cancel,lambda s:q.put(('progress',s)))))
 except Exception as exc:q.put(('error',safe_error(exc)))
def poll():
 try:
  while True:
   kind,data=q.get_nowait()
   if kind=='progress':show(data+'\n\nNo game-file changes. Wait for the final message.')
   elif kind=='error':state(False);show('Stopped:\n'+data+'\n\nNo update applied. Keep earlier staging and private databases.')
   elif kind=='plan':
    if cancel.is_set():state(False);show('Cancelled before sample download.');continue
    text='ONE exact target object: '+str(data['encoded_size'])+' bytes ('+format(data['encoded_size']/1048576,'.3f')+' MiB).\nPinned target: '+data['target_version']+'\nCurrent online version: '+data['current_online_version']+'\n'
    if data['target_version']!=data['current_online_version']:text+='WARNING: pinned target is NOT the current version; this is an older-target transport test, not a usable latest update.\n'
    text+='\nAt most 8 MiB asset response read, plus already checked small metadata and network overhead. One request, no automatic retries.\nSaved OUTSIDE game only. No install/execution/decryption.\nDownload this sample now?'
    show(text)
    if messagebox.askyesno('Confirm bounded sample download',text):threading.Thread(target=worker_download,args=(data,),daemon=True).start()
    else:state(False);show('Asset download declined. No game files changed.')
   elif kind=='done':
    state(False);r,folder=data
    text='Result: '+r['status']+'\n'
    if r['failure_reason']:text+='Reason: '+r['failure_reason']+'\n'
    text+='Encoded integrity verified: '+str(r['encoded_integrity_verified'])+'\nDecoded CKey verified: '+str(r['decoded_ckey_verified'])+'\n'
    text+='\nThis is ONE staging sample, NOT an installed update. Do NOT copy it into game or run it.\n\nShare ONLY Retail-CDN-Pilot-to-share.json from:\n'+str(folder)
    show(text)
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Stop','Request cancellation? Wait for the stopped/result message before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='انتخاب گزارش ۰٫۶ و آماده‌سازی دانلود آزمایشی',command=launch);start.pack(pady=5)
stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net. Choose the ORIGINAL v0.6 diagnostic report, then installed .build.info.\n\nOnly one small exact target object, <=8 MiB, downloaded after you confirm its size. Official HTTPS only.\nNo automatic retry, no installation or game-file changes. No key extraction or decryption.\nKeeps pinned build; shows if it differs from current online version.\nNo new pip packages or Administrator needed.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
