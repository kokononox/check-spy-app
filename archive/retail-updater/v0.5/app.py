import queue,sys,threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import verify_local as engine
from payload import PayloadError
from encoding import EncodingError
import metadata,indexes,common
root=tk.Tk();root.title('WoW Retail EU — Local Payload Verification 0.5');root.geometry('810x570')
q=queue.Queue();cancel=threading.Event();busy=False;base=Path(__file__).resolve().parent
labels={'content_verified':'Full decoded CKey + encoded integrity verified','encoded_integrity_only':'Encoded integrity only; decoded content remains unverified','validation_failed':'Candidate did not pass validation','location_not_found':'No matching bounded location found in current indexes','read_failed':'Could not read candidate','metadata_unresolved':'Metadata mapping unresolved','not_checked_size_limit':'Not checked due to size limit'}
tk.Label(root,text='صحت‌سنجی دادهٔ واقعی — فقط خواندن، بدون دانلود یا نصب',font=('Arial',14)).pack(pady=12)
tk.Label(root,text='Close WoW and Battle.net. No decoded game assets are saved or executed.',wraplength=760).pack()
view=tk.Text(root,height=20,wrap='word');view.pack(padx=15,pady=12,expand=True,fill='both')
def show(text):view.delete('1.0','end');view.insert('end',text)
def state(value):
 global busy
 busy=value;start.config(state='disabled' if value else 'normal');stop.config(state='normal' if value else 'disabled')
def launch():
 if sys.maxsize<=2**32:messagebox.showerror('Unsupported','Use your existing 64-bit Python.');return
 report=filedialog.askopenfilename(title='Select ORIGINAL Retail-Content-to-share.json from v0.4',filetypes=[('JSON','*.json')])
 if not report:return
 if not (Path(report).parent/'content-private.sqlite').is_file():messagebox.showerror('Wrong location','Select the original report beside content-private.sqlite, not a copied report. Keep databases local.');return
 info=filedialog.askopenfilename(title='Select installed game .build.info',filetypes=[('Build info','.build.info'),('All files','*')])
 if not info:return
 try:
  local=common.local_info(info)
  if base.is_relative_to(local['installation']):raise ValueError()
 except Exception:messagebox.showerror('Cannot continue','Select EU Retail Windows x64 metadata; extract the program outside the game.');return
 if not messagebox.askyesno('Hash-only local verification','Game and Battle.net must be closed.\n\nThis reads metadata and actual local candidate payloads, but does NOT download or install game files.\nDecoded game assets are hashed in memory and NOT saved.\nEncrypted/unsupported modes are NOT decrypted; encoded integrity is reported separately.\nProceed?'):return
 state(True);cancel.clear();show('Preparing candidate payload verification…')
 def worker():
  try:r,folder=engine.run(report,info,cancel,lambda s:q.put(('progress',s)));q.put(('done',(r,folder)))
  except (engine.VerifyError,PayloadError,EncodingError,metadata.ContentError,indexes.PlanError,common.StageError) as exc:q.put(('error',str(exc)))
  except Exception as exc:q.put(('error',type(exc).__name__+' — operation failed; no update applied.'))
 threading.Thread(target=worker,daemon=True).start()
def poll():
 try:
  while True:
   kind,data=q.get_nowait()
   if kind=='progress':show(data+'\n\nReading/hashing locally. No game files changed.\nWait until the result message; exact remaining time is unavailable.')
   elif kind=='error':state(False);show('Verification stopped / failed:\n'+data+'\n\nNo completed verification claim and no game update. Keep the original cache and private files.')
   elif kind=='done':
    state(False);r,folder=data;text='Verification finished — not all objects necessarily passed.\n\n'
    for name,v in r['summary'].items():text+=labels[name]+': '+str(v['target_objects'])+'\n'
    text+='\nValid old content is NOT yet an installed update or guaranteed saved bandwidth.\nNo game downloads/writes/execution.\n\nShare ONLY Retail-Payload-Verify-to-share.json from:\n'+str(folder)+'\nKeep payload-verify-private.sqlite local.';show(text)
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request cancellation? Wait for the stopped message before closing.'):cancel.set()
  return
 root.destroy()
start=tk.Button(root,text='انتخاب گزارش ۰٫۴ و شروع صحت‌سنجی',command=launch);start.pack(pady=5)
stop=tk.Button(root,text='توقف',command=lambda:cancel.set(),state='disabled');stop.pack(pady=5)
show('Close game/Battle.net. Choose the ORIGINAL v0.4 report, then installed .build.info.\nThis checks ONLY the alternate-encoding candidates from that report.\nReads fresh indexes and actual asset bytes, verifies full EKey/chunk hashes and decoded CKey for supported modes.\nNo network requests, no decoded asset files, no CASC writes.');root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
