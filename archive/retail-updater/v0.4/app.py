import queue,sys,threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import content_compare as cc
from encoding import EncodingError
import indexes as ix

root=tk.Tk();root.title('WoW Retail EU — Offline Content Comparison 0.4');root.geometry('790x550')
q=queue.Queue();cancel=threading.Event();busy=False;base=Path(__file__).resolve().parent
labels={'exact_index_candidate_now':'Exact encoding index candidate found now','alternate_encoding_same_content_candidate':'Same-content alternate encoding candidate','same_content_metadata_no_local_index_candidate':'Same CKey in old metadata, no indexed candidate','content_key_not_in_installed_build_metadata':'CKey not in old-build metadata (not proof of disk absence)','target_ekey_unmapped':'No target CKey mapping','metadata_decoded_size_conflict':'Decoded-size conflict — unresolved'}
tk.Label(root,text='تطبیق آفلاین محتوا — بدون دانلود بازی یا تغییر نصب',font=('Arial',14)).pack(pady=12)
tk.Label(root,text='Close WoW and Battle.net. Keep original v0.2/v0.3 staging folders and private SQLite files local.',wraplength=750).pack()
view=tk.Text(root,wrap='word',height=20);view.pack(padx=15,pady=12,expand=True,fill='both')
def show(text):view.delete('1.0','end');view.insert('end',text)
def state(value):
 global busy
 busy=value;start.config(state='disabled' if value else 'normal');stop.config(state='normal' if value else 'disabled')
def launch():
 if sys.maxsize<=2**32:messagebox.showerror('Unsupported','64-bit Python is required.');return
 report=filedialog.askopenfilename(title='Select ORIGINAL Retail-Inventory-to-share.json from v0.3',filetypes=[('JSON','*.json')])
 if not report:return
 if not (Path(report).parent/'inventory-private.sqlite').is_file():messagebox.showerror('Wrong report location','Select the original report beside inventory-private.sqlite, not a copied report. Do not upload that database.');return
 info=filedialog.askopenfilename(title='Select installed game .build.info',filetypes=[('Build info','.build.info'),('All files','*')])
 if not info:return
 try:
  local=cc.c.local_info(info)
  if base.is_relative_to(local['installation']):raise ValueError()
 except Exception:messagebox.showerror('Cannot continue','Extract outside the game; select an active EU Retail Windows x64 .build.info.');return
 if not messagebox.askyesno('Offline comparison','Game and Battle.net must be closed.\n\nUses target Encoding metadata already downloaded by v0.2 and installed metadata. No network downloads.\nMay read hundreds of MB of metadata and use about 1 GiB of staging space/RAM.\nNo game files will be installed. Continue?'):return
 state(True);cancel.clear();show('Reading original inventory and verified Encoding metadata…')
 def worker():
  try:result,folder=cc.run(report,info,cancel,lambda s:q.put(('progress',s)));q.put(('done',(result,folder)))
  except (cc.ContentError,EncodingError,ix.PlanError,cc.c.StageError) as exc:q.put(('error',str(exc)))
  except Exception as exc:q.put(('error',type(exc).__name__+' — operation failed; no game update applied.'))
 threading.Thread(target=worker,daemon=True).start()
def poll():
 try:
  while True:
   kind,data=q.get_nowait()
   if kind=='progress':show(data+'\n\nOffline metadata comparison. No game files changed.\nPlease wait; no exact remaining-time estimate is available.')
   elif kind=='error':state(False);show('Comparison stopped / failed:\n'+data+'\n\nNo conclusion about reusable content. No game update applied.\nDo not delete the old cache or upload the private database.')
   elif kind=='done':
    state(False);r,folder=data;text=('Partial content-candidate comparison; index coverage gaps.\n\n' if r['comparison_has_index_coverage_gaps'] else 'Content-candidate comparison completed, NOT a full update.\n\n')
    for name,v in r['summary'].items():text+=labels[name]+': '+str(v['target_objects'])+'\n'
    text+='\nEncoding metadata hashes/pages verified; OTHER asset payloads NOT verified.\nByte sums are NOT confirmed patch size or saved bandwidth.\n\nShare ONLY Retail-Content-to-share.json from:\n'+str(folder)
    show(text)
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request cancellation? Wait until it stops before closing.'):cancel.set()
  return
 root.destroy()
start=tk.Button(root,text='انتخاب گزارش ۰٫۳ و شروع تطبیق محتوا',command=launch);start.pack(pady=5)
stop=tk.Button(root,text='توقف',command=lambda:cancel.set(),state='disabled');stop.pack(pady=5)
show('This version is OFFLINE and will not repeat the earlier downloads.\nIt compares ONLY the previously unmatched target objects.\nFresh local indexes are read, then CKey/decoded-size mappings are compared.\nAlternate asset contents are NOT yet validated or installed.\nIf required metadata is missing/corrupt, it stops rather than downloading silently.');root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
