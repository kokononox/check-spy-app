import json,queue,sys,threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import planner

root=tk.Tk();root.title('WoW Retail EU — Read-only Inventory 0.3');root.geometry('780x540')
q=queue.Queue();cancel=threading.Event();busy=False
base=Path(__file__).resolve().parent
label='مقایسهٔ فقط‌خواندنی فهرست CASC — بدون نصب یا آپدیت بازی'
tk.Label(root,text=label,font=('Arial',14),wraplength=740).pack(pady=12)
tk.Label(root,text='Close WoW and Battle.net first. Select the ORIGINAL successful v0.2 report in its staging folder.',wraplength=740).pack()
view=tk.Text(root,wrap='word',height=20);view.pack(padx=15,pady=10,fill='both',expand=True)
def show(text):view.delete('1.0','end');view.insert('end',text)
def state(value):
 global busy
 busy=value;start.config(state='disabled' if value else 'normal');stop.config(state='normal' if value else 'disabled')
def run():
 if sys.maxsize<=2**32:messagebox.showerror('Unsupported','Use your 64-bit Python. This large manifest inventory does not support 32-bit Python.');return
 report=filedialog.askopenfilename(title='Select ORIGINAL Retail-Staging-to-share.json in its staging folder',filetypes=[('JSON','*.json')])
 if not report:return
 if not (Path(report).parent/'build.config').is_file():messagebox.showerror('Wrong folder','Select the original report beside build.config and cache, not a copied report.');return
 info=filedialog.askopenfilename(title='Select .build.info in the installed WoW root',filetypes=[('Build info','.build.info'),('All files','*')])
 if not info:return
 try:
  local=planner.f.local_info(info)
  if base.is_relative_to(local['installation']):raise ValueError()
 except Exception:messagebox.showerror('Cannot continue','Select EU Retail Windows x64 metadata. Extract the program outside the game installation.');return
 if not messagebox.askyesno('Read-only inventory','Game and Battle.net must be closed.\n\nThe download manifest is reused from cache if available. Otherwise this build needs about 61 MiB of metadata, not game files.\n\nThe result shows indexed candidates, NOT confirmed reusable data or the exact patch size.\nProceed?'):return
 state(True);cancel.clear();show('Preparing inventory…\nNo original game files will be changed.\nLarge-manifest processing may take several minutes.')
 def worker():
  try:
   result,folder=planner.run(report,info,cancel,lambda s:q.put(('progress',s)))
   q.put(('done',(result,folder)))
  except (planner.PlanError,planner.f.StageError) as exc:q.put(('error',str(exc)))
  except Exception as exc:q.put(('error',type(exc).__name__+' — no update applied.'))
 threading.Thread(target=worker,daemon=True).start()
def poll():
 try:
  while True:
   kind,data=q.get_nowait()
   if kind=='progress':show(data+'\n\nRead-only inventory; no game update applied.\nPlease wait. Cancellation during an HTTPS read can be delayed by its timeout.')
   elif kind=='error':state(False);show('Inventory stopped / failed:\n'+data+'\n\nNo conclusion about required downloads. No game update was applied.')
   elif kind=='done':
    state(False);r,folder=data;s=r['summary']
    heading='Partial inventory — index coverage gaps reported.' if r['comparison_has_index_coverage_gaps'] else 'Candidate inventory completed — NOT a complete update plan.'
    show(heading+'\nInstalled: '+r['local_version']+'\nCompared target: '+r['target_version']+'\n\nUnique target encoded objects: '+str(s['unique_target_ekeys'])+'\nPrefix + size candidates: '+str(s['prefix_and_size_candidates'])+'\nNo observed prefix match: '+str(s['no_observed_prefix_match'])+'\nPrefix found, size differs: '+str(s['prefix_with_size_mismatch'])+'\n\nCandidates are NOT verified reusable files. No match is NOT proof of absence.\nOptional content is included. Encoded totals are NOT patch size.\nUncovered local buckets: '+str(r['index_coverage']['uncovered_buckets'])+'\n\nShare ONLY Retail-Inventory-to-share.json from:\n'+str(folder)+'\nKeep inventory-private.sqlite local.')
 except queue.Empty:pass
 root.after(200,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request cancellation? Wait for the stopped message before closing.'):cancel.set()
  return
 root.destroy()
start=tk.Button(root,text='انتخاب گزارش قبلی و شروع بررسی',command=run);start.pack(pady=5)
stop=tk.Button(root,text='توقف بررسی',command=lambda:cancel.set(),state='disabled');stop.pack(pady=5)
show('Close the game and Battle.net before starting.\nThis version reuses the original staging folder.\nIt does not rerun TACTTool or download all archive indexes.\nNo login, Administrator access or new Python packages are required.\nPrivate database/metadata are written only into staging, outside the game.');root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
