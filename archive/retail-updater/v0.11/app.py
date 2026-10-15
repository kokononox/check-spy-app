import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import complete_catalog as engine,common
root=tk.Tk();root.title('WoW Retail — Index Completion 0.11');root.geometry('820x580');q=queue.Queue();cancel=threading.Event();busy=False
view=tk.Text(root,wrap='word');view.pack(padx=16,pady=16,fill='both',expand=True)
def show(s):view.delete('1.0','end');view.insert('end',s)
def state(v):
 global busy
 busy=v;start.config(state='disabled' if v else 'normal');stop.config(state='normal' if v else 'disabled')
def launch():
 if sys.maxsize<=2**32:messagebox.showerror('Python','64-bit Python required');return
 rp=filedialog.askopenfilename(title='Select ORIGINAL v0.9 Retail-Archive-Batch-to-share.json',filetypes=[('JSON','*.json')])
 if not rp:return
 bi=filedialog.askopenfilename(title='Select installed .build.info',filetypes=[('Build info','.build.info'),('All','*')])
 if not bi:return
 try:
  game=common.local_info(bi)['installation'];base=Path(__file__).resolve().parent
  if base==game or base.is_relative_to(game):raise ValueError('Extract outside game')
  engine.prepare(rp,bi)
 except Exception as e:messagebox.showerror('Cannot start',str(e));return
 if not messagebox.askyesno('INDEX metadata only','Close game and Battle.net.\n\nDownload only missing pinned archive INDEX metadata from official HTTPS CDN.\nMax 64 MiB response bytes / 128 requests per run, including EU metadata.\nNo game-content download or installation. Existing invalid indexes preserved.\nReruns skip verified complete files; no partial-response resume.\nPinned historical target is not changed if newer version is online.\nRequires 2 GiB free staging for offline replan.\nNormal HTTPS exposes your IP to servers. Start?'):return
 cancel.clear();state(True)
 def work():
  try:q.put(('done',engine.run(rp,bi,cancel,lambda s:q.put(('progress',s)))))
  except Exception as e:q.put(('error',str(e)))
 threading.Thread(target=work,daemon=True).start()
def poll():
 try:
  while True:
   k,d=q.get_nowait()
   if k=='progress':show(d+'\n\nWait for the final result. Stop may take up to the network timeout. No game install.')
   elif k=='error':state(False);show('Stopped: '+d+'\nNo completed-update claim. Keep previous caches.')
   else:
    state(False);r,out=d;show('Result: '+r['status']+'\nNew verified indexes saved: '+str(r['new_verified_indexes_saved'])+'\nIndexes not established valid: '+str(r['remaining_normal_indexes'])+'\nResponse bytes read: '+str(r['response_bytes_read'])+'\nReason: '+str(r['failure_reason'])+'\n\nShare Retail-Index-Completion-to-share.json'+('\nAND Retail-Full-Plan-to-share.json' if r['replan_completed'] else '')+'\nfrom:\n'+str(out)+'\n\nNo game-content download or installation. A complete plan is NOT a playable update.\nKeep caches and private SQLite LOCAL.')
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stop? Wait for final result before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='تکمیل فهرست‌ها و بازسازی طرح',command=launch);start.pack(pady=5);stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Select ORIGINAL v0.9 batch report, then .build.info.\nClose game/Battle.net; keep earlier staging caches.\nOnly missing individual archive index metadata will be downloaded.\nMax 64 MiB /128 requests; no admin/pip.\nExisting verified files are retained; rerun to continue after interruption.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
