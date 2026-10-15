import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import progressive as engine,complete_catalog as preparation,common
root=tk.Tk();root.title('WoW Retail — Progressive Bounded Queue 0.16');root.geometry('820x580');q=queue.Queue();cancel=threading.Event();busy=False
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
  preparation.prepare(rp,bi)
 except Exception as e:messagebox.showerror('Cannot start',str(e));return
 if not messagebox.askyesno('PROGRESSIVE bounded queue, STAGING ONLY','Close WoW/Battle.net and other queue tools.\n\nFresh OFFLINE plan + reverify prior v0.12/v0.14/v0.15/v0.16 files.\nAlready verified files are skipped, not downloaded again.\nIncomplete previous batch FIRST; otherwise next small batch.\nMax8 objects /16 MiB asset response per run.\nEach object <4 MiB encoded /<=16 MiB decoded.\nFirst error stops; completed files preserved.\nNo automatic retry, install, execution or decryption.\nTwo small EU metadata checks before first new request.\nNeeds2 GiB staging; cache scans can take minutes.\nHTTPS exposes IP. Start?'):return
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
    state(False);r,out=d;stats=r.get('prior_cache_verification',{});show('Result: '+r['status']+'\nMode: '+str(r.get('selection_mode','not selected'))+'\nPreviously complete unique objects reverified: '+str(stats.get('known_verified_objects','not established'))+'\nObjects selected this run: '+str(r['selected_queue_objects'])+'\nNew verified downloads: '+str(r['new_verified_objects_saved'])+'\nFailure: '+str(r.get('failure_reason','none'))+'\n\nShare ONLY Retail-Progressive-Queue-to-share.json from:\n'+str(out)+'\n\nKeep progress-private.json, queue-private.json, SQLite and caches LOCAL.\nDo not delete queue.lock blindly. No installation or full-update claim.')
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stop? Wait for final result before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='اجرای دستهٔ بعدی یا ادامهٔ دستهٔ نیمه‌تمام',command=launch);start.pack(pady=5);stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net and other queue tools. Select ORIGINAL v0.9 report, then .build.info.\nReverifies prior complete files before choosing next batch.\nPending previous batch is resumed first; otherwise up to8 NEXT objects.\nMax16 MiB asset response, no installation/automatic retry.\nOnly one progressive run at a time. Keep all caches and private state.\nNeeds2 GiB staging; no pip/admin.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
