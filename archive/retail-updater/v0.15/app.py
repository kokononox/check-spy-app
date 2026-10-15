import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import queue_engine as engine,complete_catalog as preparation,common
root=tk.Tk();root.title('WoW Retail — Bounded Resumable Queue 0.15');root.geometry('820x580');q=queue.Queue();cancel=threading.Event();busy=False
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
 if not messagebox.askyesno('BOUNDED queue, STAGING ONLY','Close WoW and Battle.net.\n\nFirst rebuild an OFFLINE plan from existing cache.\nAt most 8 objects, up to 4 per route.\nMax 16 MiB asset response bytes total; each object <4 MiB.\nDecoded limit stays 16 MiB per object.\nPrevious v0.12/v0.14 exact files reverified and copied locally.\nFirst error STOPS QUEUE; completed files preserved.\nRerun resumes by complete verified files, not partial bytes.\nNo install, execution, decryption, bypass or automatic retry.\nTwo small EU metadata checks before first new download.\nUnchanged sources reproduce SAME bounded queue, not next batch.\nNeeds 2 GiB free staging; HTTPS exposes IP to servers.\nStart?'):return
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
    state(False);r,out=d;show('Result: '+r['status']+'\nSelected queue objects: '+str(r['selected_queue_objects'])+'\nNew verified downloads: '+str(r['new_verified_objects_saved'])+'\nQueue cached files reused: '+str(r['verified_queue_cache_reused'])+'\nPrevious pilot files imported after verification: '+str(r['verified_previous_files_imported'])+'\nAsset response bytes read: '+str(r['asset_response_bytes_read'])+'\n\nShare ONLY Retail-Queue-to-share.json from:\n'+str(out)+'\n\nKeep queue-private.json, SQLite and cache objects LOCAL.\nNo installation or whole-update claim. If failed, send report before rerunning.')
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stop? Wait for final result before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='اجرای صف محدود و قابل‌ادامه',command=launch);start.pack(pady=5);stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net. Select ORIGINAL v0.9 batch report, then .build.info.\nFresh offline plan; at most8 small objects from two routes, <=16 MiB response.\nUses previous valid v0.12/v0.14 files after verification; keeps progress.\nFirst error stops queue. No install, retry or bypass.\nNo Administrator/pip; needs2 GiB staging. Keep all prior caches.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
