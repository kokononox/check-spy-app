import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import sampler as engine,complete_catalog as preparation,common
root=tk.Tk();root.title('WoW Retail — Small Route Samples 0.12');root.geometry('820x580');q=queue.Queue();cancel=threading.Event();busy=False
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
 if not messagebox.askyesno('SMALL game-data samples, STAGING ONLY','Close WoW and Battle.net.\n\nFirst rebuild an OFFLINE plan from existing cache.\nThen at most 3 ARCHIVE and 3 DIRECT small samples.\nMax 8 MiB asset response bytes total, 1 MiB per object.\nTwo small official EU metadata requests additional.\nNo game install, execution, keys or decryption.\nComplete verified files reused on rerun; no partial byte resume.\nFirst failure stops that route, not the other route.\nPinned historical target never switched if newer version online.\nNeeds 2 GiB free staging. HTTPS exposes IP to contacted servers.\nStart?'):return
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
    state(False);r,out=d;show('Result: '+r['status']+'\nSelected samples: '+str(r['selected_samples'])+'\nNew verified samples: '+str(r['new_verified_samples_saved'])+'\nVerified cached samples reused: '+str(r['verified_cached_samples_reused'])+'\nAsset response bytes read: '+str(r['asset_response_bytes_read'])+'\n\nShare ONLY Retail-Route-Samples-to-share.json from:\n'+str(out)+'\n\nNo installation or full update. Keep sample cache and private SQLite local.')
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stop? Wait for final result before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='آزمون چند نمونهٔ کوچک از دو مسیر',command=launch);start.pack(pady=5);stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net. Select ORIGINAL v0.9 batch report, then .build.info.\nUses completed v0.11 cache; rebuilds offline plan first.\nAt most 3 small samples per route, no install or execution.\nKeep cache: complete verified samples are reused on rerun.\nNo Administrator / pip; needs 2 GiB staging space.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
