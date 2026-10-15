import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import large_range as engine,complete_catalog as preparation,common
root=tk.Tk();root.title('WoW Retail — Larger Archive Range Pilot 0.18');root.geometry('820x580');q=queue.Queue();cancel=threading.Event();busy=False
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
 if not messagebox.askyesno('ONE larger archive Range, STAGING ONLY','Close WoW/Battle.net and other queue tools.\n\nFresh offline plan, then ONE archive object >=1 MiB and <4 MiB.\nDecoded cap16 MiB. Total asset response cap4 MiB including probe.\nMust receive206 + EXACT Content-Range. Full-archive200 rejected BEFORE body.\nTwo small EU metadata checks additional before new request.\nNo direct fallback, retry, bypass, install or execution.\nPrevious exact files reused only after verification; cached reuse is NOT a new Range test.\nPinned target unchanged; needs2 GiB staging. HTTPS exposes IP. Start?'):return
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
    state(False);r,out=d;show('Result: '+r['status']+'\nExpected encoded bytes: '+str(r['planned_encoded_bytes'])+'\nRange requested: '+str(r['range_request_attempted'])+'\nHTTP status: '+str(r.get('range_http_status'))+'\nStrict Range headers verified: '+str(r['strict_range_headers_verified'])+'\nExact expected bytes received: '+str(r.get('exact_range_response_length_received',False))+'\nNew verified sample saved: '+str(r['new_verified_objects_saved'])+'\nEncoded integrity verified objects: '+str(r.get('encoded_verified_objects',0))+'\nDecoded CKey verified objects: '+str(r.get('decoded_ckey_verified_objects',0))+'\nFailure: '+str(r.get('failure_reason','none'))+'\n\nShare ONLY Retail-Large-Range-to-share.json from:\n'+str(out)+'\n\nKeep range-private.json, SQLite and caches LOCAL. No installation. Send report before rerun.')
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stop? Wait for final result before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='آزمون یک نمونهٔ آرشیوی بزرگ‌تر',command=launch);start.pack(pady=5);stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net and other tools. Choose ORIGINAL v0.9 report, then .build.info.\nFresh offline preparation may take minutes. ONE larger archive Range sample only.\nExpected encoded size >=1 MiB /<4 MiB, decoded<=16 MiB.\nRejects full archive response200 BEFORE reading body.\nNo installation, direct fallback or automatic retry. Keep all caches.\nNeeds2 GiB free staging; no pip/admin.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
