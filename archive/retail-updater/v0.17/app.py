import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import progressive as engine,complete_catalog as preparation,common
root=tk.Tk();root.title('WoW Retail — Controlled Stop/Resume Test 0.17');root.geometry('820x580');q=queue.Queue();cancel=threading.Event();busy=False
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
 if not messagebox.askyesno('CONTROLLED STOP TEST, STAGING ONLY','Close WoW/Battle.net and other queue tools.\n\nReverify prior cache, prepare a NEW bounded batch.\nFIRST run deliberately pauses after TWO verified new objects.\nSECOND run finishes remaining objects of SAME batch.\nAfter completion, further runs do NOT advance to another batch.\nNo need to disconnect internet or manually time Stop.\nMax8 objects /16 MiB asset response per run.\nNo retry, bypass, install, execution or decryption.\nTwo small EU metadata checks before first new request.\nNeeds2 GiB staging; HTTPS exposes IP. Start?'):return
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
    state(False);r,out=d;show('Result: '+r['status']+'\nPlanned automatic pause triggered: '+str(r.get('controlled_pause_triggered',False))+'\nPrevious pause recognized: '+str(r.get('controlled_pause_previously_reached',False))+'\nSame-batch resume test complete: '+str(r.get('controlled_resume_test_complete',False))+'\nNew verified objects this run: '+str(r['new_verified_objects_saved'])+'\nFailure: '+str(r.get('failure_reason','none'))+'\n\nCONTROLLED PAUSE is intentional, not internet failure.\nShare ONLY Retail-Controlled-Resume-to-share.json from:\n'+str(out)+'\n\nKeep all private state/caches LOCAL. Do not reset phase or delete lock blindly. No installation.')
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stop? Wait for final result before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='آزمون مکث خودکار و ادامهٔ همان دسته',command=launch);start.pack(pady=5);stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net and other queue tools. Choose ORIGINAL v0.9 report, then .build.info.\nFIRST run pauses automatically after TWO new verified objects.\nSend first report before continuing. SECOND run finishes SAME batch.\nFurther runs after completion download no next batch.\nNo internet disconnect required; no install/automatic retry.\nKeep all caches and v0.17 state. Needs2 GiB staging; no pip/admin.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
