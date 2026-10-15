import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import direct_audit,common
root=tk.Tk();root.title('WoW Retail — OFFLINE Direct Eligibility 0.13');root.geometry('850x640');q=queue.Queue();cancel=threading.Event();busy=False
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
 except Exception as e:messagebox.showerror('Cannot start',str(e));return
 if not messagebox.askyesno('OFFLINE size audit','Close WoW/Battle.net.\n\nRebuild offline plan, then audit direct-only object encoded/decoded sizes.\nNo network, download, installation or automatic limit change.\nExisting cache required; 2 GiB free staging.\nMay take minutes. Start?'):return
 cancel.clear();state(True)
 def work():
  try:q.put(('done',direct_audit.run(rp,bi,cancel,lambda s:q.put(('progress',s)))))
  except Exception as e:q.put(('error',str(e) if isinstance(e,(direct_audit.AuditError,common.StageError,direct_audit.full_plan.FullPlanError)) else type(e).__name__+' — stopped; no network or game changes'))
 threading.Thread(target=work,daemon=True).start()
def poll():
 try:
  while True:
   k,d=q.get_nowait()
   if k=='progress':show(d+'\n\nReading cached metadata locally. Wait for final message.')
   elif k=='error':state(False);show('Stopped: '+d+'\nNo completed-audit claim. Keep cache.')
   else:
    state(False);r,out=d;a=r['audit'];text='Result: '+r['status']+'\nExplanation: '+a['selection_explanation']+'\nDirect candidates: '+str(a['direct_candidate_objects'])+'\n\n'
    labels={'eligible_under_v012_limits':'Eligible under BOTH old caps','encoded_limit_only':'Encoded cap only exceeded','decoded_limit_only':'Decoded cap only exceeded','both_limits':'Both caps exceeded'}
    for key,v in a['eligibility_groups'].items():text+=labels[key]+': '+str(v['objects'])+'\n'
    text+='\nSmallest encoded candidates (encoded / decoded bytes):\n'
    for p in a['smallest_encoded_candidates']:text+=str(p['encoded_bytes'])+' / '+str(p['decoded_bytes'])+'\n'
    text+='\nNo download and no limit increase. Share ONLY\nRetail-Direct-Eligibility-to-share.json from:\n'+str(out)+'\nKeep private SQLite LOCAL.';show(text)
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stop? Wait for final message before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='بررسی آفلاین علت حذف نمونه‌های مستقیم',command=launch);start.pack(pady=5);stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net. Choose ORIGINAL v0.9 batch report, then .build.info.\nKeeps prior v0.11 caches; first rebuilds a fresh offline plan.\nExplains old v0.12 eligibility caps: 1 MiB encoded /16 MiB decoded.\nNo network or automatic size-limit change.\nNeeds 2 GiB staging; no pip/admin.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
