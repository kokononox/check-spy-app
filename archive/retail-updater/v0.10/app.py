import sys,threading,queue
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import full_plan,common,metadata,indexes,staging
from encoding import EncodingError
root=tk.Tk();root.title('WoW Retail EU — Offline Global Candidate Plan 0.10');root.geometry('860x640');q=queue.Queue();cancel=threading.Event();busy=False;base=Path(__file__).resolve().parent
view=tk.Text(root,wrap='word');view.pack(padx=16,pady=16,fill='both',expand=True)
def show(s):view.delete('1.0','end');view.insert('end',s)
def state(v):
 global busy
 busy=v;start.config(state='disabled' if v else 'normal');stop.config(state='normal' if v else 'disabled')
def pretty(n):return format(n,',')+' bytes ('+format(n/1024**3,'.3f')+' GiB)'
def launch():
 if sys.maxsize<=2**32:messagebox.showerror('Python','Existing Python 3.9+ 64-bit required.');return
 rp=filedialog.askopenfilename(title='Select ORIGINAL v0.9 Retail-Archive-Batch-to-share.json',filetypes=[('JSON','*.json')])
 if not rp:return
 bi=filedialog.askopenfilename(title='Select installed .build.info',filetypes=[('Build info','.build.info'),('All files','*')])
 if not bi:return
 try:
  installation=common.local_info(bi)['installation']
  if base==installation or base.is_relative_to(installation):raise ValueError()
 except Exception:messagebox.showerror('Cannot continue','Extract OUTSIDE game and select EU Retail Windows x64 .build.info.');return
 text='Close WoW and Battle.net.\n\nOFFLINE planning only: cached target manifests, fresh local journals, cached CDN indexes and already staged files.\nNo HTTP requests, game downloads, execution, decryption or installation.\nNeeds 2 GiB free staging space and may take minutes.\nWhole-object sums are NOT final patch/download size. Start planning?'
 if not messagebox.askyesno('Read-only global plan',text):return
 cancel.clear();state(True);show('Preparing offline global candidate plan…')
 def worker():
  try:q.put(('done',full_plan.run(rp,bi,cancel,lambda s:q.put(('progress',s)))))
  except (full_plan.FullPlanError,common.StageError,metadata.ContentError,indexes.PlanError,EncodingError,staging.StagingError) as e:q.put(('error',str(e)))
  except Exception as e:q.put(('error',type(e).__name__+' — planning stopped. No game update or network download.'))
 threading.Thread(target=worker,daemon=True).start()
def poll():
 try:
  while True:
   kind,data=q.get_nowait()
   if kind=='progress':show(data+'\n\nReading/validating locally. No game files changed.\nExact remaining time unavailable; wait for the final message.')
   elif kind=='error':state(False);show('Plan stopped:\n'+data+'\n\nNo complete plan claim. No game-file changes or downloads. Keep caches and earlier outputs.')
   elif kind=='done':
    state(False);r,out=data;p=r['plan'];i=r['inventory']
    text='Result: '+r['status']+'\n\nUnique selected target objects: '+format(i['unique_target_ekeys'],',')+'\nLocal prefix+size candidates (PAYLOAD NOT VERIFIED): '+format(i['prefix_and_size_candidates'],',')+'\nFresh unmatched candidates: '+format(p['candidate_objects_before_staging'],',')+'\nTheir WHOLE-OBJECT bytes: '+pretty(p['candidate_whole_encoded_bytes_before_staging'])+'\n\n'
    labels={'metadata_unresolved':'Metadata unresolved','exact_encoded_copy_verified_in_staging':'Exact target representation already verified in staging','archive_range_location_known':'Archive location known (HTTP not tested for all)','advertised_direct_only':'Direct object advertised only (HTTP untested)','transport_location_unresolved':'Transport location unresolved'}
    for name,value in p['transport_classes'].items():text+=labels[name]+': '+format(value['target_objects'],',')+' objects\n'
    text+='\nCandidate bytes after exact STAGING copies excluded: '+pretty(p['candidate_whole_encoded_bytes_without_verified_exact_staged_copy'])+'\nTHIS IS NOT REQUIRED DOWNLOAD / PATCH SIZE.\nNo CASC install or updated playable-game claim.\n\nShare ONLY Retail-Full-Plan-to-share.json from:\n'+str(out)+'\nKeep full-plan-private.sqlite LOCAL.';show(text)
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request cancellation? Wait for the stopped/result message before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='انتخاب گزارش ۰٫۹ و ساخت طرح سراسری آفلاین',command=launch);start.pack(pady=5)
stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close game/Battle.net. Choose ORIGINAL v0.9 batch report, then installed .build.info.\n\nUses existing cached metadata only. No network requests at all.\nFresh whole-scope inventory + candidate archive coverage + staged-file reverification.\nReports unknown/partial coverage honestly; local prefix matches are NOT content proof.\nNo pip or Administrator. Needs 2 GiB free staging space.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
