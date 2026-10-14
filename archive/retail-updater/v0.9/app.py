import sys,queue,threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog,messagebox
import batch,pilot,common,metadata,range_pilot
from encoding import EncodingError
from archive_index import IndexError
root=tk.Tk();root.title('WoW Retail EU — Small Archive Batch 0.9');root.geometry('820x570');q=queue.Queue();cancel=threading.Event();busy=False;base=Path(__file__).resolve().parent
view=tk.Text(root,wrap='word');view.pack(padx=16,pady=16,fill='both',expand=True)
def show(s):view.delete('1.0','end');view.insert('end',s)
def state(value):
 global busy
 busy=value;start.config(state='disabled' if value else 'normal');stop.config(state='normal' if value else 'disabled')
def safe_error(e):
 if isinstance(e,(batch.BatchError,pilot.PilotError,range_pilot.RangeError,IndexError,common.StageError,metadata.ContentError,EncodingError)):return str(e)
 if isinstance(e,pilot.urllib.error.URLError):return 'Official metadata connection failed. No batch asset download or installation.'
 return type(e).__name__+' — operation stopped; no update applied.'
def prepare_worker(rp,bi):
 try:q.put(('plan',batch.prepare(rp,bi,cancel,lambda s:q.put(('progress',s)))))
 except Exception as e:q.put(('error',safe_error(e)))
def download_worker(plan):
 try:q.put(('done',batch.run(plan,cancel,lambda s:q.put(('progress',s)))))
 except Exception as e:q.put(('error',safe_error(e)))
def launch():
 if sys.maxsize<=2**32:messagebox.showerror('Python','Existing Python 3.9+ 64-bit required.');return
 rp=filedialog.askopenfilename(title='Select ORIGINAL v0.6 Retail-Payload-Diagnostic-to-share.json',filetypes=[('JSON','*.json')])
 if not rp:return
 if not (Path(rp).parent/'payload-verify-private.sqlite').is_file():messagebox.showerror('Original report','Choose original v0.6 report beside payload-verify-private.sqlite. Keep database local.');return
 bi=filedialog.askopenfilename(title='Select installed .build.info',filetypes=[('Build info','.build.info'),('All files','*')])
 if not bi:return
 try:
  installation=common.local_info(bi)['installation']
  if base==installation or base.is_relative_to(installation):raise ValueError()
 except Exception:messagebox.showerror('Cannot continue','Extract OUTSIDE game and select EU Retail Windows x64 .build.info.');return
 text='Close WoW/Battle.net. Prepare up to 8 small samples, total less than 8 MiB game-data response.\n\nUses existing local metadata/indexes. Missing indexes: at most 16 requests / 32 MiB response read SHARED across batch; small official metadata additional.\nGame-data download starts ONLY after the next confirmation. No install, execution or decryption.\nPrepare plan?'
 if not messagebox.askyesno('Prepare bounded batch',text):return
 cancel.clear();state(True);show('Preparing bounded batch; no game-data requests yet.');threading.Thread(target=prepare_worker,args=(rp,bi),daemon=True).start()
def done_text(r,folder):
 return 'Result: '+r['status']+'\n'+('Reason: '+str(r['failure_reason'])+'\n' if r['failure_reason'] else '')+'\nSelected: '+str(r['selected_target_objects'])+'\nLocated: '+str(r['located_target_objects'])+'\nEncoded integrity verified: '+str(r['encoded_verified_objects'])+'\nDecoded CKey verified: '+str(r['decoded_ckey_verified_objects'])+'\nGame-data response bytes read: '+str(r['range_response_bytes_read'])+'\n\nThis is a SMALL STAGING TEST, not an installed update.\nCompleted verified samples remain saved even after a later failure. Do not copy or execute them.\n\nShare ONLY Retail-Archive-Batch-to-share.json from:\n'+str(folder)
def poll():
 try:
  while True:
   kind,data=q.get_nowait()
   if kind=='progress':show(data+'\n\nLocal index scans may take minutes. No game-file changes. Wait for the final result.')
   elif kind=='error':state(False);show('Stopped:\n'+data+'\nKeep previous files; do not repeat a download blindly.')
   elif kind=='done':state(False);r,folder=data;show(done_text(r,folder))
   elif kind=='plan':
    if 'failed_report' in data:q.put(('done',(data['failed_report'],data['output'])));continue
    if cancel.is_set():q.put(('done',batch.stop_before_download(data)));continue
    ready=[i for i in data['items'] if i['lookup_status']=='located'];total=sum(i['expected_encoded_bytes'] for i in ready)
    text='Selected '+str(len(data['items']))+' samples; located '+str(len(ready))+'.\nExact planned game-data bytes: '+str(total)+' ('+format(total/1048576,'.3f')+' MiB).\nPinned target: '+data['target_version']+'\nCurrent online: '+data['current_online_version']+'\n'
    if data['target_version']!=data['current_online_version']:text+='WARNING: pinned target is older/different; this is NOT the current game update.\n'
    if len(ready)!=len(data['items']):text+='Unresolved samples will NOT be requested and are reported.\n'
    text+='\nSequential exact Range requests. Stop at FIRST download/verification failure, no automatic retry. Verified earlier files stay saved.\nNo install, full archive, execution or decryption. Download this batch?'
    show(text)
    if messagebox.askyesno('Confirm small batch download',text):threading.Thread(target=download_worker,args=(data,),daemon=True).start()
    else:q.put(('done',batch.decline(data)))
 except queue.Empty:pass
 root.after(150,poll)
def close():
 if busy:
  if messagebox.askyesno('Cancel','Request stopping? Wait for the final result before closing.'):cancel.set()
 else:root.destroy()
start=tk.Button(root,text='انتخاب گزارش ۰٫۶ و آماده‌سازی دستهٔ کوچک',command=launch);start.pack(pady=5)
stop=tk.Button(root,text='توقف',command=cancel.set,state='disabled');stop.pack(pady=5)
show('Close WoW/Battle.net. Choose ORIGINAL v0.6 diagnostic report, then .build.info.\n\nUp to 8 small target objects, combined game-data response read capped at 8 MiB. Small index/metadata budget is separate and shared across batch.\nPlan and size shown before asset download. Every object verified separately.\nNo automatic retry, no game-file changes, no decryption. No pip or Administrator.')
root.protocol('WM_DELETE_WINDOW',close);poll();root.mainloop()
