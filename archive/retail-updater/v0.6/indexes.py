import re,sqlite3,struct

from pathlib import Path

class PlanError(Exception): pass

def open_db(path):
    db=sqlite3.connect(path);db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=NORMAL')
    db.execute('CREATE TABLE target(ekey BLOB PRIMARY KEY, bytes INTEGER NOT NULL, priority INTEGER NOT NULL) WITHOUT ROWID')
    db.execute('CREATE TABLE local(prefix BLOB, bytes INTEGER, PRIMARY KEY(prefix,bytes)) WITHOUT ROWID')
    return db

def fingerprint(path):
    s=path.stat();return s.st_size,s.st_mtime_ns,s.st_ino

def parse_idx(data,bucket):
    if len(data)<40:raise PlanError('Truncated local index')
    hh=int.from_bytes(data[:4],'little');version=int.from_bytes(data[8:10],'little')
    if hh!=16 or version!=7 or data[10]!=bucket or data[11]!=0 or data[12:16]!=bytes((4,5,9,30)):raise PlanError('Unsupported local index format')
    size=int.from_bytes(data[32:36],'little')
    if size%18 or 40+size>len(data):raise PlanError('Invalid local index entry area')
    for pos in range(40,40+size,18):
        key=data[pos:pos+9];loc=int.from_bytes(data[pos+9:pos+14],'big');total=int.from_bytes(data[pos+14:pos+18],'little')
        yield key,loc>>30,loc&((1<<30)-1),total

def import_local(db,installation,cancel,notify):
    folder=Path(installation)/'Data'/'data'
    if not folder.is_dir():raise PlanError('Expected Data/data local CASC storage; unsupported installation layout')
    files=sorted(folder.glob('*.idx'))
    if not files:raise PlanError('No local CASC journals found')
    if len(files)>1024:raise PlanError('Too many local journals')
    snapshots={};archives={};buckets=set();problems=[];records=0;invalid=0
    for j,path in enumerate(files):
        if cancel.is_set():raise PlanError('Cancelled')
        notify('Reading local journal '+str(j+1)+' / '+str(len(files)))
        mat=re.fullmatch(r'([0-9a-fA-F]{2})[0-9a-fA-F]{8}\.idx',path.name)
        if not mat or int(mat[1],16)>15:
            problems.append('unsupported_filename');continue
        bucket=int(mat[1],16);before=fingerprint(path)
        if before[0]>128*1024*1024:problems.append('oversized_journal');continue
        data=path.read_bytes()
        if before!=fingerprint(path):raise PlanError('Local journal changed during read; close game/launcher and retry')
        snapshots[path]=before;batch=[]
        try:
            for key,archive,offset,total in parse_idx(data,bucket):
                records+=1
                if records%50000==0 and cancel.is_set():raise PlanError('Cancelled')
                if archive not in archives:
                    ap=folder/('data.'+str(archive).zfill(3))
                    try:archives[archive]=(ap,fingerprint(ap))
                    except OSError:archives[archive]=(ap,None)
                af=archives[archive][1]
                if key==b'\0'*9 or total<30 or af is None or offset+total>af[0]:invalid+=1;continue
                batch.append((key,total-30))
                if len(batch)>=20000:
                    db.executemany('INSERT OR IGNORE INTO local VALUES (?,?)',batch);batch=[]
            if batch:db.executemany('INSERT OR IGNORE INTO local VALUES (?,?)',batch)
            buckets.add(bucket)
        except PlanError as exc:
            if str(exc)=='Cancelled':raise
            problems.append('unsupported_or_malformed_journal')
    db.commit()
    if not buckets: raise PlanError('No supported local journal buckets could be read; installation layout remains unverified')
    return {'files':len(files),'valid_buckets':sorted(buckets),'uncovered_buckets':[i for i in range(16) if i not in buckets],
            'journal_problems':problems,'index_records_examined':records,'invalid_or_unavailable_archive_references':invalid},snapshots,archives,files,folder

def stable(snapshots,archives,files,folder):
    if sorted(folder.glob('*.idx'))!=files:raise PlanError('Local journal set changed during scan')
    for path,old in snapshots.items():
        if fingerprint(path)!=old:raise PlanError('Local journal changed during scan')
    for path,old in archives.values():
        if old is not None and fingerprint(path)!=old:raise PlanError('Data archive changed during scan')
        if old is None and path.exists():raise PlanError('Data archive appeared during scan')
