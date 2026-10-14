"""Read-only CASC prefix/size inventory, NOT a complete update/patch planner."""
import hashlib,json,os,re,shutil,sqlite3,struct,time,urllib.request,ssl
from datetime import datetime,timezone
from pathlib import Path
import formats as f
class PlanError(Exception): pass
LIMIT=128*1024*1024

def config_fields(raw):
    out={}
    for line in raw.decode('utf-8').splitlines():
        if '=' in line and not line.lstrip().startswith('#'):
            k,v=line.split('=',1);out[k.strip()]=v.split()
    return out

def manifest_layout(data,locales):
    if len(data)<11 or data[:2]!=b'DL' or data[2] not in (1,2,3) or data[3]!=16 or data[4] not in (0,1): raise PlanError('Unsupported download manifest header')
    version=data[2];n=int.from_bytes(data[5:9],'big');nt=int.from_bytes(data[9:11],'big')
    hs={1:11,2:12,3:16}[version]
    if len(data)<hs or not 0<n<=10000000 or nt>1000: raise PlanError('Invalid download manifest bounds')
    flag_bytes=data[11] if version>=2 else 0
    if flag_bytes>4: raise PlanError('Unsupported manifest flags')
    base=data[12] if version>=3 else 0
    es=22+4*data[4]+flag_bytes;pos=hs+n*es;width=(n+7)//8
    if pos>len(data): raise PlanError('Truncated download entries')
    tags=[]
    for _ in range(nt):
        end=data.find(b'\0',pos)
        if end<pos or end-pos>2048 or end+3+width>len(data): raise PlanError('Truncated download tag')
        name=data[pos:end].decode('utf-8');kind=int.from_bytes(data[end+1:end+3],'big')
        mask=data[end+3:end+3+width];pos=end+3+width;tags.append((kind,name,mask))
    if pos!=len(data): raise PlanError('Unexpected manifest trailing bytes')
    full=((1<<n)-1)<<(width*8-n);eligible=full
    chosen={1:{'Windows'},2:{'x86_64'},3:set(locales),4:{'EU'}}
    for kind,wanted in chosen.items():
        group=[(name,mask) for k,name,mask in tags if k==kind]
        if not group or not wanted.issubset({name for name,_ in group}): raise PlanError('Required platform/region/language tag missing')
        anytag=0;pick=0
        for name,mask in group:
            bits=int.from_bytes(mask,'big');anytag|=bits
            if name in wanted:pick|=bits
        eligible&=pick|(full^anytag)
    return {'count':n,'header_size':hs,'entry_size':es,'base_priority':base,'eligible':eligible.to_bytes(width,'big'),'tag_types':sorted(set(k for k,_,_ in tags)),
            'optional_tags_included':[name for k,name,_ in tags if k not in (1,2,3,4,5)]}

def open_db(path):
    db=sqlite3.connect(path);db.execute('PRAGMA journal_mode=DELETE');db.execute('PRAGMA synchronous=NORMAL')
    db.execute('CREATE TABLE target(ekey BLOB PRIMARY KEY, bytes INTEGER NOT NULL, priority INTEGER NOT NULL) WITHOUT ROWID')
    db.execute('CREATE TABLE local(prefix BLOB, bytes INTEGER, PRIMARY KEY(prefix,bytes)) WITHOUT ROWID')
    return db

def import_target(db,data,layout,cancel,notify):
    batch=[];eligible_count=0;hs=layout['header_size'];es=layout['entry_size'];mask=layout['eligible']
    sql='INSERT INTO target VALUES (?,?,?) ON CONFLICT(ekey) DO UPDATE SET bytes=CASE WHEN target.bytes=excluded.bytes THEN target.bytes ELSE -1 END, priority=min(target.priority,excluded.priority)'
    for i in range(layout['count']):
        if i%50000==0:
            if cancel.is_set():raise PlanError('Cancelled')
            notify('Reading target manifest: '+str(i)+' / '+str(layout['count']))
        if not (mask[i//8]&(1<<(7-i%8))):continue
        pos=hs+i*es;key=data[pos:pos+16];size=int.from_bytes(data[pos+16:pos+21],'big');priority=data[pos+21]-layout['base_priority']
        if size<=0:raise PlanError('Unsupported zero-size target entry')
        batch.append((key,size,priority));eligible_count+=1
        if len(batch)>=20000: db.executemany(sql,batch);batch=[]
    if batch:db.executemany(sql,batch)
    db.commit()
    if db.execute('SELECT count(*) FROM target WHERE bytes<0').fetchone()[0]:raise PlanError('Duplicate EKey size conflict')
    return eligible_count

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

def aggregate(db):
    # Count each full target EKey ONCE. Local journal matching is only 9-byte prefix + encoded size.
    match='EXISTS(SELECT 1 FROM local l WHERE l.prefix=substr(t.ekey,1,9) AND l.bytes=t.bytes)'
    prefix='EXISTS(SELECT 1 FROM local l WHERE l.prefix=substr(t.ekey,1,9))'
    row=db.execute('SELECT count(*),coalesce(sum(bytes),0),sum(CASE WHEN '+match+' THEN 1 ELSE 0 END),coalesce(sum(CASE WHEN '+match+' THEN bytes ELSE 0 END),0),sum(CASE WHEN NOT '+prefix+' THEN 1 ELSE 0 END),coalesce(sum(CASE WHEN NOT '+prefix+' THEN bytes ELSE 0 END),0),sum(CASE WHEN '+prefix+' AND NOT '+match+' THEN 1 ELSE 0 END),coalesce(sum(CASE WHEN '+prefix+' AND NOT '+match+' THEN bytes ELSE 0 END),0) FROM target t').fetchone()
    names=['unique_target_ekeys','target_encoded_bytes','prefix_and_size_candidates','candidate_encoded_bytes','no_observed_prefix_match','no_prefix_match_encoded_bytes','prefix_with_size_mismatch','size_mismatch_encoded_bytes']
    r=dict(zip(names,[int(x or 0) for x in row]))
    assert r['unique_target_ekeys']==r['prefix_and_size_candidates']+r['no_observed_prefix_match']+r['prefix_with_size_mismatch']
    assert r['target_encoded_bytes']==r['candidate_encoded_bytes']+r['no_prefix_match_encoded_bytes']+r['size_mismatch_encoded_bytes']
    # Independent reconciliation: LEFT JOIN with a unique local(prefix,bytes) key.
    independent=db.execute('SELECT count(*),coalesce(sum(t.bytes),0) FROM target t LEFT JOIN local l ON l.prefix=substr(t.ekey,1,9) AND l.bytes=t.bytes WHERE l.prefix IS NOT NULL').fetchone()
    if tuple(independent)!=(r['prefix_and_size_candidates'],r['candidate_encoded_bytes']):raise PlanError('Independent reconciliation failed')
    r['independent_join_check_passed']=True
    return r

def stable(snapshots,archives,files,folder):
    if sorted(folder.glob('*.idx'))!=files:raise PlanError('Local journal set changed during scan')
    for path,old in snapshots.items():
        if fingerprint(path)!=old:raise PlanError('Local journal changed during scan')
    for path,old in archives.values():
        if old is not None and fingerprint(path)!=old:raise PlanError('Data archive changed during scan')
        if old is None and path.exists():raise PlanError('Data archive appeared during scan')

def get_manifest(stage,config,target,cancel,notify):
    keys=config.get('download',[]);sizes=config.get('download-size',[])
    if len(keys)!=2 or len(sizes)!=2 or not all(f.HEX.fullmatch(k) for k in keys):raise PlanError('Unsupported download configuration')
    decoded_size,encoded_size=map(int,sizes)
    if not 0<decoded_size<=LIMIT or not 0<encoded_size<=LIMIT:raise PlanError('Manifest exceeds safe bound')
    base=stage/'cache'/'tpr'/'wow'/'data'
    if not base.resolve().is_relative_to(stage.resolve()):raise PlanError('Cache redirects outside the staging folder')
    base.mkdir(parents=True,exist_ok=True)
    encoded=base/keys[1];decoded=base/(keys[1]+'.decoded')
    if decoded.is_file():
        if decoded.stat().st_size!=decoded_size:raise PlanError('Cached decoded manifest size mismatch')
        d=decoded.read_bytes()
        if f.md5(d)!=keys[0]:raise PlanError('Cached decoded manifest hash mismatch; no cache was deleted')
        return d,'existing_decoded_cache'
    if encoded.is_file():
        if encoded.stat().st_size!=encoded_size:raise PlanError('Cached encoded manifest size mismatch; no cache was deleted')
        b=encoded.read_bytes();origin='existing_encoded_cache'
    else:
        origin='new_download_manifest_only';part=base/(keys[1]+'.v03-part')
        ok=False
        for host in target['servers']:
            if cancel.is_set():raise PlanError('Cancelled')
            try:
                url=f'{host}/tpr/wow/data/{keys[1][:2]}/{keys[1][2:4]}/{keys[1]}'
                opener=urllib.request.build_opener(f.Redirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
                with opener.open(urllib.request.Request(url,headers={'User-Agent':'WoW-Retail-Inventory/0.3'}),timeout=40) as src,part.open('wb') as dst:
                    n=0
                    while True:
                        if cancel.is_set():raise PlanError('Cancelled')
                        chunk=src.read(1024*1024)
                        if not chunk:break
                        n+=len(chunk)
                        if n>encoded_size:raise PlanError('Manifest download exceeded expected size')
                        dst.write(chunk);notify('Download manifest: '+str(round(n/1048576,1))+' / '+str(round(encoded_size/1048576,1))+' MiB')
                if n!=encoded_size:raise PlanError('Incomplete download manifest')
                b=part.read_bytes();ok=True;break
            except PlanError:raise
            except Exception:continue
        if not ok:raise PlanError('Download manifest could not be fetched from official HTTPS CDN')
    notify('Checking and decoding download manifest…')
    d=f.decode_blte(b,LIMIT)
    if len(d)!=decoded_size or f.md5(d)!=keys[0]:raise PlanError('Download manifest content hash or size mismatch')
    # Do not commit downloaded metadata to cache until verified.
    if origin=='new_download_manifest_only':part.replace(encoded)
    decoded.write_bytes(d)
    return d,origin

def run(report_path,build_info,cancel,notify):
    report_path=Path(report_path).resolve();stage=report_path.parent
    if report_path.stat().st_size>65536:raise PlanError('Staging report too large')
    previous=json.loads(report_path.read_text(encoding='utf-8-sig'))
    if previous.get('status')!='sample_downloaded_and_content_verified' or previous.get('product')!='wow' or previous.get('region')!='eu':raise PlanError('Select the successful v0.2 EU Retail staging report')
    build=previous['target_build_config'];cdn=previous['target_cdn_config'];version=previous['target_version']
    if not f.HEX.fullmatch(build) or not f.HEX.fullmatch(cdn) or not re.fullmatch(r'\d+\.\d+\.\d+\.\d+',version):raise PlanError('Invalid target identifiers')
    local=f.local_info(build_info);installation=local['installation']
    if stage==installation or stage.is_relative_to(installation) or installation.is_relative_to(stage):raise PlanError('Staging folder must be separate from the installed game')
    bi=Path(build_info);local_fingerprint=fingerprint(bi)
    # Only recognized locale names are retained; account/geolocation tags never enter reports.
    known=['deDE','enUS','esES','esMX','frFR','itIT','koKR','ptBR','ruRU','zhCN','zhTW']
    tags=f.one([r for r in f.rows(bi.read_text(encoding='utf-8-sig')) if r.get('Product')=='wow' and r.get('Active')=='1' and r.get('Branch')=='eu'])['Tags']
    locales=[l for l in known if re.search(r'(?<![A-Za-z])'+l+r'(?![A-Za-z])',tags)]
    if not locales:raise PlanError('Cannot determine installed locale; no default was guessed')
    notify('Reading the verified target build config…')
    if (stage/'build.config').stat().st_size>4*1024*1024:raise PlanError('Build config exceeds safety limit')
    if shutil.disk_usage(stage).free<1024**3:raise PlanError('At least 1 GiB free space is required in staging')
    config_raw=(stage/'build.config').read_bytes()
    if f.md5(config_raw)!=build.lower():raise PlanError('Staged build.config does not match the target build hash')
    config=config_fields(config_raw)
    if config.get('build-uid')!=['wow'] or not config.get('build-name',[''])[0].startswith('WOW-'+version.split('.')[-1]):raise PlanError('Build identity mismatch')
    target=f.discover();latest=target['version'];target.update(build=build,cdn=cdn,version=version)
    if cancel.is_set():raise PlanError('Cancelled')
    data,origin=get_manifest(stage,config,target,cancel,notify)
    layout=manifest_layout(data,locales)
    output=stage/('Inventory-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+os.urandom(3).hex());output.mkdir()
    db=open_db(output/'inventory-private.sqlite')
    db.set_progress_handler(lambda: 1 if cancel.is_set() else 0,10000)
    try:
        eligible_records=import_target(db,data,layout,cancel,notify);del data
        coverage,snapshots,archives,files,folder=import_local(db,installation,cancel,notify)
        notify('Reconciling indexed candidates; no archive contents are being verified…')
        summary=aggregate(db);stable(snapshots,archives,files,folder)
        if cancel.is_set():raise PlanError('Cancelled')
        if fingerprint(bi)!=local_fingerprint:raise PlanError('Installed build metadata changed during scan')
        partial=bool(coverage['uncovered_buckets'] or coverage['journal_problems'] or coverage['invalid_or_unavailable_archive_references'])
        result={'tool':'WoW Retail EU Inventory 0.3','status':'candidate_inventory_partial' if partial else 'candidate_inventory_completed','mode':'read_only_prefix_and_size_inventory_not_full_delta','checked_at_utc':datetime.now(timezone.utc).isoformat(),
                'local_version':local['version'],'target_version':version,'latest_version_observed':latest,'target_is_latest_observed':version==latest,
                'product':'wow','region':'eu','platform':'Windows x64','locales':locales,'manifest_origin':origin,'download_manifest_content_hash_verified':True,
                'manifest_all_records':layout['count'],'filtered_manifest_records':eligible_records,'duplicate_target_records':eligible_records-summary['unique_target_ekeys'],
                'summary':summary,'index_coverage':coverage,'comparison_has_index_coverage_gaps':partial,'optional_content_included':layout['optional_tags_included'],
                'installed_files_changed':False,'active_journals_resolved':False,'index_checksums_validated':False,'archive_payload_hashes_verified':False,
                'limitations':['Candidate match means 9-byte EKey prefix plus encoded-size match with a structurally valid journal record and archive bounds, NOT full content verification.',
                               'All readable historical journal generations are included; active journals were not resolved via shmem.',
                               'No prefix match is an inventory observation, NOT proof that data is absent or must be downloaded.',
                               'Optional content, all priorities and installed locales are included. This is not a minimal playable download calculation.',
                               'Encoded byte totals are whole-object totals, NOT a binary patch size. Reusable alternate encodings are not evaluated.',
                               'No CASC update writer, patch application or rollback engine is implemented.'],
                'sources':['https://wowdev.wiki/TACT','https://wowdev.wiki/CASC','https://github.com/wowdev/TACTSharp']}
        (output/'Retail-Inventory-to-share.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        return result,output
    except sqlite3.OperationalError:
        if cancel.is_set():raise PlanError('Cancelled')
        raise
    finally:db.close()
