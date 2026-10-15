"""Offline target DL selection; same filters as v0.3. No network code."""

from indexes import PlanError

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
