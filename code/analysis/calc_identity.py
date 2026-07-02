#!/usr/bin/env python3
"""New dataset identity ablation: RF, base(17) vs +identity (node_id,parent_id,np_pair),
group(LOGO) vs naive(SKF), per-attack, 21-mote a5 pooled."""
import re,glob,warnings,collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
ATT=['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
DISP={'blackhole':'Blackhole','decrease':'Decreased Rank','dis':'DIS Flooding','flooding':'Application Flooding','shared-slot':'TSCH Shared Cell','slot-exhaustion':'6P Cell Exhaustion','timekeep':'TSCH Desync'}
ATYPE={a:i for i,a in enumerate(ATT,1)}
BASE=['rank','buf_occupancy','dio_sent','dao_sent','dis_sent','nbr_count','tx_slot_count','parent_switch_count','rssi','route_count','delta_tx','delta_rx','app_packet_count']
NEW=['forward_ratio','bcast_tx']
COLS=['timestamp','node_id','parent_id']+BASE+NEW+['is_attacker','attack_type']
FEAT=BASE+NEW+['rank_increase','d_app']
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
def parse(fn):
    out=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20: out.append(v)
    return out
def canon(a,pl):
    fs=[f for f in glob.glob(f'dataset_v3/single/logs/*_{a}-n21-{pl}-a5-w*.log') if 'cooja' not in f and parse(f)]
    return sorted(fs,key=lambda f:f.split('_')[1]+f.split('_')[2])[-1] if fs else None
def load(a):
    rows=[]
    for pl in ['core','mid','edge']:
        f=canon(a,pl)
        if f:
            for v in parse(f): rows.append(v+[Path(f).stem])
    df=pd.DataFrame(rows,columns=COLS+['run_id'])
    df=df[df.parent_id!=0].sort_values(['run_id','node_id','timestamp']).reset_index(drop=True)
    inc=np.full(len(df),np.nan)
    for rid,g in df.groupby('run_id'):
        lut=collections.defaultdict(list)
        for t,nid,rk in zip(g.timestamp,g.node_id,g['rank']): lut[nid].append((t,rk))
        for k in lut: lut[k].sort()
        for idx,t,pid,rk in zip(g.index,g.timestamp,g.parent_id,g['rank']):
            if pid in lut:
                arr=[r for tt,r in lut[pid] if tt<=t]
                if arr: inc[idx]=rk-arr[-1]
    df['rank_increase']=pd.Series(inc,index=df.index).fillna(0)
    df['d_app']=df.groupby(['run_id','node_id'])['app_packet_count'].diff().fillna(0).clip(lower=0)
    df['np_pair']=df.node_id*1000+df.parent_id
    return df
def rf(): return RandomForestClassifier(n_estimators=100,max_depth=10,class_weight='balanced',n_jobs=-1,random_state=42)
def evalset(df,feats,atype):
    X=StandardScaler().fit_transform(df[feats].values.astype(float))
    y=((df.attack_type.values==atype)&(df.is_attacker.values==1)).astype(int)
    g=(df.run_id.astype(str)+'|'+df.node_id.astype(str)).values
    grp=set(g[y==1])
    if len(set(y))<2 or len(grp)<2: return None,None
    fg=[]
    for tr,te in LeaveOneGroupOut().split(X,y,g):
        if not(set(g[te])&grp): continue
        if len(np.unique(y[tr]))<2: continue
        m=rf(); m.fit(X[tr],y[tr]); fg.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    fn=[]
    for tr,te in StratifiedKFold(5,shuffle=True,random_state=42).split(X,y):
        m=rf(); m.fit(X[tr],y[tr]); fn.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    return (float(np.mean(fg)) if fg else 0.0), float(np.mean(fn))
print("Attack & base_grp & base_naive & +id_grp & +id_naive")
bg=[];bn=[];ig=[];ino=[]
for a in ATT:
    df=load(a)
    g1,n1=evalset(df,FEAT,ATYPE[a])
    g2,n2=evalset(df,FEAT+['node_id','parent_id','np_pair'],ATYPE[a])
    if g1 is None: continue
    bg.append(g1);bn.append(n1);ig.append(g2);ino.append(n2)
    print(f"{DISP[a]:20} & {g1:.2f} & {n1:.2f} && {g2:.2f} & {n2:.2f} \\\\")
print(f"Average & {np.mean(bg):.2f} & {np.mean(bn):.2f} && {np.mean(ig):.2f} & {np.mean(ino):.2f}")
