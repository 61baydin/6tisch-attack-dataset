#!/usr/bin/env python3
"""a1 (single-attacker) naive row-level RF F1, attack x placement x scale.
From dataset_v3/single/logs a1 runs; StratifiedKFold k=5 (no group = leakage).
Output: f1_21 / f1_31 literals ready to paste into gen_a1_heatmap.py."""
import re,glob,warnings,collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
ATT=['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
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
def canon(a,sc,pl):
    fs=[f for f in glob.glob(f'dataset_v3/single/logs/*_{a}-n{sc}-{pl}-a1-w*.log') if 'cooja' not in f and parse(f)]
    return sorted(fs,key=lambda f:f.split('_')[1]+f.split('_')[2])[-1] if fs else None
def load(a,sc,pl):
    f=canon(a,sc,pl)
    if not f: return None
    df=pd.DataFrame([v for v in parse(f)],columns=COLS)
    df=df[df.parent_id!=0].sort_values(['node_id','timestamp']).reset_index(drop=True)
    lut=collections.defaultdict(list)
    for t,nid,rk in zip(df.timestamp,df.node_id,df['rank']): lut[nid].append((t,rk))
    for k in lut: lut[k].sort()
    inc=np.full(len(df),np.nan)
    for idx,t,pid,rk in zip(df.index,df.timestamp,df.parent_id,df['rank']):
        if pid in lut:
            arr=[r for tt,r in lut[pid] if tt<=t]
            if arr: inc[idx]=rk-arr[-1]
    df['rank_increase']=pd.Series(inc,index=df.index).fillna(0)
    df['d_app']=df.groupby('node_id')['app_packet_count'].diff().fillna(0).clip(lower=0)
    return df
def f1_naive(df,atype):
    X=StandardScaler().fit_transform(df[FEAT].values.astype(float))
    y=((df.attack_type.values==atype)&(df.is_attacker.values==1)).astype(int)
    if len(set(y))<2: return None
    fs=[]
    for tr,te in StratifiedKFold(5,shuffle=True,random_state=42).split(X,y):
        m=RandomForestClassifier(n_estimators=100,max_depth=10,class_weight='balanced',n_jobs=-1,random_state=42)
        m.fit(X[tr],y[tr]); fs.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    return float(np.mean(fs))
for sc in ['21','31']:
    print(f"f1_{sc} = [")
    for a in ATT:
        row=[]
        for pl in ['core','mid','edge']:
            df=load(a,sc,pl)
            v=f1_naive(df,ATYPE[a]) if df is not None else None
            row.append('%.3f'%v if v is not None else 'None')
        print("    [%s],"%', '.join(row))
    print("]")
