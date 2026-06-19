#!/usr/bin/env python3
"""Yeni dataset RF Gini oznitelik onemi, saldiri-basina ikili, 21-mote a5,
17 oznitelik (yeni forward_ratio/bcast_tx + turetilmis rank_increase/d_app dahil)."""
import re,glob,warnings,collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
ATT=['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
DISP={'blackhole':'Blackhole','decrease':'Decreased Rank','dis':'DIS Flooding','flooding':'App Flooding','shared-slot':'Shared Cell','slot-exhaustion':'6P Exhaust','timekeep':'TSCH Desync'}
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
for atk in ATT:
    rows=[]
    for pl in ['core','mid','edge']:
        f=canon(atk,pl)
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
    X=df[FEAT].values.astype(float)
    y=((df.attack_type.values==ATYPE[atk])&(df.is_attacker.values==1)).astype(int)
    if len(set(y))<2: print(f'{DISP[atk]}: yetersiz'); continue
    rf=RandomForestClassifier(n_estimators=100,max_depth=10,class_weight='balanced',n_jobs=-1,random_state=42)
    rf.fit(X,y); imp=rf.feature_importances_*100
    top=sorted(zip(FEAT,imp),key=lambda x:-x[1])[:3]
    print(f'{DISP[atk]:16}'+', '.join(f'{f} {p:.0f}%' for f,p in top))
