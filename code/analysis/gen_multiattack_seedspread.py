#!/usr/bin/env python3
"""Coklu-saldiri: seed-basina (42,43,44) ikili tespit F1 ve cok-sinifli makro-F1,
ardindan 3 seed uzerinden ortalama +/- std. Grup-farkinda (StratifiedGroupKFold k=5,
grup=run|node), sinif-dengeli LR. Ayrica 36-kosu havuzlanmis tek deger de yazilir."""
import re, glob, warnings, collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
FAM={0:'NONE',1:'Blackhole',2:'Decrease',3:'DIS',4:'Flooding',5:'Shared',6:'6P',7:'Desync'}
BASE=['rank','buf_occupancy','dio_sent','dao_sent','dis_sent','nbr_count','tx_slot_count',
      'parent_switch_count','rssi','route_count','delta_tx','delta_rx','app_packet_count']
COLS=['timestamp','node_id','parent_id']+BASE+['forward_ratio','bcast_tx','is_attacker','attack_type']
FEAT=BASE+['forward_ratio','bcast_tx','rank_increase','d_app']
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
def parse(fn):
    o=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20: o.append(v)
    return o
def build(files):
    rows=[]
    for fn in files:
        rid=Path(fn).stem
        for v in parse(fn): rows.append(v+[rid])
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
    return df
def evaluate(df):
    X=StandardScaler().fit_transform(df[FEAT].values.astype(float))
    g=(df.run_id.astype(str)+'|'+df.node_id.astype(str)).values
    cv=StratifiedGroupKFold(5,shuffle=True,random_state=42)
    # ikili
    yb=df.is_attacker.values.astype(int); ypb=np.empty_like(yb)
    for tr,te in cv.split(X,yb,g):
        m=LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)
        m.fit(X[tr],yb[tr]); ypb[te]=m.predict(X[te])
    binF1=f1_score(yb,ypb,zero_division=0)
    # cok-sinifli
    ym=df.attack_type.values; ypm=np.empty_like(ym)
    for tr,te in cv.split(X,ym,g):
        m=LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)
        m.fit(X[tr],ym[tr]); ypm[te]=m.predict(X[te])
    labels=sorted(set(ym)); macro=f1_score(ym,ypm,labels=labels,average='macro')
    return binF1,macro
allf=[f for f in glob.glob('dataset_v3/multiattack/logs/*.log') if 'cooja' not in f]
print(f"toplam multiattack log: {len(allf)}")
bins=[];macros=[]
for s in ['s42','s43','s44']:
    sf=[f for f in allf if f'-{s}-' in f]
    df=build(sf); b,m=evaluate(df)
    bins.append(b);macros.append(m)
    print(f"  seed {s[1:]}: {len(sf)} kosu | ikili F1={b:.3f} | makro-F1={m:.3f}")
print(f"\n3-seed ORTALAMA +/- STD:")
print(f"  ikili tespit F1 = {np.mean(bins):.3f} +/- {np.std(bins):.3f}")
print(f"  cok-sinifli makro-F1 = {np.mean(macros):.3f} +/- {np.std(macros):.3f}")
# havuzlanmis (referans)
b,m=evaluate(build(allf))
print(f"\n36-kosu havuzlanmis (referans): ikili={b:.3f} makro={m:.3f}")
