#!/usr/bin/env python3
"""Fresh analysis for the new 20-column dataset (2026-06-14/15).
- Canonical log selection: for each cell, the LATEST 20-column log (the
  18-column flooding and the old broken-bcast shared logs are discarded).
- Features: 13 base + forward_ratio + bcast_tx + (derived) rank_increase.
- Labels: v[18]=is_attacker, v[19]=attack_type (20-column schema).
- Per-attack binary F1: pooled placements, a5, group-aware LOGO + naive.
"""
import re,glob,warnings,collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler

ATT=['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
DISP={'blackhole':'Blackhole','decrease':'Decreased Rank','dis':'DIS Flooding','flooding':'App Flooding','shared-slot':'Shared Cell','slot-exhaustion':'6P Exhaust','timekeep':'TSCH Desync'}
ATYPE={a:i for i,a in enumerate(ATT,1)}
BASE=['rank','buf_occupancy','dio_sent','dao_sent','dis_sent','nbr_count','tx_slot_count','parent_switch_count','rssi','route_count','delta_tx','delta_rx','app_packet_count']
NEW=['forward_ratio','bcast_tx']
COLS=['timestamp','node_id','parent_id']+BASE+NEW+['is_attacker','attack_type']
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")

def parse(fn):
    out=[]
    for ln in open(fn):
        m=RX.search(ln)
        if not m: continue
        v=[int(x) for x in m.group(1).split(',') if x.strip()]
        if len(v)==20: out.append(v)
    return out

def canonical(attack, scale, pl, ac):
    fs=[f for f in glob.glob(f'dataset_v3/single/logs/*_{attack}-n{scale}-{pl}-a{ac}-w*.log') if 'cooja' not in f]
    fs=[f for f in fs if parse(f)]
    if not fs: return None
    return sorted(fs, key=lambda f: f.split('_')[1]+f.split('_')[2])[-1]

def load_attack(attack, scale, ac='5'):
    rows=[]
    for pl in ['core','mid','edge']:
        f=canonical(attack,scale,pl,ac)
        if not f: continue
        for v in parse(f): rows.append(v+[Path(f).stem])
    if not rows: return None
    df=pd.DataFrame(rows,columns=COLS+['run_id'])
    df=df[df.parent_id!=0].sort_values(['run_id','node_id','timestamp']).reset_index(drop=True)
    inc=np.full(len(df),np.nan)
    for rid,g in df.groupby('run_id'):
        lut=collections.defaultdict(list)
        for t,nid,rk in zip(g.timestamp,g.node_id,g['rank']): lut[nid].append((t,rk))
        for k in lut: lut[k].sort()
        for idx,t,pid,rk in zip(g.index,g.timestamp,g.parent_id,g['rank']):
            pr=None
            if pid in lut:
                arr=[r for tt,r in lut[pid] if tt<=t]
                if arr: pr=arr[-1]
            if pr is not None: inc[idx]=rk-pr
    df['rank_increase']=pd.Series(inc,index=df.index).fillna(0)
    # Delta: app_packet_count rate (resolves flooding) - per-run, per-node diff
    df['d_app']=df.groupby(['run_id','node_id'])['app_packet_count'].diff().fillna(0).clip(lower=0)
    return df

def binF1(df, atype, feats):
    X=StandardScaler().fit_transform(df[feats].values.astype(float))
    y=((df.attack_type.values==atype)&(df.is_attacker.values==1)).astype(int)
    g=(df.run_id.astype(str)+'|'+df.node_id.astype(str)).values
    grp=set(g[y==1])
    if len(set(y))<2 or len(grp)<2: return None
    out={}
    for name,mk in [('LR',lambda:LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)),
                    ('RF',lambda:RandomForestClassifier(n_estimators=100,max_depth=10,class_weight='balanced',n_jobs=-1,random_state=42))]:
        fg=[]
        for tr,te in LeaveOneGroupOut().split(X,y,g):
            if not (set(g[te])&grp): continue
            if len(np.unique(y[tr]))<2: continue
            m=mk(); m.fit(X[tr],y[tr]); fg.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
        fn=[]
        for tr,te in StratifiedKFold(5,shuffle=True,random_state=42).split(X,y):
            m=mk(); m.fit(X[tr],y[tr]); fn.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
        out[name]=(float(np.mean(fg)) if fg else 0.0, float(np.mean(fn)))
    return out

def main():
    FEAT_FULL=BASE+NEW+['rank_increase','d_app']
    print("=== NEW DATASET ANALYSIS (a5, pooled, canonical 20-column) ===")
    print("Features: 13 base + forward_ratio + bcast_tx + rank_increase + d_app (17)")
    for scale in ['21','31']:
        print(f"\n##### {scale}-mote a5 #####")
        print(f"{'Attack':15}{'LR grp':>9}{'RF grp':>9}{'LR naive':>9}{'RF naive':>9}",flush=True)
        print('-'*51)
        gs={'LR':[],'RF':[]}
        for atk in ATT:
            df=load_attack(atk,scale,'5')
            if df is None: print(f"{DISP[atk]:15}{'(no log)':>9}",flush=True); continue
            r=binF1(df,ATYPE[atk],FEAT_FULL)
            if r is None: print(f"{DISP[atk]:15}{'(insufficient)':>9}",flush=True); continue
            print(f"{DISP[atk]:15}{r['LR'][0]:>9.2f}{r['RF'][0]:>9.2f}{r['LR'][1]:>9.2f}{r['RF'][1]:>9.2f}",flush=True)
            gs['LR'].append(r['LR'][0]); gs['RF'].append(r['RF'][0])
        if gs['LR']:
            print('-'*51)
            print(f"{'AVERAGE':15}{np.mean(gs['LR']):>9.2f}{np.mean(gs['RF']):>9.2f}",flush=True)

if __name__=='__main__':
    main()
