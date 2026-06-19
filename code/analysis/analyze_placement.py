#!/usr/bin/env python3
"""Per-placement (core/mid/edge) ayrintili F1, yeni kanonik 20-sutun dataset.
Her hucre tek kanonik log; kosu-ici grup-farkinda LOGO. 17 oznitelik
(13 taban + forward_ratio + bcast_tx + rank_increase + d_app). LR ve RF.
"""
import re,glob,warnings,collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler

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
        if not m: continue
        v=[int(x) for x in m.group(1).split(',') if x.strip()]
        if len(v)==20: out.append(v)
    return out

def canonical(attack,scale,pl,ac='5'):
    fs=[f for f in glob.glob(f'dataset_v3/single/logs/*_{attack}-n{scale}-{pl}-a{ac}-w*.log') if 'cooja' not in f]
    fs=[f for f in fs if parse(f)]
    if not fs: return None
    return sorted(fs,key=lambda f:f.split('_')[1]+f.split('_')[2])[-1]

def load_one(attack,scale,pl):
    f=canonical(attack,scale,pl)
    if not f: return None
    df=pd.DataFrame([v for v in parse(f)],columns=COLS)
    df=df[df.parent_id!=0].sort_values(['node_id','timestamp']).reset_index(drop=True)
    # rank_increase
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

def f1_one(df,atype,model):
    X=StandardScaler().fit_transform(df[FEAT].values.astype(float))
    y=((df.attack_type.values==atype)&(df.is_attacker.values==1)).astype(int)
    g=df.node_id.astype(str).values
    grp=set(g[y==1])
    if len(set(y))<2 or len(grp)<2: return None
    fg=[]
    for tr,te in LeaveOneGroupOut().split(X,y,g):
        if not (set(g[te])&grp): continue
        if len(np.unique(y[tr]))<2: continue
        if model=='LR': m=LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)
        else: m=RandomForestClassifier(n_estimators=100,max_depth=10,class_weight='balanced',n_jobs=-1,random_state=42)
        m.fit(X[tr],y[tr]); fg.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    return float(np.mean(fg)) if fg else 0.0

def main():
    for model in ['LR','RF']:
        for scale in ['21','31']:
            print(f"\n##### {model} grup-farkinda | {scale}-mote a5 | per-placement #####",flush=True)
            print(f"{'Saldiri':15}{'core':>7}{'mid':>7}{'edge':>7}{'ORT':>7}",flush=True)
            print('-'*43)
            allv=[]
            for atk in ATT:
                vals=[]
                for pl in ['core','mid','edge']:
                    df=load_one(atk,scale,pl)
                    v=f1_one(df,ATYPE[atk],model) if df is not None else None
                    vals.append(v)
                disp=['%.2f'%v if v is not None else ' -- ' for v in vals]
                ok=[v for v in vals if v is not None]
                ort=np.mean(ok) if ok else float('nan')
                if ok: allv.append(ort)
                print(f"{DISP[atk]:15}{disp[0]:>7}{disp[1]:>7}{disp[2]:>7}{ort:>7.2f}",flush=True)
            print('-'*43)
            print(f"{'GENEL':15}{'':>21}{np.mean(allv):>7.2f}",flush=True)

if __name__=='__main__':
    main()
