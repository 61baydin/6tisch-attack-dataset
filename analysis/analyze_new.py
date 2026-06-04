#!/usr/bin/env python3
"""Gate analysis on the NEW 84-log dataset (2026-06-03/04, naming
<attack>-n21/n31-<placement>-a{1,5}-w<W>).

Mirrors eval_placement_a5.py methodology (StratifiedGroupKFold/LOGO,
group=(run,node), identity columns dropped) but RF+LR only so it needs
only sklearn. Reports per attack x scale: group-aware F1 (the convergence
metric, must be <=0.90) and naive F1 (leakage gap).
"""
import re, glob, warnings
from pathlib import Path
import numpy as np
import pandas as pd
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler

ATTACKS = ['blackhole','decrease','dis','flooding','shared-slot',
           'slot-exhaustion','timekeep']
DISPLAY = {'blackhole':'Blackhole','decrease':'Decreased Rank',
           'dis':'DIS Flooding','flooding':'App Flooding',
           'shared-slot':'TSCH Shared Cell','slot-exhaustion':'6P Cell Exhaust',
           'timekeep':'TSCH Desync'}
LR = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
FEAT = ['rank','buf_occupancy','dio_sent','dao_sent','dis_sent','nbr_count',
        'tx_slot_count','parent_switch_count','rssi','route_count','delta_tx',
        'delta_rx','app_packet_count']
COLS = ['timestamp','node_id','parent_id','rank','buf_occupancy','dio_sent',
        'dao_sent','dis_sent','nbr_count','tx_slot_count','parent_switch_count',
        'rssi','route_count','delta_tx','delta_rx','app_packet_count',
        'is_attacker','attack_type']

def parse(fn):
    out=[]
    for ln in open(fn):
        m=LR.search(ln)
        if not m: continue
        v=[int(x) for x in m.group(1).split(',') if x.strip()!='']
        if len(v)>=18: out.append(v[:18])
    return out

def load(atk, scale, atkcount):
    files=[]
    for pl in ['core','mid','edge']:
        files += sorted(glob.glob(f'2026-06-0[34]_*_{atk}-n{scale}-{pl}-a{atkcount}-w*.log'))
    files=[f for f in files if not Path(f).name.startswith('cooja_')]
    rows=[]
    for fn in files:
        for v in parse(fn): rows.append(v+[Path(fn).stem])
    return pd.DataFrame(rows, columns=COLS+['run_id']), len(files)

def grpf1(X,y,g):
    """group-aware F1: LOGO, only folds whose test set contains attacker rows."""
    atkg=set(g[y==1])
    if not atkg: return 0.0
    fg=[]
    for tr,te in LeaveOneGroupOut().split(X,y,g):
        if not (set(g[te]) & atkg): continue
        m=RandomForestClassifier(n_estimators=100,max_depth=10,
              class_weight='balanced',n_jobs=-1,random_state=42)
        m.fit(X[tr],y[tr]); fg.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    return float(np.mean(fg)) if fg else 0.0

def naivef1(X,y):
    fn=[]
    for tr,te in StratifiedKFold(5,shuffle=True,random_state=42).split(X,y):
        m=RandomForestClassifier(n_estimators=100,max_depth=10,
              class_weight='balanced',n_jobs=-1,random_state=42)
        m.fit(X[tr],y[tr]); fn.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    return float(np.mean(fn))

for scale in ['21','31']:
    print(f"\n{'='*64}\n  SCALE {scale}-mote  (a5 placement cells, RF binary)\n{'='*64}")
    print(f"{'Attack':<18}{'logs':>5}{'recs':>8}{'atk':>7}{'GroupF1':>9}{'NaiveF1':>9}{'Delta':>8}")
    print('-'*64)
    for atk in ATTACKS:
        df,nf = load(atk, scale, 5)
        if df.empty:
            print(f"{DISPLAY[atk]:<18}{nf:>5}  (log yok)"); continue
        X=StandardScaler().fit_transform(df[FEAT].values)
        y=((df.attack_type.values!=0)&(df.is_attacker.values==1)).astype(int)
        g=(df.run_id.astype(str)+'|'+df.node_id.astype(str)).values
        gf=grpf1(X,y,g); nf1=naivef1(X,y)
        flag=' <<<<<' if gf>0.90 else ''
        print(f"{DISPLAY[atk]:<18}{nf:>5}{len(df):>8}{int(y.sum()):>7}"
              f"{gf:>9.3f}{nf1:>9.3f}{nf1-gf:>+8.3f}{flag}")
