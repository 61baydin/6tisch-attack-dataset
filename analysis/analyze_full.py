#!/usr/bin/env python3
"""Comprehensive per-(scale, density, placement, attack) F1 on the new 84-log
dataset, feeding paper Tables IX (placement), X (placement pooled), XI (scale),
XII (ablation a1 vs a5).

Methodology mirrors eval_placement_a5.py:
  group-aware F1 = LeaveOneGroupOut over group=(run,node), averaged over folds
                   whose test set contains attacker rows (RF & LR).
  naive F1       = StratifiedKFold(5) (per-node leakage; this is the a1 number
                   the ablation uses).
Identity columns (timestamp,node_id,parent_id) excluded.
Writes new_placement_f1.csv (per attack) and prints pooled-by-placement.
"""
import re, glob, warnings
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler

ATTACKS = ['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
DISP = {'blackhole':'Blackhole','decrease':'Decreased Rank','dis':'DIS Flooding',
        'flooding':'App Flooding','shared-slot':'TSCH Shared','slot-exhaustion':'6P Exhaust',
        'timekeep':'TSCH Desync'}
LR = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
FEAT_IDX = list(range(3,16))  # rank..app_packet_count (drop ts,node,parent)

def parse(fn):
    out=[]
    for ln in open(fn):
        m=LR.search(ln)
        if not m: continue
        v=[int(x) for x in m.group(1).split(',') if x.strip()!='']
        if len(v)>=18: out.append(v[:18])
    return out

def load(scale, density, placement, attacks):
    rows=[]
    for atk in attacks:
        for fn in glob.glob(f'2026-06-0[34]_*_{atk}-n{scale}-{placement}-a{density}-w*.log'):
            if Path(fn).name.startswith('cooja_'): continue
            rid=Path(fn).stem
            for v in parse(fn): rows.append(v+[rid])
    if not rows: return None
    a=np.array(rows, dtype=object)
    feats=np.array([[r[i] for i in FEAT_IDX] for r in rows], dtype=float)
    is_atk=np.array([r[16] for r in rows], dtype=int)
    run=np.array([r[18] for r in rows]); node=np.array([r[1] for r in rows])
    grp=np.array([f"{run[i]}|{node[i]}" for i in range(len(rows))])
    return feats, is_atk, grp

def group_f1(X,y,g,model_ctor):
    atkg=set(g[y==1])
    if not atkg: return 0.0
    fs=[]
    for tr,te in LeaveOneGroupOut().split(X,y,g):
        if not (set(g[te])&atkg): continue
        if len(np.unique(y[tr]))<2:  # a1: holding out the lone attacker leaves
            fs.append(0.0); continue # one class -> degenerate, F1=0 by construction
        m=model_ctor(); m.fit(X[tr],y[tr]); fs.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    return float(np.mean(fs)) if fs else 0.0

def naive_f1(X,y,model_ctor):
    fs=[]
    for tr,te in StratifiedKFold(5,shuffle=True,random_state=42).split(X,y):
        if len(np.unique(y[tr]))<2: continue
        m=model_ctor(); m.fit(X[tr],y[tr]); fs.append(f1_score(y[te],m.predict(X[te]),zero_division=0))
    return float(np.mean(fs)) if fs else 0.0

RF=lambda: RandomForestClassifier(n_estimators=100,max_depth=10,class_weight='balanced',n_jobs=-1,random_state=42)
LRc=lambda: LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)

recs=[]
for scale in ['21','31']:
    for density in ['5','1']:
        print(f"\n{'='*70}\n SCALE {scale} | a{density}\n{'='*70}")
        print(f"{'Placement':<8}{'Attack':<16}{'RFgrp':>7}{'RFnaive':>8}{'LRgrp':>7}{'LRnaive':>8}")
        for pl in ['core','mid','edge']:
            for atk in ATTACKS:
                d=load(scale,density,pl,[atk])
                if d is None: continue
                X,y,g=d; X=StandardScaler().fit_transform(X)
                rg=group_f1(X,y,g,RF); rn=naive_f1(X,y,RF)
                lg=group_f1(X,y,g,LRc); ln=naive_f1(X,y,LRc)
                recs.append(dict(scale=scale,density=density,placement=pl,attack=atk,
                                 rf_group=rg,rf_naive=rn,lr_group=lg,lr_naive=ln))
                print(f"{pl:<8}{DISP[atk]:<16}{rg:>7.3f}{rn:>8.3f}{lg:>7.3f}{ln:>8.3f}",flush=True)
            # pooled across attacks for this placement
            d=load(scale,density,pl,ATTACKS)
            if d is not None:
                X,y,g=d; X=StandardScaler().fit_transform(X)
                rg=group_f1(X,y,g,RF); lg=group_f1(X,y,g,LRc)
                recs.append(dict(scale=scale,density=density,placement=pl,attack='POOLED',
                                 rf_group=rg,rf_naive=np.nan,lr_group=lg,lr_naive=np.nan))
                print(f"{pl:<8}{'== POOLED ==':<16}{rg:>7.3f}{'':>8}{lg:>7.3f}",flush=True)

pd.DataFrame(recs).to_csv('new_placement_f1.csv',index=False)
print("\nWrote new_placement_f1.csv")
