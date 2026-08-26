#!/usr/bin/env python3
"""Tek-saldirganli (a1) hucreler: naif satir-duzeyi F1 ve grup-farkinda kontrol.

Cikti:
  core_a1_naive.csv   hucre basina (olcek, saldiri, yerlesim) naif RF/LR F1  -> Sekil a1_heatmap
  core_a1_group.csv   olcek+saldiri basina LOGO(dugum) F1                    -> "a1 grup-farkinda cokuyor" iddiasi

Protokol Bolum V-C ile ayni: RandomForest(100 agac, max_depth=10, class_weight='balanced'),
LogisticRegression(max_iter=1000, class_weight='balanced'), random_state=42,
naif bolme StratifiedKFold(k=5), grup-farkinda bolme LeaveOneGroupOut(node_id).
"""
import glob, collections, warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, LeaveOneGroupOut
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from eval_window_sweep import ATT, ATYPE, DISP, FEAT, COLS, parse

def mk(k):
    return (LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42) if k == 'LR'
            else RandomForestClassifier(n_estimators=100, max_depth=10, class_weight='balanced',
                                        n_jobs=4, random_state=42))

def load(fn):
    rows = parse(fn)
    if not rows:
        return None
    df = pd.DataFrame(rows, columns=COLS).sort_values(['node_id', 'timestamp']).reset_index(drop=True)
    df = df[df.parent_id != 0].reset_index(drop=True)
    lut = collections.defaultdict(list)
    for t, nid, rk in zip(df.timestamp, df.node_id, df['rank']):
        lut[nid].append((t, rk))
    for k in lut:
        lut[k].sort()
    inc = np.full(len(df), np.nan)
    for idx, t, pid, rk in zip(df.index, df.timestamp, df.parent_id, df['rank']):
        if pid in lut:
            arr = [r for tt, r in lut[pid] if tt <= t]
            if arr:
                inc[idx] = rk - arr[-1]
    df['rank_increase'] = pd.Series(inc, index=df.index).fillna(0)
    df['d_app'] = df.groupby('node_id')['app_packet_count'].diff().fillna(0).clip(lower=0)
    return df

def canon_a1(scale, a, pl):
    fs = [f for f in glob.glob(f'dataset_v3/single/logs/*_{a}-n{scale}-{pl}-a1-w*.log')
          if 'cooja' not in f and parse(f)]
    return sorted(fs)[-1] if fs else None

def score(X, y, groups, kind, grouped):
    out = []
    it = LeaveOneGroupOut().split(X, y, groups) if grouped else \
         StratifiedKFold(5, shuffle=True, random_state=42).split(X, y)
    for tr, te in it:
        if len(np.unique(y[tr])) < 2 or y[te].sum() == 0:
            continue
        sc = StandardScaler().fit(X[tr]); m = mk(kind); m.fit(sc.transform(X[tr]), y[tr])
        out.append(f1_score(y[te], m.predict(sc.transform(X[te])), zero_division=0))
    return float(np.mean(out)) if out else float('nan')

cells, grp = [], []
for scale in ['21', '31']:
    for a in ATT:
        frames = []
        for pl in ['core', 'mid', 'edge']:
            f = canon_a1(scale, a, pl)
            if f is None:
                print('  eksik hucre:', scale, a, pl, flush=True); continue
            d = load(f)
            X = d[FEAT].values.astype(float)
            y = ((d.attack_type.values == ATYPE[a]) & (d.is_attacker.values == 1)).astype(int)
            cells.append(dict(scale=int(scale), attack=DISP[a], placement=pl,
                              RF_naive=round(score(X, y, None, 'RF', False), 4),
                              LR_naive=round(score(X, y, None, 'LR', False), 4),
                              n_attacker_rows=int(y.sum())))
            print(cells[-1], flush=True)
            d = d.copy(); d['run_id'] = pl; frames.append(d)
        if frames:
            d = pd.concat(frames, ignore_index=True)
            X = d[FEAT].values.astype(float)
            y = ((d.attack_type.values == ATYPE[a]) & (d.is_attacker.values == 1)).astype(int)
            g = np.array([f'{r}|{n}' for r, n in zip(d.run_id.values, d.node_id.values)])
            grp.append(dict(scale=int(scale), attack=DISP[a],
                            group_f1=round(score(X, y, g, 'RF', True), 4),
                            n_attacker_groups=len(set(g[y == 1]))))
            print('  GROUP', grp[-1], flush=True)
pd.DataFrame(cells).to_csv('core_a1_naive.csv', index=False)
pd.DataFrame(grp).to_csv('core_a1_group.csv', index=False)
print('yazildi: core_a1_naive.csv, core_a1_group.csv')
