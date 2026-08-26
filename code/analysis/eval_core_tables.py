#!/usr/bin/env python3
"""Makalenin cekirdek tablolarini yeniden uretir (hakem R3-6 yeniden uretilebilirlik).

Uretilen tablolar:
  tab:f1_main            -> core_f1_main.csv           (olcek basina LOGO(run,node) LR F1)
  tab:beyond_f1          -> core_beyond_f1.csv         (P/R/MCC + saldirgansiz kosuda FPR)
  tab:identity_ablation  -> core_identity_ablation.csv (RF, temel vs +kimlik, grup vs naif)
  tab:placement/tab:scale-> core_placement.csv         (hucre basina LOGO(node) RF/LR F1)

Protokol Bolum V-C ile ayni: LogisticRegression(max_iter=1000, class_weight='balanced'),
RandomForestClassifier(100 agac, max_depth=10, class_weight='balanced'), random_state=42,
grup anahtari (run_id, node_id), StandardScaler her fold'da egitim bolumune uydurulur.

Kullanim:  python3 eval_core_tables.py [f1|pr|identity|placement|all]
"""
import sys, glob, collections, warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold
from sklearn.metrics import f1_score, precision_score, recall_score, matthews_corrcoef
from sklearn.preprocessing import StandardScaler
from eval_window_sweep import ATT, ATYPE, DISP, FEAT, COLS, parse, load_run

def mk(kind):
    if kind == 'LR':
        return LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
    return RandomForestClassifier(n_estimators=100, max_depth=10, class_weight='balanced',
                                  n_jobs=4, random_state=42)

def folds(X, y, g, grouped=True):
    if grouped:
        return LeaveOneGroupOut().split(X, y, g)
    return StratifiedKFold(5, shuffle=True, random_state=42).split(X, y)

def pooled(scale, attack):
    """Bir olcegin uc yerlesim hucresini havuzlar; run_id yerlesim adidir."""
    fr = []
    for pl in ['core', 'mid', 'edge']:
        d = load_run(scale, attack, pl)
        if d is None:
            continue
        d = d.copy(); d['run_id'] = pl; fr.append(d)
    return pd.concat(fr, ignore_index=True) if fr else None

def xyg(d, attack):
    X = d[FEAT].values.astype(float)
    y = ((d.attack_type.values == ATYPE[attack]) & (d.is_attacker.values == 1)).astype(int)
    g = np.array([f'{r}|{n}' for r, n in zip(d.run_id.values, d.node_id.values)])
    return X, y, g

def scored(X, y, g, kind, grouped=True, metric='f1'):
    vals = []
    for tr, te in folds(X, y, g, grouped):
        if len(np.unique(y[tr])) < 2 or y[te].sum() == 0:
            continue
        sc = StandardScaler().fit(X[tr]); m = mk(kind); m.fit(sc.transform(X[tr]), y[tr])
        pr = m.predict(sc.transform(X[te]))
        vals.append({'f1': f1_score, 'p': precision_score, 'r': recall_score}[metric](y[te], pr, zero_division=0)
                    if metric != 'mcc' else matthews_corrcoef(y[te], pr))
    return float(np.mean(vals)) if vals else float('nan')

def baseline(scale):
    fr = []
    for f in glob.glob(f'dataset_v3/single/logs/*baseline-n{scale}-*.log'):
        rec = parse(f)
        if not rec:
            continue
        df = pd.DataFrame(rec, columns=COLS).sort_values(['node_id', 'timestamp']).reset_index(drop=True)
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
        fr.append(df)
    return pd.concat(fr, ignore_index=True) if fr else None

def t_f1():
    rows = []
    for scale in ['21', '31']:
        for a in ATT:
            d = pooled(scale, a)
            if d is None: continue
            X, y, g = xyg(d, a)
            rows.append(dict(scale=scale, attack=DISP[a], f1=round(scored(X, y, g, 'LR'), 3)))
            print(rows[-1], flush=True)
    pd.DataFrame(rows).to_csv('core_f1_main.csv', index=False)

def t_pr():
    rows = []
    for scale in ['21', '31']:
        base = baseline(scale)
        for a in ATT:
            d = pooled(scale, a)
            if d is None: continue
            X, y, g = xyg(d, a)
            fpr = np.nan
            if base is not None:
                sc = StandardScaler().fit(X); m = mk('LR'); m.fit(sc.transform(X), y)
                fpr = float(m.predict(sc.transform(base[FEAT].values.astype(float))).mean())
            rows.append(dict(scale=scale, attack=DISP[a],
                             P=round(scored(X, y, g, 'LR', metric='p'), 2),
                             R=round(scored(X, y, g, 'LR', metric='r'), 2),
                             MCC=round(scored(X, y, g, 'LR', metric='mcc'), 2),
                             FPR=round(fpr, 2)))
            print(rows[-1], flush=True)
    pd.DataFrame(rows).to_csv('core_beyond_f1.csv', index=False)

def t_identity():
    rows = []
    for a in ATT:
        d = pooled('21', a)
        X, y, g = xyg(d, a)
        Xi = np.column_stack([X, d.node_id.values, d.parent_id.values,
                              (d.node_id * d.parent_id).values]).astype(float)
        rows.append(dict(attack=DISP[a],
                         base_group=round(scored(X, y, g, 'RF'), 2),
                         base_naive=round(scored(X, y, None, 'RF', grouped=False), 2),
                         id_group=round(scored(Xi, y, g, 'RF'), 2),
                         id_naive=round(scored(Xi, y, None, 'RF', grouped=False), 2)))
        print(rows[-1], flush=True)
    t = pd.DataFrame(rows); t.to_csv('core_identity_ablation.csv', index=False)
    print('MEAN', t.mean(numeric_only=True).round(2).to_dict())

def t_placement():
    rows = []
    for scale in ['21', '31']:
        for a in ATT:
            for pl in ['core', 'mid', 'edge']:
                d = load_run(scale, a, pl)
                if d is None: continue
                X = d[FEAT].values.astype(float)
                y = ((d.attack_type.values == ATYPE[a]) & (d.is_attacker.values == 1)).astype(int)
                g = d.node_id.values
                rows.append(dict(scale=scale, attack=DISP[a], placement=pl,
                                 RF=round(scored(X, y, g, 'RF'), 4), LR=round(scored(X, y, g, 'LR'), 4)))
                print(rows[-1], flush=True)
    t = pd.DataFrame(rows); t.to_csv('core_placement.csv', index=False)
    print('tab:scale (LR, aile havuzlanmis):')
    print(t.pivot_table(index='placement', columns='scale', values='LR').round(3).to_string())

if __name__ == '__main__':
    what = sys.argv[1] if len(sys.argv) > 1 else 'all'
    for name, fn in [('f1', t_f1), ('pr', t_pr), ('identity', t_identity), ('placement', t_placement)]:
        if what in ('all', name):
            print(f'### {name} ###', flush=True); fn()
