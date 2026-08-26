#!/usr/bin/env python3
"""Sekil model_comparison'in naif (satir-duzeyi) yarisi.

Grup-farkinda yari zaten sweep_w16_perfold.csv icinde. Bu betik ayni pencereli
gorevde (W=16, ayni ornekler) StratifiedKFold(k=5) ile naif skorlari uretir;
ikisi birlestirilerek core_model_comparison.csv yazilir.
"""
import time, warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier
from eval_window_sweep import (ATT, ATYPE, CLASSIC, DEEPK, PT, NN_FACTORY,
                               windows, train_nn, predict_nn)

W, KF = 16, 5
KEYS = CLASSIC + DEEPK
rows = []
for a in ATT:
    t0 = time.time()
    X, y, g = windows(a, ATYPE[a], W)
    nf = X.shape[2]
    for fi, (tr, te) in enumerate(StratifiedKFold(KF, shuffle=True, random_state=42).split(X, y)):
        if len(np.unique(y[tr])) < 2 or y[te].sum() == 0:
            continue
        sc = StandardScaler().fit(X[tr].reshape(-1, nf))
        Xtr = sc.transform(X[tr].reshape(-1, nf)).reshape(X[tr].shape).astype(np.float32)
        Xte = sc.transform(X[te].reshape(-1, nf)).reshape(X[te].shape).astype(np.float32)
        posw = max(1.0, (y[tr] == 0).sum() / max(1, (y[tr] == 1).sum()))
        for k in KEYS:
            if k == 'XGBoost':
                m = XGBClassifier(n_estimators=100, max_depth=4, scale_pos_weight=posw,
                                  eval_metric='logloss', random_state=42, verbosity=0)
                m.fit(Xtr[:, -1, :], y[tr]); pred = m.predict(Xte[:, -1, :])
            elif k in PT:
                m = PT[k](); m.fit(Xtr[:, -1, :], y[tr]); pred = m.predict(Xte[:, -1, :])
            else:
                m = train_nn(lambda: NN_FACTORY[k](nf), Xtr, y[tr], posw); pred = predict_nn(m, Xte)
            rows.append(dict(attack=a, fold=fi, model=k,
                             f1=f1_score(y[te], pred, zero_division=0)))
    print(f'  {a} bitti ({time.time()-t0:.0f}s)', flush=True)
    pd.DataFrame(rows).to_csv('naive_w16_perfold.csv', index=False)

naive = pd.DataFrame(rows).groupby('model')['f1'].mean()
grp = pd.read_csv('sweep_w16_perfold.csv')
grp = grp[grp.W == W].groupby('model')['f1'].mean()
out = pd.DataFrame({'group_f1': grp.round(3), 'naive_f1': naive.round(3)})
out['leakage_gap'] = (out.naive_f1 - out.group_f1).round(3)
out['family'] = ['DL' if i in DEEPK else 'CL' for i in out.index]
out = out.sort_values('group_f1', ascending=False)
out.to_csv('core_model_comparison.csv')
print(out.to_string())
