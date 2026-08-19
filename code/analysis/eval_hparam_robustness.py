#!/usr/bin/env python3
"""Hyperparameter robustness of the model ranking (reviewer item R5-7).

Question: is the ordering of the classifiers an artefact of the default settings? Each
model family is run under a small and a large configuration alongside the default, on
the same windowed task (W=16), the same groups and the same folds. The output is the
agreement of the resulting rankings (Kendall tau, Spearman rho).

Output: hparam_robustness.csv, hparam_robustness_summary.csv
"""
import time, warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from scipy.stats import kendalltau, spearmanr
import torch
from eval_window_sweep import (ATT, ATYPE, windows, train_nn, predict_nn,
                               CNN, GRUM, TransformerClf)

W, KF = 16, 5
torch.manual_seed(42); np.random.seed(42)

# (model name, configuration label) -> constructor
CLASSIC_CFG = {
    ('LR', 'default'): lambda p: LogisticRegression(max_iter=1000, C=1.0, class_weight='balanced', random_state=42),
    ('LR', 'small'): lambda p: LogisticRegression(max_iter=1000, C=0.1, class_weight='balanced', random_state=42),
    ('LR', 'large'): lambda p: LogisticRegression(max_iter=1000, C=10.0, class_weight='balanced', random_state=42),
    ('RF', 'default'): lambda p: RandomForestClassifier(n_estimators=100, max_depth=10, class_weight='balanced', n_jobs=-1, random_state=42),
    ('RF', 'small'): lambda p: RandomForestClassifier(n_estimators=50, max_depth=6, class_weight='balanced', n_jobs=-1, random_state=42),
    ('RF', 'large'): lambda p: RandomForestClassifier(n_estimators=300, max_depth=20, class_weight='balanced', n_jobs=-1, random_state=42),
    ('XGBoost', 'default'): lambda p: XGBClassifier(n_estimators=100, max_depth=4, scale_pos_weight=p, eval_metric='logloss', random_state=42, verbosity=0),
    ('XGBoost', 'small'): lambda p: XGBClassifier(n_estimators=50, max_depth=3, scale_pos_weight=p, eval_metric='logloss', random_state=42, verbosity=0),
    ('XGBoost', 'large'): lambda p: XGBClassifier(n_estimators=300, max_depth=8, scale_pos_weight=p, eval_metric='logloss', random_state=42, verbosity=0),
    ('LightGBM', 'default'): lambda p: LGBMClassifier(n_estimators=100, class_weight='balanced', random_state=42, verbose=-1),
    ('LightGBM', 'small'): lambda p: LGBMClassifier(n_estimators=50, num_leaves=15, class_weight='balanced', random_state=42, verbose=-1),
    ('LightGBM', 'large'): lambda p: LGBMClassifier(n_estimators=300, num_leaves=63, class_weight='balanced', random_state=42, verbose=-1),
    ('kNN', 'default'): lambda p: KNeighborsClassifier(n_neighbors=5),
    ('kNN', 'small'): lambda p: KNeighborsClassifier(n_neighbors=3),
    ('kNN', 'large'): lambda p: KNeighborsClassifier(n_neighbors=15),
    ('MLP', 'default'): lambda p: MLPClassifier(hidden_layer_sizes=(64,), max_iter=300, random_state=42),
    ('MLP', 'small'): lambda p: MLPClassifier(hidden_layer_sizes=(32,), max_iter=300, random_state=42),
    ('MLP', 'large'): lambda p: MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=300, random_state=42),
}
DEEP_CFG = {
    ('1D-CNN', 'default'): (CNN, 48, 8), ('1D-CNN', 'small'): (CNN, 24, 8), ('1D-CNN', 'large'): (CNN, 96, 12),
    ('GRU', 'default'): (GRUM, 48, 8), ('GRU', 'small'): (GRUM, 24, 8), ('GRU', 'large'): (GRUM, 96, 12),
    ('Transformer', 'default'): (TransformerClf, 48, 8), ('Transformer', 'small'): (TransformerClf, 24, 8),
    ('Transformer', 'large'): (TransformerClf, 96, 12),
}


def main():
    import sys
    only = sys.argv[1].split(',') if len(sys.argv) > 1 else ATT
    out = sys.argv[2] if len(sys.argv) > 2 else 'hparam_robustness.csv'
    rows = []
    for a in only:
        t0 = time.time()
        X, y, g = windows(a, ATYPE[a], W)
        if len(set(y)) < 2 or len(set(g[y == 1])) < KF:
            print('skip', a, flush=True); continue
        nf = X.shape[2]
        cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
        for fi, (tr, te) in enumerate(cv.split(X, y, g)):
            if len(np.unique(y[tr])) < 2 or len(np.unique(y[te])) < 2:
                continue
            sc = StandardScaler().fit(X[tr].reshape(-1, nf))
            Xtr = sc.transform(X[tr].reshape(-1, nf)).reshape(X[tr].shape).astype(np.float32)
            Xte = sc.transform(X[te].reshape(-1, nf)).reshape(X[te].shape).astype(np.float32)
            posw = max(1.0, (y[tr] == 0).sum() / max(1, (y[tr] == 1).sum()))
            for (name, cfg), mk in CLASSIC_CFG.items():
                m = mk(posw); m.fit(Xtr[:, -1, :], y[tr])
                rows.append(dict(attack=a, fold=fi, model=name, config=cfg,
                                 f1=f1_score(y[te], m.predict(Xte[:, -1, :]), zero_division=0)))
            for (name, cfg), (cls, h, ep) in DEEP_CFG.items():
                m = train_nn(lambda: cls(nf, h), Xtr, y[tr], posw, epochs=ep)
                rows.append(dict(attack=a, fold=fi, model=name, config=cfg,
                                 f1=f1_score(y[te], predict_nn(m, Xte), zero_division=0)))
        print(f'done {a} in {time.time()-t0:.0f}s', flush=True)
        pd.DataFrame(rows).to_csv(out, index=False)

    df = pd.DataFrame(rows)
    import os
    if out != 'hparam_robustness.csv' and os.path.exists('hparam_robustness.csv'):
        df = pd.concat([pd.read_csv('hparam_robustness.csv'), df], ignore_index=True)
        df.to_csv('hparam_robustness.csv', index=False)
        print('merged -> hparam_robustness.csv, attacks:', sorted(df.attack.unique()))
    piv = df.groupby(['model', 'config'])['f1'].mean().unstack('config').round(3)
    piv = piv[['small', 'default', 'large']]
    piv['spread'] = (piv.max(axis=1) - piv.min(axis=1)).round(3)
    piv.to_csv('hparam_robustness_summary.csv')
    print('\n### Mean group-aware per-attack F1 ###')
    print(piv.to_string())
    base = piv['default']
    print('\n### Rank agreement with the default configuration ###')
    for cfg in ['small', 'large']:
        tau = kendalltau(base.values, piv[cfg].values).correlation
        rho = spearmanr(base.values, piv[cfg].values).correlation
        print(f'{cfg:8} Kendall tau = {tau:.3f}   Spearman rho = {rho:.3f}')
    print('\nwrote: hparam_robustness.csv, hparam_robustness_summary.csv')


if __name__ == '__main__':
    main()
