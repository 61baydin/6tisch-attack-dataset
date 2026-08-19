#!/usr/bin/env python3
"""Detection delay / time-to-detect (reviewer item R5-9).

For every attacker (run, node): the onset is the first record with is_attacker=1, and
the detection instant is the first record at or after the onset where the model has
produced K consecutive positives. The delay is detection minus onset in seconds; a
node that never triggers counts as not detected.

Two models: the per-record Logistic Regression and the windowed 1D-CNN (W=16, stride 1,
window label taken from its last record). Both use out-of-fold predictions under
group-aware StratifiedGroupKFold (k=5, group = (run, node)).

Output: time_to_detect_per_node.csv, time_to_detect_summary.csv
"""
import warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
import torch
from eval_window_sweep import (ATT, ATYPE, DISP, FEAT, load_run, CNN, train_nn, predict_nn)

W, STRIDE, KF, KCONS = 16, 1, 5, 3
torch.manual_seed(42); np.random.seed(42)


def build(attack, atype):
    frames = []
    for scale in ['21', '31']:
        for pl in ['core', 'mid', 'edge']:
            df = load_run(scale, attack, pl)
            if df is None:
                continue
            df = df.copy(); df['run_id'] = f'{scale}{pl}'
            frames.append(df)
    if not frames:
        return None
    d = pd.concat(frames, ignore_index=True)
    d['label'] = ((d.attack_type.values == atype) & (d.is_attacker.values == 1)).astype(int)
    d['grp'] = d.run_id.astype(str) + '|' + d.node_id.astype(str)
    return d.sort_values(['run_id', 'node_id', 'timestamp']).reset_index(drop=True)


def oof_pointwise(d):
    X = d[FEAT].values.astype(float); y = d.label.values; g = d.grp.values
    pred = np.zeros(len(d), dtype=int)
    cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
    for tr, te in cv.split(X, y, g):
        if len(np.unique(y[tr])) < 2:
            continue
        sc = StandardScaler().fit(X[tr])
        m = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
        m.fit(sc.transform(X[tr]), y[tr])
        pred[te] = m.predict(sc.transform(X[te]))
    return pd.DataFrame(dict(grp=g, timestamp=d.timestamp.values, label=y, pred=pred))


def oof_windowed(d):
    Xs, ys, gs, ts = [], [], [], []
    for grp, sub in d.groupby('grp'):
        F = sub[FEAT].values.astype(np.float32)
        lab = sub.label.values; tv = sub.timestamp.values
        if len(sub) < W:
            continue
        for s in range(0, len(sub) - W + 1, STRIDE):
            Xs.append(F[s:s + W]); ys.append(lab[s + W - 1]); gs.append(grp); ts.append(tv[s + W - 1])
    X = np.array(Xs); y = np.array(ys); g = np.array(gs); ts = np.array(ts)
    if len(set(y)) < 2:
        return None
    nf = X.shape[2]; pred = np.zeros(len(X), dtype=int)
    cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
    for tr, te in cv.split(X, y, g):
        if len(np.unique(y[tr])) < 2:
            continue
        sc = StandardScaler().fit(X[tr].reshape(-1, nf))
        Xtr = sc.transform(X[tr].reshape(-1, nf)).reshape(X[tr].shape).astype(np.float32)
        Xte = sc.transform(X[te].reshape(-1, nf)).reshape(X[te].shape).astype(np.float32)
        posw = max(1.0, (y[tr] == 0).sum() / max(1, (y[tr] == 1).sum()))
        m = train_nn(lambda: CNN(nf), Xtr, y[tr], posw)
        pred[te] = predict_nn(m, Xte)
    return pd.DataFrame(dict(grp=g, timestamp=ts, label=y, pred=pred))


def delays(tab, attack, model, rows):
    for grp, sub in tab.groupby('grp'):
        sub = sub.sort_values('timestamp')
        if sub.label.sum() == 0:
            continue
        t0 = sub.timestamp[sub.label == 1].min()
        post = sub[sub.timestamp >= t0]
        p = post.pred.values; tv = post.timestamp.values
        hit = None
        run = 0
        for i in range(len(p)):
            run = run + 1 if p[i] == 1 else 0
            if run >= KCONS:
                hit = tv[i - KCONS + 1]
                break
        rows.append(dict(attack=DISP[attack], model=model, group=grp, onset_s=int(t0),
                         detected=hit is not None,
                         delay_s=(int(hit - t0) if hit is not None else np.nan),
                         attacker_records=int(sub.label.sum())))


def main():
    rows = []
    for a in ATT:
        d = build(a, ATYPE[a])
        if d is None:
            continue
        delays(oof_pointwise(d), a, 'LR (per-record)', rows)
        wt = oof_windowed(d)
        if wt is not None:
            delays(wt, a, '1D-CNN (W=16)', rows)
        print('done', DISP[a], flush=True)
    df = pd.DataFrame(rows)
    df.to_csv('time_to_detect_per_node.csv', index=False)
    g = df.groupby(['model', 'attack'])
    summ = pd.DataFrame({
        'attackers': g.size(),
        'detected': g.detected.sum(),
        'detection_rate': g.detected.mean().round(3),
        'median_delay_s': g.delay_s.median().round(1),
        'mean_delay_s': g.delay_s.mean().round(1),
        'p90_delay_s': g.delay_s.quantile(0.9).round(1),
    }).reset_index()
    summ.to_csv('time_to_detect_summary.csv', index=False)
    print('\n### Tespit gecikmesi (K=%d ardisik pozitif) ###' % KCONS)
    print(summ.to_string(index=False))
    print('\nwrote: time_to_detect_per_node.csv, time_to_detect_summary.csv')


if __name__ == '__main__':
    main()
