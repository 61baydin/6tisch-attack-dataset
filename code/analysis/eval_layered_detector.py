#!/usr/bin/env python3
"""A benchmark-derived detector: multi-scale temporal ensemble + layered attribution
(reviewer item R1-3).

Two designs, both dictated by measurements already in the paper rather than invented:

  1. Multi-scale temporal ensemble (MSTE). The window ablation shows that the useful
     observation span differs per family: Blackhole keeps improving to 64 records,
     TSCH Desynchronization saturates at 32, and the overt families are already at the
     ceiling with 4. A single window is therefore wrong for some family whatever it is
     set to. MSTE runs three convolutional branches over the last 4, 16 and 64 records
     of the same anchor and concatenates their pooled representations.

  2. Layered attribution. The multi-class confusion matrix shows the benign class and
     the two timing-coupled MAC families forming a mutually confused cluster, and the
     flat eight-way classifier spends its capacity on the dominant benign class. The
     layered detector splits the task: stage A decides attacker or benign, stage B
     attributes the family and is trained on attacker rows only.

Every comparison uses the folds, groups and seeds of the existing benchmark, and the
baselines are evaluated on exactly the same samples.

Output: layered_binary_perfold.csv, layered_multiclass.csv, layered_summary.txt
"""
import collections, time, warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
import torch, torch.nn as nn
from eval_window_sweep import (ATT, ATYPE, DISP, FEAT, load_run, CNN, train_nn, predict_nn)

torch.manual_seed(42); np.random.seed(42)
torch.set_num_threads(10)
SCALES = (4, 16, 64)
WMAX, STRIDE, KF, EP = 64, 2, 5, 8


class MSTE(nn.Module):
    """Three convolutional branches over nested windows, concatenated."""
    def __init__(s, d, h=32):
        super().__init__()
        s.branches = nn.ModuleList([
            nn.Sequential(nn.Conv1d(d, h, 3, padding=1), nn.ReLU(),
                          nn.Conv1d(h, h, 3, padding=1), nn.ReLU())
            for _ in SCALES])
        s.fc = nn.Linear(h * len(SCALES), 1)

    def forward(s, x):                      # x: (batch, WMAX, features)
        outs = []
        for w, br in zip(SCALES, s.branches):
            z = x[:, -w:, :].transpose(1, 2)
            outs.append(br(z).max(2).values)
        return s.fc(torch.cat(outs, dim=1)).squeeze(-1)


def windows_multi(attack, atype):
    """Anchors with WMAX history, so every model sees identical samples."""
    Xs, ys, gs = [], [], []
    for scale in ['21', '31']:
        for pl in ['core', 'mid', 'edge']:
            df = load_run(scale, attack, pl)
            if df is None:
                continue
            rid = f'{scale}{pl}'
            for nid, grp in df.groupby('node_id'):
                F = grp[FEAT].values.astype(np.float32)
                lab = ((grp.attack_type.values == atype) & (grp.is_attacker.values == 1)).astype(np.int64)
                n = len(grp)
                if n < WMAX:
                    continue
                for s0 in range(0, n - WMAX + 1, STRIDE):
                    Xs.append(F[s0:s0 + WMAX]); ys.append(lab[s0 + WMAX - 1]); gs.append(f'{rid}|{nid}')
    return np.array(Xs), np.array(ys), np.array(gs)


def binary_benchmark():
    rows = []
    for a in ATT:
        t0 = time.time()
        X, y, g = windows_multi(a, ATYPE[a])
        if len(set(y)) < 2 or len(set(g[y == 1])) < KF:
            print('  skip', a, flush=True); continue
        nf = X.shape[2]
        cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
        for fi, (tr, te) in enumerate(cv.split(X, y, g)):
            if len(np.unique(y[tr])) < 2 or len(np.unique(y[te])) < 2:
                continue
            sc = StandardScaler().fit(X[tr].reshape(-1, nf))
            Xtr = sc.transform(X[tr].reshape(-1, nf)).reshape(X[tr].shape).astype(np.float32)
            Xte = sc.transform(X[te].reshape(-1, nf)).reshape(X[te].shape).astype(np.float32)
            posw = max(1.0, (y[tr] == 0).sum() / max(1, (y[tr] == 1).sum()))
            m = train_nn(lambda: MSTE(nf), Xtr, y[tr], posw, epochs=EP)
            rows.append(dict(attack=a, fold=fi, model='MSTE',
                             f1=f1_score(y[te], predict_nn(m, Xte), zero_division=0)))
            for w in (16, 64):
                mb = train_nn(lambda: CNN(nf), Xtr[:, -w:, :], y[tr], posw, epochs=EP)
                rows.append(dict(attack=a, fold=fi, model=f'1D-CNN W={w}',
                                 f1=f1_score(y[te], predict_nn(mb, Xte[:, -w:, :]), zero_division=0)))
        print(f'  done {a} in {time.time()-t0:.0f}s, samples={len(X)}', flush=True)
        pd.DataFrame(rows).to_csv('layered_binary_perfold.csv', index=False)
    return pd.DataFrame(rows)


def records_pooled(scale='21'):
    frames = []
    for a in ATT:
        for pl in ['core', 'mid', 'edge']:
            df = load_run(scale, a, pl)
            if df is None:
                continue
            df = df.copy(); df['run_id'] = f'{a}{scale}{pl}'
            frames.append(df)
    d = pd.concat(frames, ignore_index=True)
    X = d[FEAT].values.astype(float)
    y = np.where(d.is_attacker.values == 1, d.attack_type.values, 0).astype(int)
    g = (d.run_id.astype(str) + '|' + d.node_id.astype(str)).values
    return X, y, g


def multiclass(scale='21'):
    X, y, g = records_pooled(scale)
    cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
    yp_flat = np.zeros_like(y); yp_lay = np.zeros_like(y)
    for tr, te in cv.split(X, y, g):
        sc = StandardScaler().fit(X[tr])
        Xtr, Xte = sc.transform(X[tr]), sc.transform(X[te])
        flat = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
        flat.fit(Xtr, y[tr]); yp_flat[te] = flat.predict(Xte)
        # stage A: attacker or benign
        a_tr = (y[tr] > 0).astype(int)
        sa = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
        sa.fit(Xtr, a_tr)
        # stage B: family, attacker rows only
        mask = a_tr == 1
        sb = RandomForestClassifier(n_estimators=200, max_depth=12, class_weight='balanced',
                                    n_jobs=-1, random_state=42)
        sb.fit(Xtr[mask], y[tr][mask])
        pa = sa.predict(Xte)
        out = np.zeros(len(te), dtype=int)
        if pa.sum():
            out[pa == 1] = sb.predict(Xte[pa == 1])
        yp_lay[te] = out
    labels = sorted(set(y))
    res = []
    for name, yp in [('flat multi-class LR', yp_flat), ('layered (stage A + stage B)', yp_lay)]:
        per = f1_score(y, yp, labels=labels, average=None, zero_division=0)
        res.append(dict(scale=scale, model=name,
                        macro_f1=round(float(f1_score(y, yp, labels=labels, average='macro',
                                                      zero_division=0)), 3),
                        **{f'f1_class{c}': round(float(v), 3) for c, v in zip(labels, per)}))
    return pd.DataFrame(res)


def main():
    print('=== binary: multi-scale ensemble vs single-scale CNN ===', flush=True)
    b = binary_benchmark()
    piv = b.groupby(['model', 'attack'])['f1'].mean().unstack('attack').round(3)
    means = b.groupby('model')['f1'].mean().round(3)
    print('\n### per-attack group-aware F1 ###'); print(piv.to_string())
    print('\n### mean per-attack F1 ###'); print(means.to_string())

    print('\n=== multi-class: layered vs flat ===', flush=True)
    m = pd.concat([multiclass('21'), multiclass('31')], ignore_index=True)
    m.to_csv('layered_multiclass.csv', index=False)
    print(m[['scale', 'model', 'macro_f1']].to_string(index=False))

    lines = ['### Multi-scale temporal ensemble, group-aware binary F1 ###']
    for k, v in means.items():
        lines.append(f'  {k:16} {v:.3f}')
    lines.append('')
    lines.append('### per attack ###')
    lines.append(piv.to_string())
    lines.append('')
    lines.append('### Layered attribution, multi-class macro-F1 ###')
    for _, r in m.iterrows():
        lines.append(f'  {r.scale}-mote  {r.model:30} macro-F1 = {r.macro_f1:.3f}')
    txt = '\n'.join(lines)
    open('layered_summary.txt', 'w').write(txt + '\n')
    print('\nwrote: layered_binary_perfold.csv, layered_multiclass.csv, layered_summary.txt')


if __name__ == '__main__':
    main()
