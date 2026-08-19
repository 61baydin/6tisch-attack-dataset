#!/usr/bin/env python3
"""Window-length sweep and per-fold score capture (reviewer items R3-3, R5-8, R4-I22, R5-11).

Same data, features and folds as gen_model_compare_full.py; the differences are:
  * W is a parameter (4, 8, 16, 32, 64)
  * every fold's F1 is written to CSV (input for the Friedman/Nemenyi tests)
  * --resource additionally measures model size, training time and inference latency

Usage:
  python3 eval_window_sweep.py --w 16 --models all --out window_sweep_w16
  python3 eval_window_sweep.py --w 4,8,32,64 --models deep --out window_sweep_rest
"""
import argparse, re, glob, time, pickle, warnings, collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import GaussianNB
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
import torch, torch.nn as nn

torch.manual_seed(42); np.random.seed(42)
torch.set_num_threads(10)

KF, STRIDE, EP = 5, 2, 8
ATT = ['blackhole', 'decrease', 'dis', 'flooding', 'shared-slot', 'slot-exhaustion', 'timekeep']
DISP = {'blackhole': 'Blackhole', 'decrease': 'Decrease', 'dis': 'DIS', 'flooding': 'AppFlood',
        'shared-slot': 'Shared', 'slot-exhaustion': '6P', 'timekeep': 'Desync'}
ATYPE = {a: i for i, a in enumerate(ATT, 1)}
BASE = ['rank', 'buf_occupancy', 'dio_sent', 'dao_sent', 'dis_sent', 'nbr_count', 'tx_slot_count',
        'parent_switch_count', 'rssi', 'route_count', 'delta_tx', 'delta_rx', 'app_packet_count']
COLS = ['timestamp', 'node_id', 'parent_id'] + BASE + ['forward_ratio', 'bcast_tx', 'is_attacker', 'attack_type']
FEAT = BASE + ['forward_ratio', 'bcast_tx', 'rank_increase', 'd_app']
RX = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")

CLASSIC = ['LR', 'RF', 'GBoost', 'XGBoost', 'LightGBM', 'DT', 'SVM', 'kNN', 'MLP', 'NB']
DEEPK = ['1D-CNN', 'LSTM', 'GRU', 'BiLSTM', 'CNN-LSTM', 'TCN', 'Transformer']


def parse(fn):
    o = []
    for ln in open(fn):
        m = RX.search(ln)
        if m:
            v = [int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v) == 20:
                o.append(v)
    return o


def canon(scale, a, pl):
    fs = [f for f in glob.glob(f'dataset_v3/single/logs/*_{a}-n{scale}-{pl}-a5-w*.log')
          if 'cooja' not in f and parse(f)]
    return sorted(fs)[-1] if fs else None


def load_run(scale, a, pl):
    f = canon(scale, a, pl)
    if not f:
        return None
    df = pd.DataFrame(parse(f), columns=COLS).sort_values(['node_id', 'timestamp']).reset_index(drop=True)
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


def windows(a, atype, W):
    Xs, ys, gs = [], [], []
    for scale in ['21', '31']:
        for pl in ['core', 'mid', 'edge']:
            df = load_run(scale, a, pl)
            if df is None:
                continue
            rid = f"{scale}{pl}"
            for nid, grp in df.groupby('node_id'):
                F = grp[FEAT].values.astype(np.float32)
                lab = ((grp.attack_type.values == atype) & (grp.is_attacker.values == 1)).astype(np.int64)
                n = len(grp)
                if n < W:
                    continue
                for s in range(0, n - W + 1, STRIDE):
                    Xs.append(F[s:s + W]); ys.append(lab[s + W - 1]); gs.append(f"{rid}|{nid}")
    return np.array(Xs), np.array(ys), np.array(gs)


class CNN(nn.Module):
    def __init__(s, d, h=48):
        super().__init__(); s.c1 = nn.Conv1d(d, h, 3, padding=1); s.c2 = nn.Conv1d(h, h, 3, padding=1); s.fc = nn.Linear(h, 1)
    def forward(s, x):
        z = x.transpose(1, 2); z = torch.relu(s.c1(z)); z = torch.relu(s.c2(z)); return s.fc(z.max(2).values).squeeze(-1)


class LSTMM(nn.Module):
    def __init__(s, d, h=48):
        super().__init__(); s.r = nn.LSTM(d, h, batch_first=True); s.fc = nn.Linear(h, 1)
    def forward(s, x):
        o, _ = s.r(x); return s.fc(o[:, -1, :]).squeeze(-1)


class GRUM(nn.Module):
    def __init__(s, d, h=48):
        super().__init__(); s.r = nn.GRU(d, h, batch_first=True); s.fc = nn.Linear(h, 1)
    def forward(s, x):
        o, _ = s.r(x); return s.fc(o[:, -1, :]).squeeze(-1)


class BiLSTM(nn.Module):
    def __init__(s, d, h=48):
        super().__init__(); s.r = nn.LSTM(d, h, batch_first=True, bidirectional=True); s.fc = nn.Linear(2 * h, 1)
    def forward(s, x):
        o, _ = s.r(x); return s.fc(o[:, -1, :]).squeeze(-1)


class CNNLSTM(nn.Module):
    def __init__(s, d, h=48):
        super().__init__(); s.c = nn.Conv1d(d, h, 3, padding=1); s.r = nn.LSTM(h, h, batch_first=True); s.fc = nn.Linear(h, 1)
    def forward(s, x):
        z = torch.relu(s.c(x.transpose(1, 2))).transpose(1, 2); o, _ = s.r(z); return s.fc(o[:, -1, :]).squeeze(-1)


class TCN(nn.Module):
    def __init__(s, d, h=48):
        super().__init__()
        s.c1 = nn.Conv1d(d, h, 3, padding=1, dilation=1); s.c2 = nn.Conv1d(h, h, 3, padding=2, dilation=2)
        s.c3 = nn.Conv1d(h, h, 3, padding=4, dilation=4); s.fc = nn.Linear(h, 1)
    def forward(s, x):
        z = x.transpose(1, 2); z = torch.relu(s.c1(z)); z = torch.relu(s.c2(z)); z = torch.relu(s.c3(z))
        return s.fc(z.max(2).values).squeeze(-1)


class TransformerClf(nn.Module):
    def __init__(s, d, h=48, nhead=4, nl=2):
        super().__init__(); s.proj = nn.Linear(d, h)
        enc = nn.TransformerEncoderLayer(h, nhead, h * 2, batch_first=True, dropout=0.1)
        s.tr = nn.TransformerEncoder(enc, nl); s.fc = nn.Linear(h, 1)
    def forward(s, x):
        z = s.proj(x); z = s.tr(z); return s.fc(z.mean(1)).squeeze(-1)


NN_FACTORY = {'1D-CNN': CNN, 'LSTM': LSTMM, 'GRU': GRUM, 'BiLSTM': BiLSTM,
              'CNN-LSTM': CNNLSTM, 'TCN': TCN, 'Transformer': TransformerClf}

PT = {'LR': lambda: LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
      'RF': lambda: RandomForestClassifier(n_estimators=100, max_depth=10, class_weight='balanced', n_jobs=-1, random_state=42),
      'GBoost': lambda: GradientBoostingClassifier(n_estimators=100, max_depth=3, random_state=42),
      'DT': lambda: DecisionTreeClassifier(max_depth=10, class_weight='balanced', random_state=42),
      'SVM': lambda: SVC(kernel='rbf', class_weight='balanced', random_state=42),
      'kNN': lambda: KNeighborsClassifier(n_neighbors=5),
      'MLP': lambda: MLPClassifier(hidden_layer_sizes=(64,), max_iter=300, random_state=42),
      'NB': lambda: GaussianNB(),
      'LightGBM': lambda: LGBMClassifier(n_estimators=100, class_weight='balanced', random_state=42, verbose=-1)}


def train_nn(mk, Xtr, ytr, posw, epochs=EP):
    m = mk(); opt = torch.optim.Adam(m.parameters(), lr=1e-3)
    lf = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([posw], dtype=torch.float32))
    Xt = torch.tensor(Xtr); yt = torch.tensor(ytr, dtype=torch.float32); idx = np.arange(len(Xt))
    m.train()
    for _ in range(epochs):
        np.random.shuffle(idx)
        for i in range(0, len(idx), 256):
            b = idx[i:i + 256]; opt.zero_grad(); lf(m(Xt[b]), yt[b]).backward(); opt.step()
    m.eval()
    return m


def predict_nn(m, Xte):
    with torch.no_grad():
        return (torch.sigmoid(m(torch.tensor(Xte))).numpy() >= 0.5).astype(int)


def run(W, model_keys, attacks, rows_out, resource_rows=None):
    for a in attacks:
        t0 = time.time()
        X, y, g = windows(a, ATYPE[a], W)
        if len(set(y)) < 2 or y.sum() < KF or len(set(g[y == 1])) < KF:
            print(f'  skip {a} (W={W})', flush=True); continue
        nf = X.shape[2]
        cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
        for fi, (tr, te) in enumerate(cv.split(X, y, g)):
            if len(np.unique(y[tr])) < 2 or len(np.unique(y[te])) < 2:
                continue
            sc = StandardScaler().fit(X[tr].reshape(-1, nf))
            Xtr = sc.transform(X[tr].reshape(-1, nf)).reshape(X[tr].shape).astype(np.float32)
            Xte = sc.transform(X[te].reshape(-1, nf)).reshape(X[te].shape).astype(np.float32)
            posw = max(1.0, (y[tr] == 0).sum() / max(1, (y[tr] == 1).sum()))
            for k in model_keys:
                ts = time.time()
                if k == 'XGBoost':
                    m = XGBClassifier(n_estimators=100, max_depth=4, scale_pos_weight=posw,
                                      eval_metric='logloss', random_state=42, verbosity=0)
                    m.fit(Xtr[:, -1, :], y[tr]); fit_s = time.time() - ts
                    ti = time.time(); pred = m.predict(Xte[:, -1, :]); inf_s = time.time() - ti
                    params = None
                elif k in PT:
                    m = PT[k](); m.fit(Xtr[:, -1, :], y[tr]); fit_s = time.time() - ts
                    ti = time.time(); pred = m.predict(Xte[:, -1, :]); inf_s = time.time() - ti
                    params = None
                else:
                    m = train_nn(lambda: NN_FACTORY[k](nf), Xtr, y[tr], posw); fit_s = time.time() - ts
                    ti = time.time(); pred = predict_nn(m, Xte); inf_s = time.time() - ti
                    params = sum(p.numel() for p in m.parameters())
                f1 = f1_score(y[te], pred, zero_division=0)
                rows_out.append(dict(W=W, attack=a, fold=fi, model=k, f1=f1,
                                     n_train=len(tr), n_test=len(te)))
                if resource_rows is not None:
                    try:
                        blob = len(pickle.dumps(m))
                    except Exception:
                        blob = None
                    resource_rows.append(dict(W=W, attack=a, fold=fi, model=k, params=params,
                                              serialized_bytes=blob, train_s=fit_s,
                                              infer_s=inf_s, n_test=len(te)))
        print(f'  done {a} (W={W}) in {time.time()-t0:.0f}s, windows={len(X)}', flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--w', default='16')
    ap.add_argument('--models', default='deep', choices=['deep', 'all', 'classic'])
    ap.add_argument('--attacks', default='')
    ap.add_argument('--out', default='window_sweep')
    ap.add_argument('--resource', action='store_true')
    args = ap.parse_args()

    if args.models == 'deep':
        keys = ['LR', 'RF'] + DEEPK
    elif args.models == 'classic':
        keys = CLASSIC
    else:
        keys = CLASSIC + DEEPK
    attacks = args.attacks.split(',') if args.attacks else ATT
    rows, res = [], ([] if args.resource else None)
    for W in [int(x) for x in args.w.split(',')]:
        print(f'=== W={W}, models={len(keys)}, attacks={len(attacks)} ===', flush=True)
        run(W, keys, attacks, rows, res)
        pd.DataFrame(rows).to_csv(f'{args.out}_perfold.csv', index=False)
        if res is not None:
            pd.DataFrame(res).to_csv(f'{args.out}_resource.csv', index=False)
    df = pd.DataFrame(rows)
    if len(df):
        piv = df.groupby(['W', 'model'])['f1'].mean().unstack(0).round(3)
        print('\n### Mean group-aware per-attack F1 (columns are W) ###')
        print(piv.to_string())
        piv.to_csv(f'{args.out}_summary.csv')
        df.groupby(['W', 'attack', 'model'])['f1'].mean().unstack(2).round(3) \
          .to_csv(f'{args.out}_per_attack.csv')
    print('wrote:', f'{args.out}_perfold.csv')


if __name__ == '__main__':
    main()
