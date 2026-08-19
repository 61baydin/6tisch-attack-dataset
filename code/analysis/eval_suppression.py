#!/usr/bin/env python3
"""Telemetry-suppression ablation (reviewer item R3-4).

Threat: a fully compromised node can stop emitting its own analyser records, so the
per-record detector loses its input by construction. The released data answers what
is left, without new simulation: withhold every attacker row and ask whether the run
can still be classified as under attack from the benign nodes alone.

Protocol. The design has only two attacker-free runs, far too few to score a
run-level classifier, so the benign reference is taken from the time axis instead of
from separate runs: every run contributes one vector from its settled pre-attack
window (600 to 1200 s, after convergence and before any attacker starts) and one from
its attack window (1350 to 1950 s), the two windows having the same length. Attacker rows are withheld from both, so the
detector only ever sees the nodes that a suppressing adversary cannot silence. Folds
are leave-one-run-out and both windows of a run share a fold, so a run is never split
across training and test. Two references make the number interpretable: the same task
with attacker rows retained, and the liveness signal alone.

Output: suppression_results.csv, suppression_summary.txt
"""
import glob, os, re, collections, warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import f1_score, accuracy_score
from sklearn.preprocessing import StandardScaler
from eval_window_sweep import ATT, ATYPE, DISP, FEAT, COLS, parse, load_run

# The two windows must have the SAME length, otherwise row counts alone separate
# them and the detector learns the window rather than the attack.
BENIGN_FROM_S, BENIGN_TO_S = 600, 1200    # settled, before any attacker starts
ATTACK_FROM_S, ATTACK_TO_S = 1350, 1950   # all attackers active, same 600 s span
NEIGH_FEATS = ['rank', 'buf_occupancy', 'nbr_count', 'tx_slot_count',
               'parent_switch_count', 'rssi', 'route_count', 'delta_tx', 'delta_rx',
               'forward_ratio', 'bcast_tx', 'rank_increase']


def run_files():
    """(path, attack, scale, placement) for the five-attacker cells and the baselines."""
    out = []
    for p in sorted(glob.glob('dataset_v3/single/logs/*.log')):
        b = os.path.basename(p)
        m = re.search(r'_([a-z-]+)-n(\d+)-(core|mid|edge)-a5-w', b)
        if m:
            out.append((p, m.group(1), m.group(2), m.group(3)))
        elif '_baseline-n' in b:
            m2 = re.search(r'_baseline-n(\d+)-', b)
            out.append((p, 'baseline', m2.group(1), '-'))
    return out


def load_log(path):
    rows = parse(path)
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


def run_vector(df, drop_attackers, window):
    """Aggregate one time window of a run into a single feature vector."""
    lo, hi = window
    w = df[(df.timestamp >= lo) & (df.timestamp < hi)] if hi else df[df.timestamp >= lo]
    if drop_attackers:
        w = w[w.is_attacker == 0]
    if len(w) < 50:
        return None
    v = {}
    for f in NEIGH_FEATS:
        v[f + '_mean'] = w[f].mean()
        v[f + '_std'] = w[f].std()
    v['reporting_nodes'] = w.node_id.nunique()
    v['rows_per_node'] = len(w) / max(w.node_id.nunique(), 1)
    return v


def score(X, y, groups, name, rows):
    f1s, accs = [], []
    for tr, te in LeaveOneGroupOut().split(X, y, groups):
        if len(np.unique(y[tr])) < 2:
            continue
        sc = StandardScaler().fit(X[tr])
        m = RandomForestClassifier(n_estimators=200, max_depth=6, class_weight='balanced',
                                   n_jobs=-1, random_state=42)
        m.fit(sc.transform(X[tr]), y[tr])
        p = m.predict(sc.transform(X[te]))
        f1s.append(f1_score(y[te], p, zero_division=0)); accs.append(accuracy_score(y[te], p))
    rows.append(dict(setting=name, folds=len(f1s), f1=round(float(np.mean(f1s)), 3),
                     accuracy=round(float(np.mean(accs)), 3)))
    return float(np.mean(f1s)) if f1s else float('nan')


def main():
    recs = []
    for path, attack, scale, pl in run_files():
        if attack == 'baseline':
            continue                      # benign reference comes from the time axis
        df = load_log(path)
        if df is None:
            continue
        for drop in (True, False):
            for label, win in ((0, (BENIGN_FROM_S, BENIGN_TO_S)), (1, (ATTACK_FROM_S, ATTACK_TO_S))):
                v = run_vector(df, drop, win)
                if v is None:
                    continue
                v.update(run=os.path.basename(path)[:-4], attack=attack, scale=scale,
                         placement=pl, suppressed=drop, label=label)
                recs.append(v)
        print(f'  {os.path.basename(path)[:52]:52} nodes={df.node_id.nunique():3d}', flush=True)
    d = pd.DataFrame(recs)
    d.to_csv('suppression_results.csv', index=False)

    feats = [c for c in d.columns if c.endswith(('_mean', '_std'))] + ['reporting_nodes', 'rows_per_node']
    out = []
    n_runs = d.run.nunique()
    lines = ['### Attack-window detection from benign nodes only (leave-one-run-out) ###',
             f'runs: {n_runs}; each contributes one pre-attack vector (600-1200 s) and one '
             f'attack-window vector (1350-1950 s), equal length']
    for drop, name in [(True, 'attacker rows withheld (suppression)'),
                       (False, 'attacker rows retained (reference)')]:
        sub = d[d.suppressed == drop].dropna(subset=feats)
        X = sub[feats].values.astype(float); y = sub.label.values; g = sub.run.values
        f1 = score(X, y, g, name, out)
        lines.append(f'  {name:42} F1 = {f1:.3f}')
    sub = d[d.suppressed].dropna(subset=['reporting_nodes'])
    f1 = score(sub[['reporting_nodes', 'rows_per_node']].values.astype(float),
               sub.label.values, sub.run.values, 'liveness only', out)
    lines.append(f'  {"liveness only (reporting nodes, rows per node)":42} F1 = {f1:.3f}')
    # per-family breakdown under suppression
    lines.append('')
    lines.append('### Per attack family, attacker rows withheld ###')
    for a in sorted(d.attack.unique()):
        sub = d[(d.suppressed) & (d.attack == a)].dropna(subset=feats)
        if sub.label.nunique() < 2 or sub.run.nunique() < 3:
            continue
        f1 = score(sub[feats].values.astype(float), sub.label.values, sub.run.values,
                   f'suppressed:{a}', out)
        lines.append(f'  {DISP.get(a, a):26} F1 = {f1:.3f}   (runs={sub.run.nunique()})')
    pd.DataFrame(out).to_csv('suppression_scores.csv', index=False)
    txt = '\n'.join(lines)
    open('suppression_summary.txt', 'w').write(txt + '\n')
    print('\n' + txt)
    print('\nwrote: suppression_results.csv, suppression_scores.csv, suppression_summary.txt')


if __name__ == '__main__':
    main()
