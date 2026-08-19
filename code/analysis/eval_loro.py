#!/usr/bin/env python3
"""Leave-one-run-out versus (run, node) group-aware evaluation (reviewer item R5-6).

Question: does the (run, node) key used in the paper leave residual leakage in the
five-attacker design? The same per-record pipeline is run under three grouping keys:
  A) group = (run_id, node_id)  -> the protocol of the paper
  B) group = node_id            -> the mote is removed from EVERY run, which isolates
                                   cross-run positional memorisation without adding
                                   distribution shift
  C) group = run_id             -> the whole run is withheld; the model also faces an
                                   unseen placement zone
A minus B is identity leakage; B minus C is distribution shift. Naive StratifiedKFold
is reported as a reference.

Output: loro_comparison.csv, loro_comparison_summary.csv
"""
import warnings
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut, StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from eval_window_sweep import ATT, ATYPE, DISP, FEAT, load_run

MODELS = {
    'LR': lambda: LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42),
    'RF': lambda: RandomForestClassifier(n_estimators=100, max_depth=10, class_weight='balanced',
                                         n_jobs=4, random_state=42),
}


def records(attack, atype):
    """Per-record data: X, y, run_id, node_id (21+31 motes, a5, six runs)."""
    frames = []
    for scale in ['21', '31']:
        for pl in ['core', 'mid', 'edge']:
            df = load_run(scale, attack, pl)
            if df is None:
                continue
            df = df.copy()
            df['run_id'] = f'{scale}{pl}'
            frames.append(df)
    if not frames:
        return None
    d = pd.concat(frames, ignore_index=True)
    X = d[FEAT].values.astype(float)
    y = ((d.attack_type.values == atype) & (d.is_attacker.values == 1)).astype(int)
    return X, y, d.run_id.values, d.node_id.values, d


def score(X, y, groups, splitter, name, attack, model_key, rows, grouped=True):
    f1s = []
    it = splitter.split(X, y, groups) if grouped else splitter.split(X, y)
    for fi, (tr, te) in enumerate(it):
        if len(np.unique(y[tr])) < 2 or y[te].sum() == 0:
            continue
        sc = StandardScaler().fit(X[tr])
        m = MODELS[model_key]()
        m.fit(sc.transform(X[tr]), y[tr])
        f = f1_score(y[te], m.predict(sc.transform(X[te])), zero_division=0)
        f1s.append(f)
        rows.append(dict(attack=attack, model=model_key, protocol=name, fold=fi, f1=f,
                         n_test=len(te), n_test_attacker=int(y[te].sum())))
    return float(np.mean(f1s)) if f1s else float('nan')


def main():
    rows, summ = [], []
    for a in ATT:
        rec = records(a, ATYPE[a])
        if rec is None:
            continue
        X, y, runs, nodes, _ = rec
        gnode = np.array([f'{r}|{n}' for r, n in zip(runs, nodes)])
        for mk in MODELS:
            g_node = score(X, y, gnode, LeaveOneGroupOut(), 'LOGO(run,node)', a, mk, rows)
            # node identity only: the mote is excluded from training in EVERY run.
            # the gap to (run,node) is cross-run positional memorisation (pure leakage),
            # without adding environment or distribution shift.
            g_id = score(X, y, nodes, LeaveOneGroupOut(), 'LONO(node id)', a, mk, rows)
            g_run = score(X, y, runs, LeaveOneGroupOut(), 'LORO(run)', a, mk, rows)
            naive = score(X, y, None, StratifiedKFold(5, shuffle=True, random_state=42),
                          'naive StratifiedKFold', a, mk, rows, grouped=False)
            summ.append(dict(attack=DISP[a], model=mk, logo_run_node=round(g_node, 3),
                             lono_node_id=round(g_id, 3), loro_run=round(g_run, 3),
                             naive=round(naive, 3),
                             leakage_identity=round(g_node - g_id, 3),
                             shift_run=round(g_id - g_run, 3),
                             delta_loro_minus_logo=round(g_run - g_node, 3)))
            print(f'{DISP[a]:10} {mk:3} LOGO(run,node)={g_node:.3f}  LONO(node)={g_id:.3f}  '
                  f'LORO(run)={g_run:.3f}  naive={naive:.3f}', flush=True)
    pd.DataFrame(rows).to_csv('loro_comparison.csv', index=False)
    s = pd.DataFrame(summ)
    s.to_csv('loro_comparison_summary.csv', index=False)
    print('\n### Means ###')
    print(s.groupby('model')[['logo_run_node', 'lono_node_id', 'loro_run', 'naive']].mean().round(3).to_string())
    print('\nwrote: loro_comparison.csv, loro_comparison_summary.csv')


if __name__ == '__main__':
    main()
