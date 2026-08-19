#!/usr/bin/env python3
"""Multi-seed analysis: per-cell distributions, confidence intervals and significance
tests (reviewer items R5-1, R5-2 and the remaining part of R4-I22).

Every (attack, scale, placement) cell was run under three Cooja radio seeds:
  123456 -> the published benchmark chain (data/single/)
  7331, 9173 -> the replication chain generated for this revision (data/multiseed/)
Each cell and seed is scored with the per-record Logistic Regression under
LeaveOneGroupOut, which is the protocol of the placement table in the paper. Reported:
  * per-cell mean, standard deviation and 95% confidence interval (t, n=3)
  * paired significance tests for the placement and scale comparisons

Output: multiseed_cells.csv, multiseed_summary.csv, multiseed_tests.txt
"""
import glob, os, re, sys, warnings, collections
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from scipy import stats

ATT = ['blackhole', 'decrease', 'dis', 'flooding', 'shared-slot', 'slot-exhaustion', 'timekeep']
DISP = {'blackhole': 'Blackhole', 'decrease': 'Decreased Rank', 'dis': 'DIS Flooding',
        'flooding': 'Application Flooding', 'shared-slot': 'TSCH Shared Cell',
        'slot-exhaustion': '6P Cell Exhaustion', 'timekeep': 'TSCH Desynchronization'}
ATYPE = {a: i for i, a in enumerate(ATT, 1)}
BASE = ['rank', 'buf_occupancy', 'dio_sent', 'dao_sent', 'dis_sent', 'nbr_count', 'tx_slot_count',
        'parent_switch_count', 'rssi', 'route_count', 'delta_tx', 'delta_rx', 'app_packet_count']
COLS = ['timestamp', 'node_id', 'parent_id'] + BASE + ['forward_ratio', 'bcast_tx',
                                                       'is_attacker', 'attack_type']
FEAT = BASE + ['forward_ratio', 'bcast_tx', 'rank_increase', 'd_app']
RX = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
SEEDS = ['123456', '7331', '9173']
PLACEMENTS = ['core', 'mid', 'edge']


def parse(fn):
    out = []
    with open(fn, errors='replace') as fh:
        for ln in fh:
            m = RX.search(ln)
            if m:
                v = [int(x) for x in m.group(1).split(',') if x.strip()]
                if len(v) == 20:
                    out.append(v)
    return out


def find_log(attack, nodes, placement, seed):
    """Locate the log of a cell for a given seed (newest match wins)."""
    if seed == '123456':
        pat = f'dataset_v3/single/logs/*_{attack}-n{nodes}-{placement}-a5-w*.log'
    else:
        pat = f'*_{attack}-n{nodes}-{placement}-a5-s{seed}-w*.log'
    fs = [f for f in glob.glob(pat) if not os.path.basename(f).startswith('cooja_')]
    fs = [f for f in fs if os.path.getsize(f) > 100_000]
    return sorted(fs)[-1] if fs else None


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


def cell_f1(df, atype):
    """Per-record LR under LeaveOneGroupOut (group = node), averaged over the
    attacker-bearing folds: the protocol of the placement table in the paper."""
    X = df[FEAT].values.astype(float)
    y = ((df.attack_type.values == atype) & (df.is_attacker.values == 1)).astype(int)
    g = df.node_id.values
    if y.sum() == 0 or len(set(g[y == 1])) < 2:
        return np.nan, int(y.sum())
    f1s = []
    for tr, te in LeaveOneGroupOut().split(X, y, g):
        if len(np.unique(y[tr])) < 2 or y[te].sum() == 0:
            continue
        sc = StandardScaler().fit(X[tr])
        m = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
        m.fit(sc.transform(X[tr]), y[tr])
        f1s.append(f1_score(y[te], m.predict(sc.transform(X[te])), zero_division=0))
    return (float(np.mean(f1s)) if f1s else np.nan), int(y.sum())


def main():
    only = sys.argv[1].split(',') if len(sys.argv) > 1 else ATT
    rows = []
    for a in only:
        for nodes in ['21', '31']:
            for pl in PLACEMENTS:
                for sd in SEEDS:
                    fn = find_log(a, nodes, pl, sd)
                    if not fn:
                        rows.append(dict(attack=a, nodes=nodes, placement=pl, seed=sd,
                                         f1=np.nan, atk_rows=0, log=''))
                        print(f'  MISSING {a} n{nodes} {pl} s{sd}', flush=True)
                        continue
                    df = load(fn)
                    f1, natk = (cell_f1(df, ATYPE[a]) if df is not None else (np.nan, 0))
                    rows.append(dict(attack=a, nodes=nodes, placement=pl, seed=sd,
                                     f1=f1, atk_rows=natk, log=os.path.basename(fn)))
                    print(f'  {a:16} n{nodes} {pl:4} s{sd:6} F1={f1:.3f} atk_rows={natk}', flush=True)
        pd.DataFrame(rows).to_csv('multiseed_cells.csv', index=False)

    d = pd.DataFrame(rows)
    d.to_csv('multiseed_cells.csv', index=False)

    # --- per-cell distribution: mean, std, 95% CI (t, n=3) ---
    g = d.dropna(subset=['f1']).groupby(['attack', 'nodes', 'placement'])['f1']
    summ = g.agg(n='count', mean='mean', std='std').reset_index()
    tcrit = summ.n.apply(lambda n: stats.t.ppf(0.975, n - 1) if n > 1 else np.nan)
    summ['ci95'] = (tcrit * summ['std'] / np.sqrt(summ.n)).round(3)
    summ['mean'] = summ['mean'].round(3); summ['std'] = summ['std'].round(3)
    summ.to_csv('multiseed_summary.csv', index=False)
    print('\n### Per-cell mean +/- CI ###')
    print(summ.to_string(index=False))

    # --- significance tests ---
    out = []
    piv = d.dropna(subset=['f1']).pivot_table(index=['attack', 'nodes', 'seed'],
                                              columns='placement', values='f1')
    piv = piv.dropna()
    if len(piv) >= 3:
        fr = stats.friedmanchisquare(piv['core'], piv['mid'], piv['edge'])
        out.append(f'Placement (core/mid/edge) Friedman: chi2={fr.statistic:.2f}, p={fr.pvalue:.4f}, '
                   f'blocks={len(piv)}')
        for x, y in [('core', 'mid'), ('core', 'edge'), ('mid', 'edge')]:
            w = stats.wilcoxon(piv[x], piv[y])
            out.append(f'  {x} vs {y}: Wilcoxon p={w.pvalue:.4f}, mean difference='
                       f'{(piv[x]-piv[y]).mean():+.3f}')
    sc = d.dropna(subset=['f1']).pivot_table(index=['attack', 'placement', 'seed'],
                                             columns='nodes', values='f1').dropna()
    if len(sc) >= 3:
        w = stats.wilcoxon(sc['21'], sc['31'])
        out.append(f'Scale 21 vs 31: Wilcoxon p={w.pvalue:.4f}, mean difference='
                   f'{(sc["31"]-sc["21"]).mean():+.3f}, paired n={len(sc)}')
    sd_by_attack = d.dropna(subset=['f1']).groupby(['attack', 'nodes', 'placement'])['f1'].std() \
                    .groupby('attack').mean().round(3)
    out.append('\nMean within-cell std per attack family (seed variability):')
    for a, v in sd_by_attack.items():
        out.append(f'  {DISP.get(a,a):24} {v:.3f}')
    txt = '\n'.join(out)
    open('multiseed_tests.txt', 'w').write(txt + '\n')
    print('\n### Tests ###'); print(txt)
    print('\nwrote: multiseed_cells.csv, multiseed_summary.csv, multiseed_tests.txt')


if __name__ == '__main__':
    main()
