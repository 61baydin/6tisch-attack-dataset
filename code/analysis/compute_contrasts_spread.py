#!/usr/bin/env python3
"""Per-run feature-signature contrasts with dispersion.

compute_contrasts.py pools every run of a scale into a single mean, which is why
the contrast figures carried no error bars. This computes the same four contrasts
per run, so the figure can show the mean over runs and its spread. With the
three-seed replication chain each attack family now has up to nine runs per scale
(three placement zones times three radio seeds).

Output: contrast_per_run.csv, contrast_summary.csv
"""
import re, glob
from pathlib import Path
import numpy as np, pandas as pd

RX = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
ATT = ['blackhole', 'decrease', 'dis', 'flooding', 'shared-slot', 'slot-exhaustion', 'timekeep']
DISP = {'blackhole': 'Blackhole', 'decrease': 'Decreased Rank', 'dis': 'DIS Flooding',
        'flooding': 'App Flooding', 'shared-slot': 'Shared Cell',
        'slot-exhaustion': '6P Cell Exh.', 'timekeep': 'TSCH Desync.'}
WIN = 1500          # attack window, as in compute_contrasts.py


def rows(fn):
    o = []
    for ln in open(fn, errors='replace'):
        m = RX.search(ln)
        if not m:
            continue
        v = [int(x) for x in m.group(1).split(',') if x.strip() != '']
        if len(v) == 20:
            o.append(v)
    return o


def node_rate(recs, col):
    recs = sorted(recs)
    if len(recs) < 2:
        return 0.0
    dt = (recs[-1][0] - recs[0][0]) / 60.0
    return (recs[-1][col] - recs[0][col]) / dt if dt > 0 else 0.0


def pool(byn):
    if not byn:
        return None
    ppm = [node_rate(r, 15) for r in byn.values()]
    ctrl = [node_rate(r, 5) + node_rate(r, 6) + node_rate(r, 7) for r in byn.values()]
    rank = [np.mean([x[3] for x in r]) for r in byn.values()]
    buf = [np.mean([x[4] for x in r]) for r in byn.values()]
    return float(np.mean(ppm)), float(np.mean(ctrl)), float(np.mean(rank)), float(np.mean(buf))


def main():
    recs = []
    for sc in ['21', '31']:
        for atk in ATT:
            pats = [f'dataset_v3/single/logs/*_{atk}-n{sc}-*-a5-w*.log',
                    f'dataset_v3/multiseed/logs/*_{atk}-n{sc}-*-a5-s*-w*.log']
            files = [f for p in pats for f in glob.glob(p) if not Path(f).name.startswith('cooja_')]
            for fn in sorted(files):
                byn_atk, byn_nrm = {}, {}
                for v in rows(fn):
                    if v[0] < WIN:
                        continue
                    (byn_atk if v[18] == 1 else byn_nrm).setdefault(v[1], []).append(v)
                a, n = pool(byn_atk), pool(byn_nrm)
                if a is None or n is None:
                    continue
                seed = re.search(r'-s(\d+)-w', fn)
                recs.append(dict(scale=sc, attack=atk, run=Path(fn).stem,
                                 seed=seed.group(1) if seed else '123456',
                                 atk_ppm=a[0], nrm_ppm=n[0], atk_ctrl=a[1], nrm_ctrl=n[1],
                                 atk_rank=a[2], nrm_rank=n[2], atk_buf=a[3], nrm_buf=n[3]))
            print(f'  n{sc} {atk}: {len([r for r in recs if r["scale"]==sc and r["attack"]==atk])} runs',
                  flush=True)
    d = pd.DataFrame(recs)
    d.to_csv('contrast_per_run.csv', index=False)
    cols = [c for c in d.columns if c.startswith(('atk_', 'nrm_'))]
    g = d.groupby(['scale', 'attack'])[cols]
    summ = g.mean().round(2).join(g.std().round(2), rsuffix='_sd').join(
        d.groupby(['scale', 'attack']).size().rename('n'))
    summ.to_csv('contrast_summary.csv')
    print('\n' + summ.to_string())
    print('\nwrote: contrast_per_run.csv, contrast_summary.csv')


if __name__ == '__main__':
    main()
