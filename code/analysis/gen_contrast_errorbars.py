#!/usr/bin/env python3
"""Within-run feature contrasts with dispersion across runs.

The earlier version of these figures plotted a single pooled mean per family and
carried no error bars, because the contrast was computed once over all runs of a
scale. With the three-seed replication chain each family has up to nine runs per
scale (three placement zones times three radio seeds), so the same contrast can be
shown as a mean over runs with its standard deviation.

Input: contrast_per_run.csv (compute_contrasts_spread.py)
Output: feature_signature.pdf, feature_signature_31mote.pdf
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else 'paper/figures')
OUT.mkdir(parents=True, exist_ok=True)
EXT = sys.argv[2] if len(sys.argv) > 2 else 'pdf'
ORDER = ['blackhole', 'decrease', 'dis', 'flooding', 'shared-slot', 'slot-exhaustion', 'timekeep']
LABEL = ['Blackhole', 'Decreased\nRank', 'DIS\nFlooding', 'App\nFlooding',
         'Shared\nCell', '6P Cell\nExh.', 'TSCH\nDesync.']
PANELS = [('ppm', 'AtkPpm vs NrmPpm (app packets / min)', 'packets / min'),
          ('ctrl', 'AtkCtrl vs NrmCtrl: delta(DIO+DAO+DIS)', 'count'),
          ('rank', 'AtkRank vs NrmRank (mean RPL rank)', 'rank'),
          ('buf', 'AtkBuf vs NrmBuf (mean buffer occupancy)', '% of queue')]

d = pd.read_csv('contrast_per_run.csv')

for scale, out in [(21, 'feature_signature'), (31, 'feature_signature_31mote')]:
    sub = d[d.scale == scale]
    n_runs = int(sub.groupby('attack').size().max())
    fig, axes = plt.subplots(2, 2, figsize=(14, 8.8))
    x = np.arange(len(ORDER)); w = 0.38
    for ax, (key, title, ylab) in zip(axes.flat, PANELS):
        am = [sub[sub.attack == a][f'atk_{key}'].mean() for a in ORDER]
        asd = [sub[sub.attack == a][f'atk_{key}'].std(ddof=1) for a in ORDER]
        nm = [sub[sub.attack == a][f'nrm_{key}'].mean() for a in ORDER]
        nsd = [sub[sub.attack == a][f'nrm_{key}'].std(ddof=1) for a in ORDER]
        ra = ax.bar(x - w/2, am, w, yerr=asd, capsize=3, label='Attacker (Atk)',
                    color='#d62728', edgecolor='black', linewidth=0.5,
                    error_kw=dict(ecolor='0.25', lw=1.1))
        rn = ax.bar(x + w/2, nm, w, yerr=nsd, capsize=3, label='Normal (Nrm)',
                    color='#1f77b4', edgecolor='black', linewidth=0.5,
                    error_kw=dict(ecolor='0.25', lw=1.1))
        fmt = '%.0f' if max(max(am), max(nm)) > 100 else '%.2f'
        ax.bar_label(ra, fmt=fmt, fontsize=9, padding=3)
        ax.bar_label(rn, fmt=fmt, fontsize=9, padding=3)
        ax.set_xticks(x); ax.set_xticklabels(LABEL, fontsize=11.5)
        ax.set_title(title, fontsize=13); ax.set_ylabel(ylab, fontsize=12)
        ax.grid(True, axis='y', linestyle=':', alpha=0.5)
        top = max(np.array(am) + np.array(asd)); top = max(top, max(np.array(nm) + np.array(nsd)))
        ax.set_ylim(0, top * 1.18)
        ax.legend(fontsize=11, loc='upper right')
        ax.tick_params(labelsize=11)
    fig.suptitle(f'Within-run attacker and normal pool means, {scale}-mote five-attacker runs '
                 f'(mean over {n_runs} runs, error bars are one standard deviation)', fontsize=13)
    plt.tight_layout()
    fig.savefig(OUT / f'{out}.{EXT}', bbox_inches='tight', **({'dpi': 130} if EXT == 'png' else {}))
    plt.close(fig)
    print('wrote', OUT / f'{out}.{EXT}')
