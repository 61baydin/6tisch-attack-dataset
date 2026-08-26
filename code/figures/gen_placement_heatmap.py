#!/usr/bin/env python3
"""Sekil: yerlesime gore LR ikili grup-farkinda F1 isi haritasi (tab:placement ile ayni kaynak).

Girdi : core_placement.csv  (eval_core_tables.py placement ile uretilir)
Cikti : paper/figures/placement_heatmap.pdf
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt

SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('core_placement.csv')
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('paper/figures')
ORDER = ['Blackhole', 'Decreased Rank', 'DIS Flooding', 'App Flooding',
         'Shared Cell', '6P Cell Exh.', 'TSCH Desync.']
SRCNAME = {'Blackhole': 'Blackhole', 'Decreased Rank': 'Decrease', 'DIS Flooding': 'DIS',
           'App Flooding': 'AppFlood', 'Shared Cell': 'Shared', '6P Cell Exh.': '6P',
           'TSCH Desync.': 'Desync'}
PL = ['core', 'mid', 'edge']

d = pd.read_csv(SRC)
fig, axes = plt.subplots(1, 2, figsize=(11, 6))
for ax, scale in zip(axes, [21, 31]):
    arr = np.array([[d[(d.scale == scale) & (d.attack == SRCNAME[a]) &
                       (d.placement == p)].LR.iloc[0] for p in PL] for a in ORDER])
    im = ax.imshow(arr, cmap='RdYlGn', vmin=0, vmax=1, aspect='auto')
    ax.set_xticks(range(3)); ax.set_xticklabels(PL, fontsize=11)
    ax.set_yticks(range(len(ORDER)))
    ax.set_yticklabels(ORDER if scale == 21 else [], fontsize=10)
    ax.set_title(f'{scale}-mote (5 attackers)', fontsize=13, fontweight='bold')
    for i in range(len(ORDER)):
        for j in range(3):
            v = arr[i, j]
            ax.text(j, i, '%.2f' % v, ha='center', va='center',
                    color='white' if (v < 0.35 or v > 0.85) else 'black',
                    fontsize=10, fontweight='bold')
fig.suptitle('Logistic Regression binary F1: attack x placement\n'
             '(LeaveOneGroupOut, group=(run,node))', fontsize=12)
fig.colorbar(im, ax=axes, fraction=0.025, pad=0.04, label='binary F1')
OUT.mkdir(parents=True, exist_ok=True)
plt.savefig(OUT / 'placement_heatmap.pdf', bbox_inches='tight')
print('Wrote', OUT / 'placement_heatmap.pdf')
