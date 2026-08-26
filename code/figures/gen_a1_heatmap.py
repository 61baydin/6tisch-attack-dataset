#!/usr/bin/env python3
"""a1 (tek saldirganli) naif satir-duzeyi RF F1 isi haritasi, (saldiri x yerlesim).

a5 grup-farkinda placement_heatmap'in karsiligi: a1'de grup-farkinda tahmin
anlamli degil (saldiri basina 3 grup), bu yuzden naif (satir-duzeyi,
StratifiedKFold) RF F1 gosterilir; her yerde 1.0'a doygun cikmasi makalenin
uyardigi sizintiinin gorsel kanitidir.

Girdi : core_a1_naive.csv  (eval_a1_naive.py ile uretilir)
Cikti : paper/figures/a1_placement_heatmap.pdf
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt

SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('core_a1_naive.csv')
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('paper/figures')
OUT.mkdir(parents=True, exist_ok=True)

attacks = ['Blackhole', 'Decreased Rank', 'DIS Flooding', 'App Flooding',
           'Shared Cell', '6P Cell Exh.', 'TSCH Desync.']
SRCNAME = {'Blackhole': 'Blackhole', 'Decreased Rank': 'Decrease', 'DIS Flooding': 'DIS',
           'App Flooding': 'AppFlood', 'Shared Cell': 'Shared', '6P Cell Exh.': '6P',
           'TSCH Desync.': 'Desync'}
placements = ['core', 'mid', 'edge']

d = pd.read_csv(SRC)
fig, axes = plt.subplots(1, 2, figsize=(11, 6))
for ax, scale in zip(axes, [21, 31]):
    arr = np.array([[d[(d.scale == scale) & (d.attack == SRCNAME[a]) &
                       (d.placement == p)].RF_naive.iloc[0] for p in placements]
                    for a in attacks])
    im = ax.imshow(arr, cmap='RdYlGn', vmin=0, vmax=1, aspect='auto')
    ax.set_xticks(range(3)); ax.set_xticklabels(placements, fontsize=11)
    ax.set_yticks(range(len(attacks)))
    ax.set_yticklabels(attacks if scale == 21 else [], fontsize=10)
    ax.set_title(f'{scale}-mote (1 attacker)', fontsize=12, fontweight='bold')
    for i in range(len(attacks)):
        for j in range(3):
            v = arr[i, j]
            ax.text(j, i, '%.2f' % v, ha='center', va='center',
                    color='white' if (v < 0.35 or v > 0.85) else 'black',
                    fontsize=10, fontweight='bold')
plt.suptitle('1-attacker naive row-level RF F1: attack x placement\n'
             '(StratifiedKFold k=5; group-aware infeasible at a1)', fontsize=12)
fig.colorbar(im, ax=axes, fraction=0.025, pad=0.04, label='RF naive (row-level) F1')
plt.savefig(OUT / 'a1_placement_heatmap.pdf', bbox_inches='tight')
print('Wrote', OUT / 'a1_placement_heatmap.pdf')
