#!/usr/bin/env python3
"""a1 (1-attacker) naive row-level RF F1 heatmap by (attack, placement).

Parallel to the a5 group-aware placement_heatmap, but for the 1-attacker
density: group-aware is infeasible at a1 (3 groups/attack), so this shows
the naive (row-level, StratifiedKFold) RF F1 -- which saturates near 1.0
everywhere, the visual proof of the leakage the thesis warns about.

Values pulled from new_placement_f1.csv (density=1, rf_naive).
"""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = Path('paper/figures')
OUT.mkdir(parents=True, exist_ok=True)

attacks = ['Blackhole', 'Decreased Rank', 'DIS Flooding', 'App Flooding',
           'Shared Cell', '6P Cell Exh.', 'TSCH Desync.']
placements = ['core', 'mid', 'edge']

# a1 naive (row-level) Random Forest F1, per (attack, placement)
f1_21 = [
    [1.000, 0.998, 0.996],
    [1.000, 0.998, 0.998],
    [0.998, 0.998, 0.996],
    [1.000, 0.998, 1.000],
    [0.986, 0.972, 0.995],
    [0.998, 0.998, 0.996],
    [1.000, 1.000, 0.998],
]
f1_31 = [
    [0.998, 0.852, 1.000],
    [1.000, 0.990, 1.000],
    [0.998, 0.997, 0.998],
    [0.998, 1.000, 1.000],
    [0.938, 0.967, 0.996],
    [1.000, 0.998, 0.996],
    [0.996, 0.996, 0.998],
]

fig, axes = plt.subplots(1, 2, figsize=(13, 6))
titles = ['21-mote (1 attacker)', '31-mote (1 attacker)']
for ax, data, title in zip(axes, [f1_21, f1_31], titles):
    arr = np.array(data)
    im = ax.imshow(arr, cmap='RdYlGn', vmin=0, vmax=1.0, aspect='auto')
    ax.set_xticks(range(3))
    ax.set_xticklabels(placements, fontsize=11)
    ax.set_yticks(range(len(attacks)))
    ax.set_yticklabels(attacks, fontsize=10)
    ax.set_title(title, fontsize=12)
    for i in range(len(attacks)):
        for j in range(3):
            v = arr[i, j]
            col = 'white' if v < 0.4 or v > 0.85 else 'black'
            ax.text(j, i, f'{v:.2f}', ha='center', va='center',
                    color=col, fontsize=10, fontweight='bold')
    plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label='RF naive (row-level) F1')
plt.suptitle('1-attacker naive row-level RF F1: attack x placement '
             '(StratifiedKFold k=5; group-aware infeasible at a1)', fontsize=13)
plt.tight_layout()
out_png = OUT / 'a1_placement_heatmap.png'
plt.savefig(out_png, dpi=140, bbox_inches='tight')
plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
plt.close()
print(f'Wrote {out_png.with_suffix(".pdf")} + .png')
