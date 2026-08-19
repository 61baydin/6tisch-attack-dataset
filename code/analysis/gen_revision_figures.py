#!/usr/bin/env python3
"""Two figures added in the revision.

  feature_importance.pdf  per-attack Random Forest importance of the 17 released
                          features, averaged over the group-aware folds
  multiseed_spread.pdf    per-cell F1 across the three Cooja radio seeds, which shows
                          how much of the placement structure is seed noise

Usage: python3 gen_revision_figures.py [output_dir]
"""
import sys
import numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else 'paper/figures')
OUT.mkdir(parents=True, exist_ok=True)
ORDER = ['Blackhole', 'Decrease', 'DIS', 'AppFlood', 'Shared', '6P', 'Desync']
NICE = {'Blackhole': 'Blackhole', 'Decrease': 'Decreased Rank', 'DIS': 'DIS Flooding',
        'AppFlood': 'App Flooding', 'Shared': 'TSCH Shared Cell',
        '6P': '6P Cell Exhaustion', 'Desync': 'TSCH Desync'}

# ---------- 1) feature importance heat map ----------
d = pd.read_csv('feature_importance_v3.csv')
piv = d.pivot(index='feature', columns='attack', values='importance')
piv = piv[[c for c in ORDER if c in piv.columns]]
piv = piv.loc[piv.max(axis=1).sort_values(ascending=False).index]

fig, ax = plt.subplots(figsize=(9.2, 7.6))
im = ax.imshow(piv.values, cmap='YlOrRd', aspect='auto', vmin=0, vmax=float(piv.values.max()))
ax.set_xticks(range(piv.shape[1]))
ax.set_xticklabels([NICE.get(c, c) for c in piv.columns], fontsize=12, rotation=28, ha='right')
ax.set_yticks(range(piv.shape[0])); ax.set_yticklabels(piv.index, fontsize=12)
for i in range(piv.shape[0]):
    for j in range(piv.shape[1]):
        v = piv.values[i, j]
        if v >= 0.02:
            ax.text(j, i, f'{v:.2f}', ha='center', va='center', fontsize=11,
                    color='white' if v > 0.35 else 'black', fontweight='bold')
ax.set_xlabel('Attack family', fontsize=14)
ax.set_ylabel('Released feature', fontsize=14)
ax.set_title('Random Forest feature importance per attack family\n'
             '(mean over group-aware folds, 21+31-mote five-attacker cells)', fontsize=13)
cb = plt.colorbar(im, ax=ax); cb.set_label('Gini importance', fontsize=12)
cb.ax.tick_params(labelsize=11)
plt.tight_layout(); plt.savefig(OUT / 'feature_importance.pdf', bbox_inches='tight')
plt.close(fig)
print('wrote', OUT / 'feature_importance.pdf')

# ---------- 2) multi-seed spread ----------
c = pd.read_csv('multiseed_cells.csv').dropna(subset=['f1'])
disp = {'blackhole': 'Blackhole', 'decrease': 'Decreased Rank', 'dis': 'DIS Flooding',
        'flooding': 'App Flooding', 'shared-slot': 'TSCH Shared Cell',
        'slot-exhaustion': '6P Cell Exh.', 'timekeep': 'TSCH Desync'}
fams = [f for f in ['blackhole', 'decrease', 'dis', 'flooding', 'shared-slot',
                    'slot-exhaustion', 'timekeep'] if f in set(c.attack)]
placements = ['core', 'mid', 'edge']
colors = {'core': '#1f77b4', 'mid': '#2ca02c', 'edge': '#d62728'}

fig, axes = plt.subplots(1, 2, figsize=(12.5, 5.4), sharey=True)
for ax, scale in zip(axes, ['21', '31']):
    for xi, fam in enumerate(fams):
        for pi, pl in enumerate(placements):
            sub = c[(c.attack == fam) & (c.nodes.astype(str) == scale) & (c.placement == pl)]
            if not len(sub):
                continue
            x = xi + (pi - 1) * 0.24
            ax.scatter([x] * len(sub), sub.f1.values, s=26, color=colors[pl], zorder=3,
                       label=pl if (xi == 0 and scale == '21') else None)
            if len(sub) > 1:
                ax.plot([x, x], [sub.f1.min(), sub.f1.max()], color=colors[pl], lw=2,
                        alpha=0.45, zorder=2)
    ax.set_xticks(range(len(fams)))
    ax.set_xticklabels([disp[f] for f in fams], rotation=32, ha='right', fontsize=11.5)
    ax.set_title(f'{"21" if scale == "21" else "31"}-mote', fontsize=13)
    ax.grid(axis='y', ls=':', alpha=0.5)
    ax.tick_params(labelsize=11.5)
axes[0].set_ylabel('Group-aware binary F1', fontsize=13)
axes[0].set_ylim(-0.02, 1.05)
axes[0].legend(title='placement', fontsize=11, title_fontsize=11, loc='lower left')
fig.suptitle('Per-cell F1 across three Cooja radio seeds: the vertical bar is the spread '
             'of one cell', fontsize=13)
plt.tight_layout(); plt.savefig(OUT / 'multiseed_spread.pdf', bbox_inches='tight')
plt.close(fig)
print('wrote', OUT / 'multiseed_spread.pdf')
