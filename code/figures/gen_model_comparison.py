#!/usr/bin/env python3
"""Sekil: 17 modelin grup-farkinda ve naif satir-duzeyi F1 karsilastirmasi.

Girdi : core_model_comparison.csv (eval_naive_baseline.py ile uretilir; grup-farkinda
        yari sweep_w16_perfold.csv'den, naif yari naive_w16_perfold.csv'den gelir)
Cikti : paper/figures/model_comparison.pdf
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

SRC = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('core_model_comparison.csv')
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('paper/figures')
OUT.mkdir(parents=True, exist_ok=True)

d = pd.read_csv(SRC).sort_values('group_f1', ascending=False)
names = d.iloc[:, 0].tolist() if d.columns[0] not in ('group_f1',) else d.index.tolist()
grp, naive, fam = d.group_f1.tolist(), d.naive_f1.tolist(), d.family.tolist()
y = np.arange(len(names))[::-1]

fig, ax = plt.subplots(figsize=(8.5, 7.4))
for yi, g, n, f in zip(y, grp, naive, fam):
    ax.plot([g, n], [yi, yi], color='0.78', lw=2, zorder=1)
    ax.scatter(n, yi, marker='o', s=34, color='0.65', zorder=2)
    ax.scatter(g, yi, marker='D', s=58, color='#1f77b4' if f == 'DL' else '#d62728',
               edgecolor='black', lw=0.5, zorder=3)
ax.set_yticks(y); ax.set_yticklabels(names, fontsize=13)
ax.set_xlabel('Mean per-attack F1 (detection)', fontsize=14)
ax.set_xlim(min(grp) - 0.05, min(1.02, max(naive) + 0.03))
ax.axvline(max(g for g, f in zip(grp, fam) if f == 'CL'), ls=':', color='0.4', lw=1)
ax.grid(True, axis='x', ls=':', alpha=0.5)
leg = [Line2D([0], [0], marker='D', color='w', markerfacecolor='#1f77b4', markeredgecolor='k',
              markersize=9, label='Deep (windowed), group-aware'),
       Line2D([0], [0], marker='D', color='w', markerfacecolor='#d62728', markeredgecolor='k',
              markersize=9, label='Classical/ensemble, group-aware'),
       Line2D([0], [0], marker='o', color='0.65', markersize=8, label='Naive (row-level), leakage'),
       Line2D([0], [0], color='0.78', lw=2, label='Naive minus group leakage gap')]
ax.legend(handles=leg, fontsize=11, loc='upper center', bbox_to_anchor=(0.5, -0.11),
          ncol=2, framealpha=0.95)
ax.set_title('Seventeen-model detection comparison (W=16 windows,\n'
             'StratifiedGroupKFold $k$=5, 21+31-mote pooled)', fontsize=13)
plt.tight_layout()
plt.savefig(OUT / 'model_comparison.pdf', bbox_inches='tight')
print('Wrote', OUT / 'model_comparison.pdf')
