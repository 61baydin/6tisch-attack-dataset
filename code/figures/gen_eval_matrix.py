#!/usr/bin/env python3
"""2x2 evaluation matrix: rows = {naive, group-aware}, cols = {a5, a1};
each cell a 7-attack x 3-placement F1 heatmap (21-mote, Random Forest).
Shows the full result richness in one view.
Values from new_placement_f1.csv (rf_naive / rf_group, scale=21).
"""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = Path('paper/figures'); OUT.mkdir(parents=True, exist_ok=True)
attacks = ['Blackhole', 'Decreased Rank', 'DIS Flooding', 'App Flooding',
           'Shared Cell', '6P Cell Exh.', 'TSCH Desync.']
pl = ['core', 'mid', 'edge']

NAIVE_A5 = [[0.99,0.96,0.99],[1.0,1.0,1.0],[1.0,1.0,1.0],[1.0,1.0,1.0],[0.94,0.97,0.99],[1.0,1.0,1.0],[1.0,1.0,1.0]]
NAIVE_A1 = [[0.98,0.93,1.0],[1.0,1.0,1.0],[0.99,1.0,0.99],[1.0,1.0,1.0],[0.99,0.98,0.99],[1.0,1.0,1.0],[1.0,1.0,1.0]]
GROUP_A5 = [[0.73,0.48,0.24],[1.0,0.64,0.71],[0.98,0.99,0.94],[0.79,0.38,0.38],[0.53,0.44,0.56],[1.0,1.0,1.0],[0.79,0.59,0.78]]
GROUP_A1 = [[0.06,0.0,0.0],[0.0,0.0,0.0],[0.0,0.0,0.0],[0.0,0.0,0.0],[0.0,0.0,0.0],[0.0,0.0,0.0],[0.0,0.0,0.0]]

panels = [('Naive - a5 (5-attacker)', NAIVE_A5, 0, 0),
          ('Naive - a1 (1-attacker)', NAIVE_A1, 0, 1),
          ('Group-aware - a5',      GROUP_A5, 1, 0)]

fig, axes = plt.subplots(2, 2, figsize=(12.5, 9.5))
im = None
for title, data, r, c in panels:
    ax = axes[r][c]
    arr = np.array(data)
    im = ax.imshow(arr, cmap='RdYlGn', vmin=0, vmax=1.0, aspect='auto')
    ax.set_xticks(range(3)); ax.set_xticklabels(pl, fontsize=10)
    if c == 0:
        ax.set_yticks(range(len(attacks))); ax.set_yticklabels(attacks, fontsize=9)
    else:
        ax.set_yticks(range(len(attacks))); ax.set_yticklabels([])
    ax.set_title(title, fontsize=12, fontweight='bold')
    for i in range(len(attacks)):
        for j in range(3):
            v = arr[i, j]
            col = 'white' if v < 0.4 or v > 0.85 else 'black'
            ax.text(j, i, f'{v:.2f}', ha='center', va='center',
                    color=col, fontsize=9, fontweight='bold')

# Group-aware a1: not applicable (3 groups per attack) -> note instead of panel
axes[1][1].axis('off')
axes[1][1].text(0.5, 0.5,
                'Group-aware - a1\n\n(not applicable:\n3 groups per attack)',
                ha='center', va='center', fontsize=12,
                color='gray', style='italic',
                transform=axes[1][1].transAxes)
fig.suptitle('Detection F1 matrix: attack x placement (21-mote, Random Forest)\n'
             'row = evaluation method, column = attacker density',
             fontsize=13)
fig.colorbar(im, ax=axes, fraction=0.025, pad=0.04, label='binary F1')
out = OUT / 'eval_matrix_2x2.png'
plt.savefig(out, dpi=140, bbox_inches='tight')
plt.savefig(out.with_suffix('.pdf'), bbox_inches='tight')
plt.close()
print(f'Wrote {out.with_suffix(".pdf")} + .png')
