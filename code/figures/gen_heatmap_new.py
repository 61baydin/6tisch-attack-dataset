#!/usr/bin/env python3
"""New dataset placement heatmap (LR group-aware, 17 features, a5).
Values from analyze_placement.py output (within-run per-placement LR)."""
from pathlib import Path
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

attacks = ['Blackhole','Decreased Rank','DIS Flooding','App Flooding',
           'Shared Cell','6P Cell Exh.','TSCH Desync.']
pl = ['core','mid','edge']
# LR group-aware, per-placement (analyze_placement.py)
LR21 = [[0.56,0.74,0.53],[0.98,0.55,0.96],[0.96,0.96,0.94],[0.98,1.00,1.00],
        [0.40,0.28,0.17],[0.96,1.00,0.78],[0.70,0.47,0.44]]
LR31 = [[0.71,0.73,0.50],[0.89,0.85,0.98],[0.94,0.99,0.98],[1.00,0.99,0.99],
        [0.14,0.36,0.33],[0.99,1.00,1.00],[0.49,0.69,0.77]]

fig, axes = plt.subplots(1, 2, figsize=(11, 6))
for ax, data, title in [(axes[0], LR21, '21-mote'), (axes[1], LR31, '31-mote')]:
    arr = np.array(data)
    im = ax.imshow(arr, cmap='RdYlGn', vmin=0, vmax=1, aspect='auto')
    ax.set_xticks(range(3)); ax.set_xticklabels(pl, fontsize=11)
    ax.set_yticks(range(len(attacks)))
    ax.set_yticklabels(attacks if title == '21-mote' else [], fontsize=10)
    ax.set_title(title, fontsize=13, fontweight='bold')
    for i in range(len(attacks)):
        for j in range(3):
            v = arr[i, j]
            c = 'white' if (v < 0.35 or v > 0.85) else 'black'
            ax.text(j, i, '%.2f' % v, ha='center', va='center', color=c,
                    fontsize=10, fontweight='bold')
fig.suptitle('Detection F1 (LR, group-aware), attack x placement, a5\n'
             '17 features (base + forward_ratio/bcast_tx + rank_increase/d_app)',
             fontsize=12)
fig.colorbar(im, ax=axes, fraction=0.025, pad=0.04, label='binary F1')
out = Path('paper/figures/placement_heatmap')
plt.savefig(str(out)+'.pdf', bbox_inches='tight')
plt.savefig(str(out)+'.png', dpi=140, bbox_inches='tight')
print('Wrote', out, '.pdf/.png')
