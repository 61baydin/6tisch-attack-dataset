#!/usr/bin/env python3
"""Generate the 31-mote analogues of feature_signature
so the paper has parity with the 21-mote main-chain figures."""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = Path('paper/figures')
OUT.mkdir(parents=True, exist_ok=True)


def fig_feature_signature_31():
    attacks = ['Blackhole', 'Decreased\nRank', 'DIS\nFlooding', 'App\nFlooding',
               'Shared\nCell', '6P Cell\nExh.', 'TSCH\nDesync.']
    atk_ppm  = [3.97,    4.00,   4.01,   59.26,  2.64,   4.00,   3.99]
    nrm_ppm  = [5.91,    8.39,   8.39,   19.08,  7.22,   8.27,   8.19]
    atk_ctrl = [17.93,   15.90,  41.02,  15.38,  10.62,  23.79,  17.02]
    nrm_ctrl = [13.85,   15.76,  20.91,  15.55,  14.09,  15.41,  15.52]
    atk_rank = [1229.22, 734.77, 1075.20, 1041.07, 1058.59, 1075.20, 1041.96]
    nrm_rank = [1226.48, 940.94, 1094.60, 1017.44, 1080.59, 1071.85, 1072.35]
    atk_buf  = [8.36,    4.41,   2.68,   6.84,   3.05,   0.88,   2.90]
    nrm_buf  = [11.97,   2.93,   3.12,   3.36,   3.99,   3.12,   3.84]

    fig, axes = plt.subplots(2, 2, figsize=(14, 8.4))
    x = np.arange(len(attacks))
    w = 0.38
    panels = [
        (atk_ppm,  nrm_ppm,  'AtkPpm vs NrmPpm (app packets / min)', 'packets / min'),
        (atk_ctrl, nrm_ctrl, 'AtkCtrl vs NrmCtrl: delta(DIO+DAO+DIS)', 'count'),
        (atk_rank, nrm_rank, 'AtkRank vs NrmRank (mean RPL rank)',    'rank'),
        (atk_buf,  nrm_buf,  'AtkBuf vs NrmBuf (mean buffer occupancy)', '% of queue'),
    ]
    for ax, (atk, nrm, title, ylab) in zip(axes.flat, panels):
        rects_atk = ax.bar(x - w / 2, atk, w, label='Attacker (Atk)',
                           color='#d62728', edgecolor='black', linewidth=0.5)
        rects_nrm = ax.bar(x + w / 2, nrm, w, label='Normal (Nrm)',
                           color='#1f77b4', edgecolor='black', linewidth=0.5)
        fmt = '%.0f' if max(max(atk), max(nrm)) > 100 else '%.2f'
        ax.bar_label(rects_atk, fmt=fmt, fontsize=7, padding=2)
        ax.bar_label(rects_nrm, fmt=fmt, fontsize=7, padding=2)
        ax.set_xticks(x)
        ax.set_xticklabels(attacks, fontsize=9, rotation=0)
        ax.set_title(title, fontsize=11)
        ax.set_ylabel(ylab, fontsize=10)
        ax.grid(True, axis='y', linestyle=':', alpha=0.5)
        ymax = max(max(atk), max(nrm))
        ax.set_ylim(0, ymax * 1.15)
        ax.legend(fontsize=9, loc='upper right')
    plt.suptitle('Within-run feature contrast (31-mote scale chain)',
                 fontsize=13, y=1.00)
    plt.tight_layout()
    out_png = OUT / 'feature_signature_31mote.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


if __name__ == '__main__':
    fig_feature_signature_31()
