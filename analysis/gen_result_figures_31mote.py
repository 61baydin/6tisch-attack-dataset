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
    atk_ppm  = [3.74,    3.99,   4.00,   14.98,  0.00,   4.00,   4.00]
    nrm_ppm  = [6.08,    8.13,   8.13,   9.31,   7.71,   8.13,   8.13]
    atk_ctrl = [17.13,   15.55,  38.97,  16.11,  15.99,  23.59,  15.95]
    nrm_ctrl = [14.84,   15.65,  19.97,  15.52,  15.52,  15.44,  15.44]
    atk_rank = [1239.06, 763.11, 1066.67, 1095.11, 1052.44, 1080.89, 1052.44]
    nrm_rank = [1232.10, 994.50, 1061.94, 1081.57, 1065.17, 1087.64, 1068.57]
    atk_buf  = [7.64,    3.86,   3.37,   3.14,   2.97,   0.96,   3.60]
    nrm_buf  = [11.15,   3.15,   3.22,   3.18,   3.11,   3.23,   3.06]

    fig, axes = plt.subplots(2, 2, figsize=(14, 8.4))
    x = np.arange(len(attacks))
    w = 0.38
    panels = [
        (atk_ppm,  nrm_ppm,  'AtkPpm vs NrmPpm (app packets / min)', 'packets / min'),
        (atk_ctrl, nrm_ctrl, 'AtkCtrl vs NrmCtrl: delta(DIO+DAO+DIS)', 'count'),
        (atk_rank, nrm_rank, 'AtkRank vs NrmRank (mean RPL rank)',    'rank'),
        (atk_buf,  nrm_buf,  'AtkBuf vs NrmBuf (mean buffer occupancy)', 'packets'),
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
