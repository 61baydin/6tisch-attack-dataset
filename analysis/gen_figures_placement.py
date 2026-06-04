#!/usr/bin/env python3
"""Generate feature_signature for 21-mote placement chain.

Replaces the old random-main-chain numbers in gen_result_figures.py.
The 31-mote feature signatures are unchanged because
the 31-mote scale chain was already the placement chain.
"""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT = Path('paper/figures')
OUT.mkdir(parents=True, exist_ok=True)


def fig_feature_signature():
    attacks = ['Blackhole', 'Decreased\nRank', 'DIS\nFlooding', 'App\nFlooding',
               'Shared\nCell', '6P Cell\nExh.', 'TSCH\nDesync.']
    # 21-mote placement chain (a5+a1 pooled, 6 cells per attack)
    atk_ppm  = [3.98,    4.00,   4.00,   14.95,  2.67,   4.00,   4.01]
    nrm_ppm  = [7.15,    8.15,   8.12,   9.99,   7.06,   8.21,   8.22]
    atk_ctrl = [18.60,   15.51,  39.96,  15.65,  11.02,  23.39,  15.33]
    nrm_ctrl = [15.86,   15.32,  20.02,  14.98,  13.50,  15.01,  15.05]
    atk_rank = [1056.81, 648.89, 953.71, 955.12, 981.33, 952.89, 967.11]
    nrm_rank = [1065.54, 851.37, 945.96, 946.50, 961.41, 950.55, 955.26]
    atk_buf  = [7.28,    5.28,   4.10,   4.90,   3.86,   0.78,   4.37]
    nrm_buf  = [7.37,    2.67,   2.67,   2.81,   3.93,   2.70,   2.55]

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
        ra = ax.bar(x - w/2, atk, w, label='Attacker (Atk)', color='#d62728',
                    edgecolor='black', linewidth=0.5)
        rn = ax.bar(x + w/2, nrm, w, label='Normal (Nrm)', color='#1f77b4',
                    edgecolor='black', linewidth=0.5)
        fmt = '%.0f' if max(max(atk), max(nrm)) > 100 else '%.2f'
        ax.bar_label(ra, fmt=fmt, fontsize=7, padding=2)
        ax.bar_label(rn, fmt=fmt, fontsize=7, padding=2)
        ax.set_xticks(x); ax.set_xticklabels(attacks, fontsize=9)
        ax.set_title(title, fontsize=11)
        ax.set_ylabel(ylab, fontsize=10)
        ax.grid(True, axis='y', linestyle=':', alpha=0.5)
        ax.set_ylim(0, max(max(atk), max(nrm)) * 1.15)
        ax.legend(fontsize=9, loc='upper right')
    plt.suptitle('Within-run feature contrast (21-mote placement chain, '
                 '42 runs pooled across core/mid/edge × {1, 5 attackers})',
                 fontsize=12, y=1.00)
    plt.tight_layout()
    out_png = OUT / 'feature_signature.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


if __name__ == '__main__':
    fig_feature_signature()
