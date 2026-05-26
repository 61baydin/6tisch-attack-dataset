#!/usr/bin/env python3
"""Generate vic_pdr_bars and feature_signature for 21-mote placement chain.

Replaces the old random-main-chain numbers in gen_result_figures.py.
The 31-mote feature signatures and vic_pdr_bars are unchanged because
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
    atk_ppm  = [3.42,   3.88,   0.00,   15.01,  0.00,   3.99,   0.00]
    nrm_ppm  = [3.71,   3.99,   4.00,   3.99,   3.99,   4.00,   3.98]
    atk_ctrl = [296.17, 304.83, 433.56, 355.06, 352.94, 517.06, 348.17]
    nrm_ctrl = [291.57, 344.88, 382.15, 346.79, 345.10, 332.50, 342.80]
    atk_rank = [950.47, 569.99, 873.23, 872.45, 860.93, 832.52, 858.84]
    nrm_rank = [1065,   862.01, 935.53, 950.62, 952.67, 941.43, 942.36]
    atk_buf  = [14.03,  4.50,   3.72,   3.26,   4.23,   1.11,   2.99]
    nrm_buf  = [12.64,  3.34,   3.86,   3.86,   3.89,   3.35,   3.58]

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


def fig_vic_pdr_bars():
    attacks = ['Blackhole', 'Decreased\nRank', 'DIS\nFlooding', 'App\nFlooding',
               'Shared\nCell', '6P Cell\nExh.', 'TSCH\nDesync.']
    atk_pdr = [27.45, 30.89, 30.00, 29.63, 36.00, 29.69, 31.67]
    vic_pdr = [1.82,  1.21,  0.06,  0.47,  0.06,  1.15,  0.07]
    bys_pdr = [20.68, 23.08, 20.51, 21.34, 21.32, 20.82, 20.70]

    x = np.arange(len(attacks))
    w = 0.27
    fig, ax = plt.subplots(figsize=(13, 5.2))

    def _bar(arr, offset, color, label):
        rects = ax.bar(x + offset, arr, w, label=label, color=color,
                       edgecolor='black', linewidth=0.5, alpha=0.85)
        ax.bar_label(rects, fmt='%.2f', fontsize=8, padding=2)

    _bar(atk_pdr, -w, '#d62728', 'Attacker PDR')
    _bar(vic_pdr,  0,  '#ff7f0e', 'Victim PDR')
    _bar(bys_pdr,  w,  '#1f77b4', 'Bystander PDR')
    ax.set_xticks(x); ax.set_xticklabels(attacks, fontsize=10)
    ax.set_ylabel('Per-source PDR (%)', fontsize=11)
    ax.set_title('Per-source PDR by class (21-mote placement chain, '
                 '42 runs pooled)', fontsize=12)
    ax.legend(fontsize=10, loc='upper right')
    ax.grid(True, axis='y', linestyle=':', alpha=0.5)
    ax.set_ylim(0, 42)
    plt.tight_layout()
    out_png = OUT / 'vic_pdr_bars.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


if __name__ == '__main__':
    fig_feature_signature()
    fig_vic_pdr_bars()
