#!/usr/bin/env python3
"""Generate the 31-mote analogues of feature_signature and vic_pdr_bars
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
    # From damage_analysis_summary_31mote.csv (42 runs pooled per attack family)
    atk_ppm  = [3.92,   4.00,   0.01,   14.96,  0.00,   3.99,   0.00]
    nrm_ppm  = [3.79,   3.95,   3.99,   3.99,   4.00,   3.97,   3.98]
    atk_ctrl = [275.83, 332.06, 406.56, 352.22, 346.24, 502.59, 349.67]
    nrm_ctrl = [255.22, 327.66, 352.06, 341.17, 336.57, 333.26, 329.40]
    atk_rank = [1113,   671.75, 1028,   1040,   1010,   1013,   995.09]
    nrm_rank = [1258,   1027,   1131,   1125,   1122,   1121,   1103]
    atk_buf  = [13.53,  6.71,   5.12,   4.85,   3.43,   1.81,   4.48]
    nrm_buf  = [15.13,  3.95,   4.02,   4.54,   3.89,   4.15,   4.39]

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


def fig_vic_pdr_bars_31():
    attacks = ['Baseline', 'Blackhole', 'Decreased\nRank', 'DIS\nFlooding',
               'App\nFlooding', 'Shared\nCell', '6P Cell\nExh.', 'TSCH\nDesync.']
    atk_pdr = [np.nan, 25.23, 25.87, 25.60, 26.32, 25.56, 24.90, 25.37]
    vic_pdr = [np.nan, 2.40,  0.00,  0.00,  0.00,  0.00,  0.00,  0.00]
    bys_pdr = [13.17,  13.26, 14.53, 13.73, 13.26, 13.61, 13.73, 13.61]

    x = np.arange(len(attacks))
    w = 0.27
    fig, ax = plt.subplots(figsize=(13, 5.2))

    def _bar(arr, offset, color, label):
        heights = [v if not np.isnan(v) else 0 for v in arr]
        rects = ax.bar(x + offset, heights, w, label=label, color=color,
                       edgecolor='black', linewidth=0.5, alpha=0.85)
        labels = ['n/a' if np.isnan(v) else f'{v:.2f}' for v in arr]
        ax.bar_label(rects, labels=labels, fontsize=8, padding=2, rotation=0)

    _bar(atk_pdr, -w, '#d62728', 'Attacker PDR')
    _bar(vic_pdr,  0,  '#ff7f0e', 'Victim PDR')
    _bar(bys_pdr,  w,  '#1f77b4', 'Bystander PDR')
    ax.set_xticks(x)
    ax.set_xticklabels(attacks, fontsize=10)
    ax.set_ylabel('Per-source PDR (%)', fontsize=11)
    ax.set_title('Per-source PDR by class (31-mote scale chain)', fontsize=12)
    ax.legend(fontsize=10, loc='upper right')
    ax.grid(True, axis='y', linestyle=':', alpha=0.5)
    ax.set_ylim(0, 32)
    plt.tight_layout()
    out_png = OUT / 'vic_pdr_bars_31mote.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


if __name__ == '__main__':
    fig_feature_signature_31()
    fig_vic_pdr_bars_31()
