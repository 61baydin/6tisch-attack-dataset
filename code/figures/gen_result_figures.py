#!/usr/bin/env python3
"""Generate quantitative result figures.

Produces vector PDF (for the IEEE paper) and raster PNG (for the
python-docx Word report) side-by-side:

  feature_signature.{pdf,png}   per-attack Atk vs Nrm feature contrast
  placement_heatmap.{pdf,png}   F1 heatmap by (attack, placement)
"""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np


OUT = Path('paper/figures')
OUT.mkdir(parents=True, exist_ok=True)


def fig_feature_signature():
    """Atk vs Nrm bars for AtkPpm/Ctrl/Rank/Buf across 7 attacks."""
    attacks = ['Blackhole', 'Decreased\nRank', 'DIS\nFlooding', 'App\nFlooding',
               'Shared\nCell', '6P Cell\nExh.', 'TSCH\nDesync.']
    atk_ppm  = [3.96,    3.99,   4.00,   58.98,  2.03,   4.00,   4.00]
    nrm_ppm  = [7.16,    8.75,   8.74,   25.36,  6.21,   8.74,   8.74]
    atk_ctrl = [18.21,   15.78,  41.63,  15.14,  8.93,   23.21,  15.77]
    nrm_ctrl = [16.22,   15.00,  22.06,  15.10,  10.96,  14.80,  14.91]
    atk_rank = [1068.49, 649.60, 938.67, 938.67, 961.32, 972.80, 955.73]
    nrm_rank = [1082.43, 791.97, 981.32, 1003.10, 988.52, 944.10, 944.80]
    atk_buf  = [7.55,    6.17,   4.07,   7.93,   5.21,   0.78,   2.87]
    nrm_buf  = [7.81,    2.48,   2.90,   3.13,   4.67,   2.74,   2.69]

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
        # Annotate every bar so zero-height bars remain visible.
        fmt = '%.0f' if max(max(atk), max(nrm)) > 100 else '%.2f'
        ax.bar_label(rects_atk, fmt=fmt, fontsize=7, padding=2)
        ax.bar_label(rects_nrm, fmt=fmt, fontsize=7, padding=2)
        ax.set_xticks(x)
        ax.set_xticklabels(attacks, fontsize=9, rotation=0)
        ax.set_title(title, fontsize=11)
        ax.set_ylabel(ylab, fontsize=10)
        ax.grid(True, axis='y', linestyle=':', alpha=0.5)
        # Headroom so labels above tall bars are not clipped.
        ymax = max(max(atk), max(nrm))
        ax.set_ylim(0, ymax * 1.15)
        ax.legend(fontsize=9, loc='upper right')
    plt.suptitle('Within-run feature contrast (21-mote main chain)',
                 fontsize=13, y=1.00)
    plt.tight_layout()
    out_png = OUT / 'feature_signature.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


def fig_placement_heatmap():
    """F1 heatmap: rows=attacks, cols=placements; two panels for 21- and 30-mote."""
    attacks = ['Blackhole', 'Decreased Rank', 'DIS Flooding', 'App Flooding',
               'Shared Cell', '6P Cell Exh.', 'TSCH Desync.']
    placements = ['core', 'mid', 'edge']

    f1_21 = [
        [0.56, 0.74, 0.53],
        [0.98, 0.55, 0.96],
        [0.96, 0.96, 0.94],
        [0.98, 1.00, 1.00],
        [0.40, 0.28, 0.17],
        [0.96, 1.00, 0.78],
        [0.70, 0.47, 0.44],
    ]
    f1_30 = [
        [0.71, 0.73, 0.50],
        [0.89, 0.85, 0.98],
        [0.94, 0.99, 0.98],
        [1.00, 0.99, 0.99],
        [0.14, 0.36, 0.33],
        [0.99, 1.00, 1.00],
        [0.49, 0.69, 0.77],
    ]

    fig, axes = plt.subplots(1, 2, figsize=(13, 6))
    titles = ['21-mote (5 attackers)', '31-mote (5 attackers)']
    for ax, data, title in zip(axes, [f1_21, f1_30], titles):
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
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label='LR binary F1')
    plt.suptitle('Logistic Regression binary F1: attack x placement '
                 '(LeaveOneGroupOut, group=(run,node))', fontsize=13)
    plt.tight_layout()
    out_png = OUT / 'placement_heatmap.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


def main():
    fig_feature_signature()
    fig_placement_heatmap()


if __name__ == '__main__':
    main()
