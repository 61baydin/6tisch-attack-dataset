#!/usr/bin/env python3
"""Generate quantitative result figures.

Produces vector PDF (for the IEEE paper) and raster PNG (for the
python-docx Word report) side-by-side:

  feature_signature.{pdf,png}   per-attack Atk vs Nrm feature contrast
  placement_heatmap.{pdf,png}   F1 heatmap by (attack, placement)
  vic_pdr_bars.{pdf,png}        Attacker / Victim / Bystander PDR
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
    # From damage_analysis (21-mote, Phase 1 chain)
    atk_ppm  = [3.47,   3.99,   0.00,   14.93,  0.00,   4.00,   0.00]
    nrm_ppm  = [3.30,   3.95,   3.99,   3.99,   3.99,   4.00,   4.00]
    atk_ctrl = [284.14, 346.40, 426.73, 341.27, 330.67, 511.13, 385.67]
    nrm_ctrl = [332.87, 348.91, 421.11, 340.93, 348.27, 329.09, 356.29]
    atk_rank = [1048,   550.06, 925.91, 958.96, 949.05, 959.62, 941.75]
    nrm_rank = [1005,   738.87, 929.90, 929.62, 915.32, 951.99, 931.64]
    atk_buf  = [13.49,  6.82,   2.73,   3.84,   4.33,   1.15,   3.90]
    nrm_buf  = [10.46,  3.19,   3.93,   3.92,   3.68,   5.33,   5.04]

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
        [0.649, 0.109, 0.062],
        [0.969, 0.530, 0.097],
        [0.761, 0.961, 0.977],
        [0.254, 0.647, 0.410],
        [0.646, 0.436, 0.000],
        [0.749, 0.945, 0.543],
        [0.895, 0.686, 0.349],
    ]
    f1_30 = [
        [0.268, 0.026, 0.303],
        [0.422, 0.813, 0.227],
        [0.616, 0.590, 0.444],
        [0.705, 0.362, 0.228],
        [0.340, 0.429, 0.000],
        [0.835, 0.900, 0.733],
        [0.640, 0.523, 0.579],
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
        plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label='RF binary F1')
    plt.suptitle('Random Forest binary F1: attack x placement '
                 '(StratifiedGroupKFold, k=5)', fontsize=13)
    plt.tight_layout()
    out_png = OUT / 'placement_heatmap.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


def fig_vic_pdr_bars():
    """Per-source PDR: attacker / victim / bystander per attack."""
    attacks = ['Baseline', 'Blackhole', 'Decreased\nRank', 'DIS\nFlooding',
               'App\nFlooding', 'Shared\nCell', '6P Cell\nExh.', 'TSCH\nDesync.']
    atk_pdr = [np.nan, 20.16, 20.40, 19.49, 19.82, 20.00, 20.28, 22.67]
    vic_pdr = [np.nan, 8.32,  3.51,  8.19,  0.19,  0.00,  7.68,  0.00]
    bys_pdr = [19.22,  30.25, 45.40, 24.35, 29.75, 26.87, 25.73, 26.34]

    x = np.arange(len(attacks))
    w = 0.27
    fig, ax = plt.subplots(figsize=(13, 5.2))

    def _bar(arr, offset, color, label):
        heights = [v if not np.isnan(v) else 0 for v in arr]
        rects = ax.bar(x + offset, heights, w, label=label, color=color,
                       edgecolor='black', linewidth=0.5, alpha=0.85)
        # Per-bar labels: 'n/a' for NaN (Baseline attacker/victim),
        # '0.00' for true zeros so they remain visible.
        labels = ['n/a' if np.isnan(v) else f'{v:.2f}' for v in arr]
        ax.bar_label(rects, labels=labels, fontsize=8, padding=2,
                     rotation=0)

    _bar(atk_pdr, -w, '#d62728', 'Attacker PDR')
    _bar(vic_pdr,  0,  '#ff7f0e', 'Victim PDR')
    _bar(bys_pdr,  w,  '#1f77b4', 'Bystander PDR')
    ax.set_xticks(x)
    ax.set_xticklabels(attacks, fontsize=10)
    ax.set_ylabel('Per-source PDR (%)', fontsize=11)
    ax.set_title('Per-source PDR by class (21-mote main chain)', fontsize=12)
    ax.legend(fontsize=10, loc='upper right')
    ax.grid(True, axis='y', linestyle=':', alpha=0.5)
    ax.set_ylim(0, 55)
    plt.tight_layout()
    out_png = OUT / 'vic_pdr_bars.png'
    plt.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


def main():
    fig_feature_signature()
    fig_placement_heatmap()
    fig_vic_pdr_bars()


if __name__ == '__main__':
    main()
