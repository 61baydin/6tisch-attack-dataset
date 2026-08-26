#!/usr/bin/env python3
"""Generate conceptual diagrams for each of the 7 attacks.

Each diagram shows a small reference topology (sink + 7 motes) and
illustrates the attack's mechanism with arrows, crosses, or annotations.

Outputs in paper/figures/ (vector PDF for the IEEE paper + raster PNG
for the python-docx Word report):
    attack_<name>.{pdf,png}   (7 stand-alone diagrams)
    attack_grid.{pdf,png}     (2x4 composite for the IEEE paper)
"""
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch
import numpy as np


REF_POS = {
    'S': (0.0, 1.5),
    'A': (1.5, 2.5),
    'B': (1.5, 0.5),
    'C': (3.0, 3.0),
    'D': (3.0, 1.5),
    'E': (3.0, 0.0),
    'F': (4.5, 2.5),
    'G': (4.5, 0.5),
}
PARENTS = {
    'A': 'S', 'B': 'S',
    'C': 'A', 'D': 'A', 'E': 'B',
    'F': 'C', 'G': 'E',
}


def draw_base(ax, attacker_id=None, attacker_label=None, label_pos=None):
    """Render base topology; attacker rendered with X and red border.

    label_pos may be 'above', 'below', 'left', 'right'.  If None, no
    attacker label is drawn (caller may place it manually).
    """
    for child, parent in PARENTS.items():
        cx, cy = REF_POS[child]
        px, py = REF_POS[parent]
        ax.plot([cx, px], [cy, py], color='#bbb', linewidth=1.0,
                zorder=1, linestyle='-')

    for mote, (x, y) in REF_POS.items():
        if mote == 'S':
            ax.scatter(x, y, c='#1f77b4', marker='s', s=600,
                       edgecolors='black', linewidths=1.4, zorder=3)
            ax.text(x, y, 'SINK', ha='center', va='center',
                    fontsize=9, fontweight='bold', color='white', zorder=4)
        elif mote == attacker_id:
            ax.scatter(x, y, c='#d62728', marker='X', s=520,
                       edgecolors='black', linewidths=2.0, zorder=3)
            ax.text(x, y + 0.32, mote, ha='center', va='bottom',
                    fontsize=13, fontweight='bold', color='black', zorder=4)
        else:
            ax.scatter(x, y, c='#999', marker='o', s=360,
                       edgecolors='black', linewidths=0.8, zorder=3)
            ax.text(x, y, mote, ha='center', va='center',
                    fontsize=12.5, zorder=4)

    if attacker_label and attacker_id and label_pos:
        ax_x, ax_y = REF_POS[attacker_id]
        if label_pos == 'above':
            ax.text(ax_x, ax_y + 0.85, attacker_label, ha='center', va='bottom',
                    fontsize=11.5, color='#a00', style='italic', zorder=4)
        elif label_pos == 'below':
            ax.text(ax_x, ax_y - 0.40, attacker_label, ha='center', va='top',
                    fontsize=11.5, color='#a00', style='italic', zorder=4)
        elif label_pos == 'left':
            ax.text(ax_x - 0.45, ax_y, attacker_label, ha='right', va='center',
                    fontsize=11.5, color='#a00', style='italic', zorder=4)
        elif label_pos == 'right':
            ax.text(ax_x + 0.45, ax_y, attacker_label, ha='left', va='center',
                    fontsize=11.5, color='#a00', style='italic', zorder=4)

    ax.set_xlim(-0.9, 5.7)
    ax.set_ylim(-1.1, 4.2)
    ax.set_aspect('equal')
    ax.axis('off')


def add_arrow(ax, src, dst, **kwargs):
    sx, sy = REF_POS[src] if src in REF_POS else src
    dx, dy = REF_POS[dst] if dst in REF_POS else dst
    arr = FancyArrowPatch((sx, sy), (dx, dy),
                          arrowstyle='-|>', mutation_scale=18,
                          shrinkA=18, shrinkB=18, zorder=2, **kwargs)
    ax.add_patch(arr)


def add_cross(ax, x, y, size=0.18, color='#d62728', lw=3.5):
    ax.plot([x - size, x + size], [y - size, y + size],
            color=color, linewidth=lw, zorder=5)
    ax.plot([x - size, x + size], [y + size, y - size],
            color=color, linewidth=lw, zorder=5)


# -------- Per-attack panel renderers (also reused by composite) --------

def panel_blackhole(ax):
    draw_base(ax, attacker_id='A', attacker_label='Attacker A',
              label_pos='right')
    add_arrow(ax, 'C', 'A', color='#2ca02c', linewidth=2.0)
    add_arrow(ax, 'D', 'A', color='#2ca02c', linewidth=2.0)
    add_arrow(ax, 'F', 'C', color='#2ca02c', linewidth=2.0)
    mid_x = (REF_POS['A'][0] + REF_POS['S'][0]) / 2
    mid_y = (REF_POS['A'][1] + REF_POS['S'][1]) / 2 + 0.10
    add_cross(ax, mid_x, mid_y, size=0.22)
    ax.text(mid_x - 0.05, mid_y - 0.45, 'DROP',
            color='#d62728', fontsize=12.5, fontweight='bold')


def panel_decrease_rank(ax):
    draw_base(ax, attacker_id='F', attacker_label='Attacker F',
              label_pos='right')
    add_arrow(ax, 'D', 'F', color='#ff7f0e', linewidth=2.0, linestyle='--')
    add_arrow(ax, 'G', 'F', color='#ff7f0e', linewidth=2.0, linestyle='--')
    ax.text(2.25, 3.85, 'F advertises low rank',
            fontsize=11.5, color='#a00', fontweight='bold', ha='center')


def panel_dis_flooding(ax):
    draw_base(ax, attacker_id='B', attacker_label='Attacker B',
              label_pos='left')
    for tgt in ['S', 'E', 'D']:
        add_arrow(ax, 'B', tgt, color='#9467bd', linewidth=1.6)
    ax.text(2.6, -0.75, 'DIS flood',
            fontsize=11.5, color='#7030a0', fontweight='bold', ha='center')
    add_arrow(ax, 'S', 'A', color='#888', linewidth=1.0, linestyle=':')
    add_arrow(ax, 'A', 'C', color='#888', linewidth=1.0, linestyle=':')
    ax.text(2.6, 3.85, 'DIO cascade',
            fontsize=11, color='#555', ha='center', style='italic')


def panel_app_flooding(ax):
    draw_base(ax, attacker_id='D', attacker_label='Attacker D',
              label_pos='below')
    for offset in [-0.10, 0.0, 0.10]:
        sx, sy = REF_POS['D']
        tx, ty = REF_POS['S']
        arr = FancyArrowPatch((sx, sy + offset), (tx, ty + offset),
                              arrowstyle='-|>', mutation_scale=14,
                              shrinkA=18, shrinkB=18, zorder=2,
                              color='#e377c2', linewidth=1.5)
        ax.add_patch(arr)
    ax.text(1.5, 3.6, '15x app rate (D → SINK)',
            fontsize=12.5, color='#a0006e', fontweight='bold', ha='center')


def panel_shared_slot(ax):
    # Skip auto-placed attacker label; we set it manually below to avoid
    # collision with the radial jamming arrows around E.
    draw_base(ax, attacker_id='E', attacker_label=None)
    sx, sy = REF_POS['E']
    for ang in np.linspace(0, 2 * np.pi, 8, endpoint=False):
        dx = sx + 0.7 * np.cos(ang)
        dy = sy + 0.7 * np.sin(ang)
        arr = FancyArrowPatch((sx, sy), (dx, dy),
                              arrowstyle='->', mutation_scale=12,
                              shrinkA=10, shrinkB=0, zorder=2,
                              color='#bcbd22', linewidth=1.5)
        ax.add_patch(arr)
    # Place Attacker E label well clear of the radial arrows.
    ax.text(4.7, -0.8, 'Attacker E:\nmonopolises shared slot',
            fontsize=11.5, color='#7a7a00', fontweight='bold',
            ha='center', va='top')


def panel_slot_exhaustion(ax):
    draw_base(ax, attacker_id='C', attacker_label='Attacker C',
              label_pos='right')
    for offset in [-0.15, 0.0, 0.15]:
        sx, sy = REF_POS['C']
        tx, ty = REF_POS['A']
        arr = FancyArrowPatch((sx + offset, sy), (tx + offset, ty),
                              arrowstyle='-|>', mutation_scale=14,
                              shrinkA=18, shrinkB=18, zorder=2,
                              color='#17becf', linewidth=1.5)
        ax.add_patch(arr)
    ax.text(2.25, 3.85, '6P ADD x N',
            fontsize=11.5, color='#006e6e', fontweight='bold', ha='center')


def panel_timekeep(ax):
    draw_base(ax, attacker_id='G', attacker_label='Attacker G',
              label_pos='right')
    add_arrow(ax, 'G', 'E', color='#8c564b', linewidth=2.0)
    ax.text(3.75, -0.85, 'corrupted EB -> E loses sync',
            fontsize=11.5, color='#6b3a2c', fontweight='bold', ha='center')


PANELS = [
    ('Blackhole',            'attack_blackhole.png',       panel_blackhole),
    ('Decreased Rank',       'attack_decrease_rank.png',   panel_decrease_rank),
    ('DIS Flooding',         'attack_dis_flooding.png',    panel_dis_flooding),
    ('Application Flooding', 'attack_app_flooding.png',    panel_app_flooding),
    ('TSCH Shared Cell',     'attack_shared_slot.png',     panel_shared_slot),
    ('6P Cell Exhaustion',   'attack_slot_exhaustion.png', panel_slot_exhaustion),
    ('TSCH Desync.',         'attack_timekeep.png',        panel_timekeep),
]


def main():
    out = Path('paper/figures')
    out.mkdir(parents=True, exist_ok=True)

    # Stand-alone .pdf (vector, IEEE paper) (raster, Word report).
    for title, fname, panel_fn in PANELS:
        fig, ax = plt.subplots(figsize=(8, 5))
        panel_fn(ax)
        ax.set_title(title, fontsize=14, fontweight='bold')
        png_path = out / fname
        pdf_path = png_path.with_suffix('.pdf')
        fig.savefig(png_path, dpi=140, bbox_inches='tight')
        fig.savefig(pdf_path, bbox_inches='tight')
        plt.close(fig)
        print(f'Wrote {pdf_path}')

    # 2 x 4 composite for the IEEE paper.  Larger panels, larger fonts.
    fig, axes = plt.subplots(2, 4, figsize=(16, 8))
    for ax, (title, _, panel_fn) in zip(axes.flat[:7], PANELS):
        panel_fn(ax)
        ax.set_title(title, fontsize=15, fontweight='bold')

    # 8th cell: legend explaining symbols
    leg_ax = axes.flat[7]
    leg_ax.axis('off')
    leg_ax.set_xlim(0, 1)
    leg_ax.set_ylim(0, 1)
    leg_ax.scatter(0.18, 0.78, c='#1f77b4', marker='s', s=520,
                   edgecolors='black', linewidths=1.4)
    leg_ax.text(0.34, 0.78, 'Sink (border router)', va='center', fontsize=13)
    leg_ax.scatter(0.18, 0.58, c='#999', marker='o', s=320,
                   edgecolors='black', linewidths=0.8)
    leg_ax.text(0.34, 0.58, 'Normal mote', va='center', fontsize=13)
    leg_ax.scatter(0.18, 0.38, c='#d62728', marker='X', s=460,
                   edgecolors='black', linewidths=2.0)
    leg_ax.text(0.34, 0.38, 'Attacker', va='center', fontsize=13)
    leg_ax.plot([0.10, 0.26], [0.20, 0.20], color='#bbb', linewidth=1.5)
    leg_ax.text(0.34, 0.20, 'RPL parent link', va='center', fontsize=13)
    leg_ax.set_title('Legend', fontsize=15, fontweight='bold')

    plt.tight_layout()
    # PNG output disabled (paper uses PDF only)
    # fig.savefig(out / 'attack_grid.png', dpi=150, bbox_inches='tight')
    fig.savefig(out / 'attack_grid.pdf', bbox_inches='tight')
    plt.close(fig)
    print(f"Wrote {out / 'attack_grid.pdf'}")


if __name__ == '__main__':
    main()
