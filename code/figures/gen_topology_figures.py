#!/usr/bin/env python3
"""Generate topology figures for 21-mote and 30-mote scenarios.

For each scale, plots all motes at their (x, y) positions, colour-coded by
placement class (sink / core / mid / edge), labels each mote with its ID,
and draws a unit-disk radio-range circle for the sink (illustrative only).

Outputs (vector PDF for the IEEE paper, raster PNG for the Word report):
  paper/figures/topology_21mote.{pdf,png}
  paper/figures/topology_31mote.{pdf,png}
  paper/figures/topology_21mote_a5_placement.{pdf,png}
  paper/figures/topology_31mote_a5_placement.{pdf,png}
"""
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as patches


# ----- 21-mote topology (existing v2 CSC) -----
POS_21 = {
    1:  (-30.01, 35.46),  # sink
    2:  (0.0, 0.0),    3:  (0.0, 25.0),   4:  (0.0, 50.0),   5:  (0.0, 75.0),
    6:  (25.0, 0.0),   7:  (25.0, 25.0),  8:  (25.0, 50.0),  9:  (25.0, 75.0),
    10: (50.0, 0.0),   11: (50.0, 25.0),  12: (50.0, 50.0),  13: (50.0, 75.0),
    14: (75.0, 0.0),   15: (75.0, 25.0),  16: (75.0, 50.0),  17: (75.0, 75.0),
    18: (100.0, 0.0),  19: (100.0, 25.0), 20: (100.0, 50.0),
    21: (100.0, 75.0),
}
PLACE_21 = {
    'core': [2, 3, 4, 5, 7, 8],
    'mid':  [6, 9, 10, 11, 12, 13],
    'edge': [14, 15, 16, 17, 18, 19, 20, 21],
}

# ----- 30-mote topology (gen_topology_csc.py output) -----
def gen_30mote_positions():
    pos = {1: (-30.0, 50.0)}  # sink
    mid = 2
    for c in range(6):       # cols 0..5
        for r in range(5):   # rows 0..4
            pos[mid] = (c * 25.0, r * 25.0)
            mid += 1
    return pos


POS_30 = gen_30mote_positions()
PLACE_30 = {
    'core': [2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    'mid':  [12, 13, 14, 15, 16, 17, 18, 19, 20, 21],
    'edge': [22, 23, 24, 25, 26, 27, 28, 29, 30, 31],
}

# ----- Attacker subsets per phase -----
ATK_21_PHASE1 = {  # 3 runs (random placement), 5 attackers each, seeds 43/44/45
    'Run 1 (seed 43)': [3, 6, 11, 13, 16],
    'Run 2 (seed 44)': [5, 7, 15, 18, 19],
    'Run 3 (seed 45)': [4, 10, 15, 17, 21],
}
# Attacker selections of the released 84-run dataset (deterministic per worker,
# master seed 42). a5 = 5 attackers sampled from the tertile pool, a1 = 1.
ATK_21_PHASE2_A5 = {
    'core': [2, 3, 4, 7, 8],
    'mid':  [6, 9, 10, 12, 13],
    'edge': [14, 15, 18, 19, 20],
}
ATK_21_PHASE2_A1 = {'core': [3], 'mid': [11], 'edge': [17]}

ATK_30_A5 = {
    'core': [2, 3, 6, 8, 11],
    'mid':  [12, 14, 15, 17, 19],
    'edge': [22, 23, 24, 30, 31],
}
ATK_30_A1 = {'core': [5], 'mid': [19], 'edge': [25]}


PLACEMENT_COLOURS = {
    'sink': '#1f77b4',
    'core': '#2ca02c',
    'mid':  '#ff7f0e',
    'edge': '#d62728',
}


def mote_class(mote_id, placement_dict):
    if mote_id == 1:
        return 'sink'
    for cls, ids in placement_dict.items():
        if mote_id in ids:
            return cls
    return 'unknown'


def draw_topology(pos, placement, title, out_path, attacker_ids=None,
                   show_radio=True):
    fig, ax = plt.subplots(figsize=(9, 6.5))
    xs = [p[0] for p in pos.values()]
    ys = [p[1] for p in pos.values()]
    pad = 15
    ax.set_xlim(min(xs) - pad, max(xs) + pad)
    ax.set_ylim(min(ys) - pad, max(ys) + pad)
    ax.set_aspect('equal')
    ax.grid(True, linestyle=':', alpha=0.4)

    if show_radio:
        sink_x, sink_y = pos[1]
        ax.add_patch(patches.Circle((sink_x, sink_y), 50,
                                     fill=False, linestyle='--',
                                     edgecolor='#888', linewidth=0.8,
                                     label='Sink radio range (UDGM, illustrative)'))

    attacker_set = set(attacker_ids or [])
    for mid, (x, y) in sorted(pos.items()):
        cls = mote_class(mid, placement)
        colour = PLACEMENT_COLOURS[cls]
        is_attacker = mid in attacker_set
        marker = 'X' if is_attacker else ('s' if cls == 'sink' else 'o')
        size = 320 if cls == 'sink' else (260 if is_attacker else 200)
        edgecolor = 'black' if is_attacker else colour
        linewidth = 2.5 if is_attacker else 0.8
        ax.scatter(x, y, c=colour, marker=marker, s=size,
                   edgecolors=edgecolor, linewidths=linewidth, zorder=3)
        ax.text(x, y - 5.5, str(mid), ha='center', va='top',
                fontsize=10.5, zorder=4)

    # Legend
    handles = [
        plt.Line2D([0], [0], marker='s', color='w', markersize=12,
                   markerfacecolor=PLACEMENT_COLOURS['sink'], label='Sink (mote 1)'),
        plt.Line2D([0], [0], marker='o', color='w', markersize=11,
                   markerfacecolor=PLACEMENT_COLOURS['core'], label='Core mote'),
        plt.Line2D([0], [0], marker='o', color='w', markersize=11,
                   markerfacecolor=PLACEMENT_COLOURS['mid'], label='Mid mote'),
        plt.Line2D([0], [0], marker='o', color='w', markersize=11,
                   markerfacecolor=PLACEMENT_COLOURS['edge'], label='Edge mote'),
    ]
    if attacker_ids:
        handles.append(
            plt.Line2D([0], [0], marker='X', color='w', markersize=12,
                       markerfacecolor='#444', markeredgecolor='black',
                       label='Attacker (this run)')
        )
    ax.legend(handles=handles, loc='upper left',
              bbox_to_anchor=(1.02, 1), fontsize=11, frameon=True)

    ax.set_xlabel('x (m)')
    ax.set_ylabel('y (m)')
    ax.set_title(title, fontsize=12.5)

    plt.tight_layout()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out_path, dpi=140, bbox_inches='tight')
    plt.savefig(out_path.with_suffix('.pdf'), bbox_inches='tight')
    plt.close()
    print(f'Wrote {out_path.with_suffix(".pdf")}')


def main():
    out_dir = Path('paper/figures')

    # 21-mote base topology (no attacker overlay)
    draw_topology(POS_21, PLACE_21,
                   '21-mote topology: 1 sink + 20 clients (5x4 grid plus central mote 21)',
                   out_dir / 'topology_21mote.png')

    # 31-mote base topology (1 sink + 30 clients)
    draw_topology(POS_30, PLACE_30,
                   '31-mote topology: 1 sink + 30 clients (6x5 grid, 25 m spacing)',
                   out_dir / 'topology_31mote.png')

    # 21-mote a5 placement attackers (one combined fig with 3 placements)
    fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))
    for ax, (placement, atk_ids) in zip(axes, ATK_21_PHASE2_A5.items()):
        xs = [p[0] for p in POS_21.values()]
        ys = [p[1] for p in POS_21.values()]
        ax.set_xlim(min(xs) - 15, max(xs) + 15)
        ax.set_ylim(min(ys) - 15, max(ys) + 15)
        ax.set_aspect('equal')
        ax.grid(True, linestyle=':', alpha=0.4)
        for mid, (x, y) in POS_21.items():
            cls = mote_class(mid, PLACE_21)
            colour = PLACEMENT_COLOURS[cls]
            is_attacker = mid in atk_ids
            marker = 'X' if is_attacker else ('s' if cls == 'sink' else 'o')
            size = 280 if cls == 'sink' else (220 if is_attacker else 160)
            edgecolor = 'black' if is_attacker else colour
            linewidth = 2.5 if is_attacker else 0.6
            ax.scatter(x, y, c=colour, marker=marker, s=size,
                       edgecolors=edgecolor, linewidths=linewidth, zorder=3)
            ax.text(x, y - 5.5, str(mid), ha='center', va='top', fontsize=10)
        ax.set_title(f'21-mote {placement} (a5) attackers: {atk_ids}', fontsize=11.5)
        ax.set_xlabel('x (m)')
        ax.set_ylabel('y (m)')
    plt.tight_layout()
    # PNG output disabled (paper uses PDF only)
    # plt.savefig(out_dir / 'topology_21mote_a5_placement.png', dpi=140, bbox_inches='tight')
    plt.savefig(out_dir / 'topology_21mote_a5_placement.pdf', bbox_inches='tight')
    plt.close()
    print(f"Wrote {out_dir / 'topology_21mote_a5_placement.pdf'}")

    # 30-mote a5 placement attackers
    fig, axes = plt.subplots(1, 3, figsize=(18, 5.5))
    for ax, (placement, atk_ids) in zip(axes, ATK_30_A5.items()):
        xs = [p[0] for p in POS_30.values()]
        ys = [p[1] for p in POS_30.values()]
        ax.set_xlim(min(xs) - 15, max(xs) + 15)
        ax.set_ylim(min(ys) - 15, max(ys) + 15)
        ax.set_aspect('equal')
        ax.grid(True, linestyle=':', alpha=0.4)
        for mid, (x, y) in POS_30.items():
            cls = mote_class(mid, PLACE_30)
            colour = PLACEMENT_COLOURS[cls]
            is_attacker = mid in atk_ids
            marker = 'X' if is_attacker else ('s' if cls == 'sink' else 'o')
            size = 280 if cls == 'sink' else (220 if is_attacker else 160)
            edgecolor = 'black' if is_attacker else colour
            linewidth = 2.5 if is_attacker else 0.6
            ax.scatter(x, y, c=colour, marker=marker, s=size,
                       edgecolors=edgecolor, linewidths=linewidth, zorder=3)
            ax.text(x, y - 5.5, str(mid), ha='center', va='top', fontsize=10)
        ax.set_title(f'31-mote {placement} (a5) attackers: {atk_ids}', fontsize=11.5)
        ax.set_xlabel('x (m)')
        ax.set_ylabel('y (m)')
    plt.tight_layout()
    # PNG output disabled (paper uses PDF only)
    # plt.savefig(out_dir / 'topology_31mote_a5_placement.png', dpi=140, bbox_inches='tight')
    plt.savefig(out_dir / 'topology_31mote_a5_placement.pdf', bbox_inches='tight')
    plt.close()
    print(f"Wrote {out_dir / 'topology_31mote_a5_placement.pdf'}")


if __name__ == '__main__':
    main()
