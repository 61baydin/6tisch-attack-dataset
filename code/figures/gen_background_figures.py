#!/usr/bin/env python3
"""Generate background figures for the IEEE paper.

Outputs (vector PDF + raster PNG):
    stack_6tisch.{pdf,png}    layered 6TiSCH protocol stack
    tsch_slotframe.{pdf,png}  TSCH slotframe with channel hopping example
    sixp_handshake.{pdf,png}  6P ADD 2-step handshake message-sequence chart
"""
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import numpy as np


OUT = Path('paper/figures')
OUT.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------
# 1. 6TiSCH protocol stack
# ---------------------------------------------------------------------

def fig_stack():
    layers = [
        ('Application (sensing, actuation, attacker telemetry)',
         '#fde9b8', 'Application Flooding'),
        ('Transport: UDP (CoAP optional)',
         '#ffe0a0', ''),
        ('Network: IPv6 / 6LoWPAN header compression\n'
         'Routing: RPL (DIO, DIS, DAO; trickle algorithm)',
         '#cde4f9', 'Decreased Rank,\nDIS Flooding,\nBlackhole'),
        ('6top sublayer: 6P scheduling (ADD, DELETE, RELOCATE);\n'
         'Scheduling Function (SF) selects cells',
         '#b8e3c0', '6P Cell Allocation\nExhaustion'),
        ('IEEE 802.15.4-2015 TSCH MAC:\n'
         'slotframes, channel hopping, Enhanced Beacons (EB)',
         '#f2c3c3', 'Shared Cell Contention,\nTSCH Desynchronization'),
        ('IEEE 802.15.4 PHY: 2.4 GHz ISM band, 16 channels (11-26),\n'
         '2 MHz wide, O-QPSK, 250 kbit/s',
         '#d8c8e3', '(out of scope:\nphysical jamming)'),
    ]

    fig, ax = plt.subplots(figsize=(12, 6.5))
    ax.set_xlim(0, 14)
    ax.set_ylim(-0.3, len(layers) + 0.5)
    ax.axis('off')

    y = len(layers)
    for label, color, atk in layers:
        # Stack box on the left
        box = FancyBboxPatch((0.4, y - 0.85), 8.4, 0.78,
                              boxstyle='round,pad=0.04,rounding_size=0.10',
                              facecolor=color, edgecolor='black', linewidth=1.0)
        ax.add_patch(box)
        ax.text(4.6, y - 0.46, label, ha='center', va='center',
                fontsize=11)
        # Attack annotation on the right
        if atk:
            color_a = '#a00' if 'out of scope' not in atk else 'black'
            arr = FancyArrowPatch((8.85, y - 0.46), (9.55, y - 0.46),
                                   arrowstyle='-|>', mutation_scale=14,
                                   color=color_a, linewidth=1.3)
            ax.add_patch(arr)
            ax.text(9.7, y - 0.46, atk, ha='left', va='center',
                    fontsize=9, color=color_a,
                    style='italic' if 'out of scope' in atk else 'normal',
                    fontweight='bold' if 'out of scope' not in atk else 'normal')
        y -= 1

    ax.text(7.0, -0.15,
            'left: layered protocol stack | right: attack families addressed in this paper, by plane',
            ha='center', va='top', fontsize=9, style='italic', color='black')

    ax.set_title('6TiSCH protocol stack and attack surface',
                 fontsize=14, fontweight='bold', pad=12)

    plt.tight_layout()
    out_png = OUT / 'stack_6tisch.png'
    fig.savefig(out_png, dpi=140, bbox_inches='tight')
    fig.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close(fig)
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


# ---------------------------------------------------------------------
# 2. TSCH slotframe with channel hopping
# ---------------------------------------------------------------------

def fig_slotframe():
    """TSCH slotframe (channels x slots) annotated with concrete mote pairs.

    Example 5-mote DODAG used to fill the slotframe:

            mote 2 ---\\
            mote 3 ----+--> mote 1 (sink, also EB advertiser)
            mote 4 ---/
            mote 5 ---> mote 3 (multi-hop)

    Each dedicated cell (s, c_off) is labelled with the sender->receiver
    pair from the sender's view (TX side); the receiver's RX side of
    the same allocation is shown one row below as a paired cell.
    """
    n_slots = 21
    n_channels = 16

    fig, ax = plt.subplots(figsize=(15, 6.0))
    ax.set_xlim(-0.5, n_slots + 8.5)
    ax.set_ylim(-0.5, n_channels + 0.5)
    ax.set_aspect('equal')

    for s in range(n_slots):
        for c in range(n_channels):
            rect = Rectangle((s, c), 1, 1, facecolor='white',
                             edgecolor='black', linewidth=0.4)
            ax.add_patch(rect)

    # Allocated cells in this example schedule (matches the 4emac firmware
    # configuration used in this study: SLOT_CONF_FRAME_SIZE=21 and three
    # hard slots at offsets 0 (timekeeping/EB), 8 (shared), 18 (shared);
    # see Table~\ref{tab:firmware_config}). The remaining cells are
    # dedicated TX/RX pairs for the sink's children and one multi-hop link.
    cells = [
        (0,  4,  'EB',     'EB\n(time)'),
        (8,  8,  'shared', 'Sh'),
        (18, 9,  'shared', 'Sh'),
        (3,  2,  'tx',     '2->1\nTX'),
        (3,  3,  'rx',     '2->1\nRX'),
        (6,  10, 'tx',     '3->1\nTX'),
        (6,  11, 'rx',     '3->1\nRX'),
        (11, 6,  'tx',     '4->1\nTX'),
        (11, 7,  'rx',     '4->1\nRX'),
        (15, 13, 'tx',     '5->3\nTX'),
        (15, 14, 'rx',     '5->3\nRX'),
    ]

    cell_colors = {
        'EB':     '#1f77b4',
        'shared': '#ff7f0e',
        'tx':     '#2ca02c',
        'rx':     '#aec7e8',
    }
    for s, c, kind, label in cells:
        rect = Rectangle((s, c), 1, 1, facecolor=cell_colors[kind],
                         edgecolor='black', linewidth=1.0, alpha=0.92)
        ax.add_patch(rect)
        ax.text(s + 0.5, c + 0.5, label, ha='center', va='center',
                fontsize=7, fontweight='bold',
                color='white' if kind != 'rx' else 'black')

    ax.set_xticks(np.arange(n_slots) + 0.5)
    ax.set_xticklabels(range(n_slots), fontsize=9)
    ax.set_yticks(np.arange(n_channels) + 0.5)
    ax.set_yticklabels([f'{11 + c}' for c in range(n_channels)], fontsize=9)
    ax.set_xlabel('slot offset within slotframe (length $L=21$)', fontsize=11)
    ax.set_ylabel('IEEE 802.15.4 channel (2.4 GHz)', fontsize=11)
    ax.set_title('TSCH slotframe annotated with sender$\\rightarrow$receiver mote pairs',
                 fontsize=12, fontweight='bold')

    # Right-side margin: explanatory boxes (legend + formula + topology).
    box_x = n_slots + 0.6

    # Topology hint
    ax.text(box_x, n_channels - 0.3,
            'example DODAG used\nfor this schedule:\n'
            'sink: mote 1\n'
            'children: 2, 3, 4\n'
            'multi-hop: 5 $\\rightarrow$ 3 $\\rightarrow$ 1',
            fontsize=9, va='top', ha='left',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#eef4ff',
                      edgecolor='black'))

    # Channel hop formula
    ax.text(box_x, n_channels - 6.0,
            'channel hopping:\n'
            r'$f = H[(\mathrm{ASN} + c_\mathrm{off}) \, \mathrm{mod} \, L]$',
            fontsize=9, va='top', ha='left',
            bbox=dict(boxstyle='round,pad=0.4', facecolor='#fff7e6',
                      edgecolor='black'))

    # Cell-type legend, wrapped in a rounded bounding box to match the
    # two annotation boxes above.
    legend_items = [
        ('EB',     'EB (TSCH timekeeping)'),
        ('shared', 'shared (CSMA-CA)'),
        ('tx',     'dedicated TX (sender)'),
        ('rx',     'dedicated RX (receiver)'),
    ]
    legend_x = box_x
    legend_w = 7.4
    legend_top = n_channels - 8.0
    line_h = 0.85
    swatch_h = 0.55
    # Geometry: title + gap + 4 items, all with comfortable spacing.
    title_h = 0.5
    items_h = len(legend_items) * line_h
    legend_h = 0.3 + title_h + 0.35 + items_h + 0.3
    legend_bg = FancyBboxPatch(
        (legend_x - 0.20, legend_top - legend_h),
        legend_w, legend_h,
        boxstyle='round,pad=0.15', facecolor='#f7f7f7',
        edgecolor='black', linewidth=0.8, zorder=1,
    )
    ax.add_patch(legend_bg)
    ax.text(legend_x, legend_top - 0.45, 'cell types:',
            fontsize=10, va='top', fontweight='bold', zorder=2)
    swatch_x = legend_x + 0.1
    label_x  = swatch_x + 0.95
    first_y = legend_top - title_h - 0.35 - swatch_h
    for i, (kind, name) in enumerate(legend_items):
        sy = first_y - i * line_h
        rect = Rectangle((swatch_x, sy), 0.65, swatch_h,
                         facecolor=cell_colors[kind], edgecolor='black',
                         linewidth=0.8, alpha=0.92, zorder=2)
        ax.add_patch(rect)
        ax.text(label_x, sy + swatch_h / 2.0, name,
                fontsize=9, va='center', ha='left', zorder=2)

    plt.tight_layout()
    out_png = OUT / 'tsch_slotframe.png'
    fig.savefig(out_png, dpi=140, bbox_inches='tight')
    fig.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close(fig)
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


# ---------------------------------------------------------------------
# 3. 6P ADD handshake
# ---------------------------------------------------------------------

def fig_6p_handshake():
    """6P ADD two-step transaction between requester (A) and responder (B)."""
    fig, ax = plt.subplots(figsize=(11, 5.4))
    # Widen the canvas so the side-placed processing boxes are fully inside.
    ax.set_xlim(-1.0, 11.5)
    ax.set_ylim(0, 8)
    ax.axis('off')

    # Lifelines (kept at the same positions; the wider canvas just adds margin)
    a_x, b_x = 2.2, 8.5
    ax.text(a_x, 7.6, 'Requester A\n(child node)', ha='center', va='center',
            fontsize=12, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.35', facecolor='#cde4f9',
                      edgecolor='black'))
    ax.text(b_x, 7.6, 'Responder B\n(RPL parent)', ha='center', va='center',
            fontsize=12, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.35', facecolor='#b8e3c0',
                      edgecolor='black'))
    # Vertical timelines
    ax.plot([a_x, a_x], [0.5, 7.0], color='black', linewidth=1.0, linestyle='--')
    ax.plot([b_x, b_x], [0.5, 7.0], color='black', linewidth=1.0, linestyle='--')

    def arrow(y, from_x, to_x, text, color='black'):
        arr = FancyArrowPatch((from_x, y), (to_x, y),
                              arrowstyle='-|>', mutation_scale=18,
                              color=color, linewidth=1.5)
        ax.add_patch(arr)
        ax.text((from_x + to_x) / 2, y + 0.18, text, ha='center', va='bottom',
                fontsize=10, color=color, fontweight='bold')

    # Step 1: ADD request
    arrow(5.7, a_x, b_x,
          '6P ADD Request (Code=ADD, NumCells, CellOptions, CellList)',
          color='#d62728')

    ax.text(a_x - 0.2, 5.95, 'SeqNum = N', ha='right', va='center',
            fontsize=8, style='italic', color='black')

    # B processing - sits to the right of B's timeline so it does not
    # cover the dashed line. Box stays fully inside the canvas
    # (right edge 10.7 < xlim 11.5).
    proc_x = b_x + 0.5
    proc_w, proc_h = 1.7, 0.95
    proc = FancyBboxPatch((proc_x, 4.05), proc_w, proc_h,
                          boxstyle='round,pad=0.05',
                          facecolor='#fff3cd', edgecolor='black')
    ax.add_patch(proc)
    ax.text(proc_x + proc_w / 2, 4.52, 'SF on B picks\ncells, updates\nschedule',
            ha='center', va='center', fontsize=9)
    # Connector from B's timeline to the processing box
    ax.plot([b_x, proc_x], [4.52, 4.52], color='black', linestyle=':',
            linewidth=0.8, zorder=1)

    # Step 2: ADD response
    arrow(3.0, b_x, a_x,
          '6P ADD Response (Code=RC_SUCCESS, CellList)',
          color='#2ca02c')
    ax.text(b_x + 0.2, 3.25, 'SeqNum = N', ha='left', va='center',
            fontsize=8, style='italic', color='black')

    # A processing - sits to the left of A's timeline. With xlim=-1.0,
    # left edge 0.0 is fully inside the canvas.
    proc2_w, proc2_h = 1.7, 0.95
    proc2_x = a_x - 0.5 - proc2_w
    proc2 = FancyBboxPatch((proc2_x, 1.35), proc2_w, proc2_h,
                           boxstyle='round,pad=0.05',
                           facecolor='#fff3cd', edgecolor='black')
    ax.add_patch(proc2)
    ax.text(proc2_x + proc2_w / 2, 1.82, 'A installs\nallocated\ncells',
            ha='center', va='center', fontsize=9)
    ax.plot([proc2_x + proc2_w, a_x], [1.82, 1.82], color='black',
            linestyle=':', linewidth=0.8, zorder=1)

    ax.text(5.25, 0.25, '6P transaction = one ADD request + one matching response\n'
                       'attacker (e.g. cell-allocation exhaustion) issues repeated ADD\n'
                       'requests to exhaust the schedule on B',
            ha='center', va='center', fontsize=9, style='italic',
            color='black')

    ax.set_title('6P ADD two-step handshake (RFC 8480)',
                 fontsize=13, fontweight='bold')

    plt.tight_layout()
    out_png = OUT / 'sixp_handshake.png'
    fig.savefig(out_png, dpi=140, bbox_inches='tight')
    fig.savefig(out_png.with_suffix('.pdf'), bbox_inches='tight')
    plt.close(fig)
    print(f'Wrote {out_png.with_suffix(".pdf")} + .png')


def main():
    fig_stack()
    fig_slotframe()
    fig_6p_handshake()


if __name__ == '__main__':
    main()
