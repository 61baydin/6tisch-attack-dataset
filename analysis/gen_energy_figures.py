#!/usr/bin/env python3
"""Generate network-wide energy time-series figure (one panel per attack).

Reads telemetry logs, sums delta_tx + delta_rx across all motes per 10-second
bin, converts Energest ticks to Joules (exp5438 / CC2520 approximate model),
plots mean +/- std across runs vs simulation time. A shaded band marks the
designed attack-start window (Uniform[20, 25] min in the v3 firmware).

Usage:
  python3 gen_energy_figures.py 21   # uses 2026-05*_<atk>-v2-*-multirun-*.log
  python3 gen_energy_figures.py 31   # uses 2026-05*_<atk>-v3-30-*-multirun-*.log
"""
import sys, re, glob, warnings
from pathlib import Path
import numpy as np
import pandas as pd
warnings.filterwarnings('ignore')

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

SCALE = sys.argv[1] if len(sys.argv) > 1 else '21'
SLUG = 'v2' if SCALE == '21' else 'v3-30'

ATTACKS = ['blackhole', 'decrease', 'dis', 'flooding', 'shared-slot',
           'slot-exhaustion', 'timekeep']
DISPLAY = {'blackhole': 'Blackhole', 'decrease': 'Decreased Rank',
           'dis': 'DIS Flooding', 'flooding': 'Application Flooding',
           'shared-slot': 'TSCH Shared Cell',
           'slot-exhaustion': '6P Cell Exhaustion',
           'timekeep': 'TSCH Desynchronization'}

# Energest tick -> Joule conversion (exp5438 + CC2520 datasheet typical)
ENERGEST_SECOND = 32768       # exp5438 RTIMER_ARCH_SECOND (32 kHz)
V_BATT = 3.0                  # supply
I_TX   = 0.025                # 25 mA TX
I_RX   = 0.020                # 20 mA RX
TX_J_PER_TICK = I_TX * V_BATT / ENERGEST_SECOND
RX_J_PER_TICK = I_RX * V_BATT / ENERGEST_SECOND

LOG_RE = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
COLS = ['timestamp', 'node_id', 'parent_id', 'rank', 'buf_occupancy',
        'dio_sent', 'dao_sent', 'dis_sent', 'nbr_count', 'tx_slot_count',
        'parent_switch_count', 'rssi', 'route_count', 'delta_tx',
        'delta_rx', 'app_packet_count', 'is_attacker', 'attack_type']
BIN_S = 10                    # 10-second bins (matches telemetry tick)


def parse_log(fn):
    rows = []
    with open(fn) as f:
        for line in f:
            m = LOG_RE.search(line)
            if not m:
                continue
            vals = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
            if len(vals) >= 18:
                rows.append(vals[:18])
    return rows


def collect_traces(atk):
    """Return list of (t_min_array, network_energy_J_per_bin) per run."""
    pat = f'2026-05*_{atk}-{SLUG}-*-multirun-*.log'
    files = sorted(glob.glob(pat))
    traces = []
    for fn in files:
        rows = parse_log(fn)
        if not rows:
            continue
        df = pd.DataFrame(rows, columns=COLS)
        df = df[(df['delta_tx'] >= 0) & (df['delta_rx'] >= 0)]
        df['e_record'] = (df['delta_tx'] * TX_J_PER_TICK +
                          df['delta_rx'] * RX_J_PER_TICK)
        df['t_bin'] = (df['timestamp'] // BIN_S) * BIN_S
        net = df.groupby('t_bin')['e_record'].sum().reset_index()
        traces.append(net)
    return traces


def aggregate(traces, t_max_min=None):
    """Compute mean+std at each time bin across runs."""
    if not traces:
        return None
    max_t = max(tr['t_bin'].max() for tr in traces)
    if t_max_min:
        max_t = min(max_t, int(t_max_min * 60))
    all_t = np.arange(0, max_t + BIN_S, BIN_S)
    aligned = np.full((len(traces), len(all_t)), np.nan)
    for i, tr in enumerate(traces):
        m = tr.set_index('t_bin')['e_record']
        for j, t in enumerate(all_t):
            if t in m.index:
                aligned[i, j] = m.loc[t]
    # Treat missing as 0 (no telemetry = no recorded delta)
    aligned = np.nan_to_num(aligned, nan=0.0)
    return all_t / 60.0, aligned.mean(axis=0), aligned.std(axis=0)


def main():
    print(f'=== Energy time-series, {SCALE}-mote ({SLUG}) ===', flush=True)
    fig, axes = plt.subplots(4, 2, figsize=(11, 11), sharex=True)
    axes_flat = axes.flatten()

    # Determine global plot range based on first available trace
    sample = collect_traces(ATTACKS[0])
    t_max = max((tr['t_bin'].max() for tr in sample), default=1800) / 60.0
    t_max = max(t_max, 30.0)

    for i, atk in enumerate(ATTACKS):
        ax = axes_flat[i]
        traces = collect_traces(atk)
        if not traces:
            ax.set_title(f'{DISPLAY[atk]} (veri yok)', fontsize=10)
            ax.text(0.5, 0.5, 'no logs found', transform=ax.transAxes,
                    ha='center', va='center', alpha=0.5)
            continue
        t_min, mean, std = aggregate(traces, t_max_min=t_max)
        ax.plot(t_min, mean, color='#1f77b4', linewidth=1.4, label='ortalama')
        ax.fill_between(t_min, np.clip(mean - std, 0, None), mean + std,
                        alpha=0.2, color='#1f77b4', label='±1 std')
        # Designed attack-start window (Uniform[20, 25] min in v3 firmware)
        ax.axvspan(20, 25, alpha=0.15, color='red',
                   label='saldırı başlangıç penceresi')
        ax.set_title(f'{DISPLAY[atk]}  (n={len(traces)} koşu, '
                     f'zirve ≈ {mean.max() * 1000:.1f} mJ/10s)',
                     fontsize=10)
        ax.set_ylabel('enerji (J / 10s)', fontsize=9)
        ax.grid(True, linestyle=':', alpha=0.4)
        ax.set_xlim(0, t_max)
        if i == 0:
            ax.legend(fontsize=7, loc='upper left')

    # Hide unused 8th panel; add x-labels to bottom row
    axes_flat[7].axis('off')
    for ax in [axes_flat[5], axes_flat[6]]:
        ax.set_xlabel('simülasyon zamanı (dk)', fontsize=9)

    plt.suptitle(f'Ağ-geneli enerji tüketimi vs zaman '
                 f'({SCALE}-mote, koşular üzeri ortalama)',
                 fontsize=12, y=1.00)
    plt.tight_layout()
    out = Path('paper/figures')
    out.mkdir(parents=True, exist_ok=True)
    suffix = '' if SCALE == '21' else '_31mote'
    fn = out / f'energy_timeseries{suffix}'
    fig.savefig(f'{fn}.pdf', bbox_inches='tight')
    fig.savefig(f'{fn}.png', dpi=140, bbox_inches='tight')
    plt.close(fig)
    print(f'Wrote {fn}.{{pdf,png}}', flush=True)


if __name__ == '__main__':
    main()
