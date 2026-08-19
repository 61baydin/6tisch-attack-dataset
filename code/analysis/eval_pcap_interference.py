#!/usr/bin/env python3
"""Physical-layer interference between simultaneous attacks (reviewer item R3-5).

The reviewer asks whether concurrent attacks interfere at the radio, for example
whether DIS floods suppress poisoned Enhanced Beacons. The released radio captures
answer this directly, so this replaces the schedule-level argument with a measurement.

Method: every frame is placed in its TSCH slot from its timestamp (15 ms slots,
21-slot frame), the 802.15.4 header is decoded for frame type and source, and three
quantities are computed per run:
  * beacon rate and the slot offsets beacons occupy (EB suppression test)
  * frames per slot offset (does traffic stay in the cells the schedule assigns)
  * co-transmissions: slots carrying frames from two or more distinct sources,
    which is the only way two attacks can collide in the slot domain

Concurrent runs are compared against the single-attack runs of the same families.

Output: pcap_interference_runs.csv, pcap_interference_summary.txt
"""
import glob, os, re, struct, sys
import collections
import numpy as np, pandas as pd

SLOT_S = 0.015
FRAME_LEN = 21


def read_pcap(path):
    """Yield (timestamp_seconds, frame_bytes). Handles both byte orders."""
    with open(path, 'rb') as f:
        hdr = f.read(24)
        if len(hdr) < 24:
            return
        for endian in ('<', '>'):
            magic = struct.unpack(endian + 'I', hdr[:4])[0]
            if magic in (0xa1b2c3d4, 0xa1b23c4d):
                nano = magic == 0xa1b23c4d
                break
        else:
            return
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts, tsub, cl, ol = struct.unpack(endian + 'IIII', ph)
            data = f.read(cl)
            if len(data) < cl:
                return
            yield ts + (tsub / 1e9 if nano else tsub / 1e6), data


def decode(frame):
    """Minimal IEEE 802.15.4 header decode -> (type, src)."""
    if len(frame) < 3:
        return None, None
    fcf = struct.unpack('<H', frame[0:2])[0]
    ftype = fcf & 0x7                      # 0 beacon, 1 data, 2 ack, 3 mac command
    dest_mode = (fcf >> 10) & 0x3
    src_mode = (fcf >> 14) & 0x3
    pan_comp = (fcf >> 6) & 0x1
    i = 3                                   # FCF + sequence number
    if dest_mode == 2:
        i += 4                              # dest PAN + short address
    elif dest_mode == 3:
        i += 10                             # dest PAN + extended address
    if src_mode in (2, 3):
        if not pan_comp:
            i += 2                          # source PAN
        if src_mode == 2:
            src = struct.unpack('<H', frame[i:i + 2])[0] if len(frame) >= i + 2 else None
            i += 2
        else:
            src = struct.unpack('<Q', frame[i:i + 8])[0] & 0xFFFF if len(frame) >= i + 8 else None
            i += 8
    else:
        src = None
    return ftype, src


def analyse(path):
    """Phase-based metrics. The slot phase is measured continuously within the
    315 ms slotframe, which avoids the rounding artefacts of integer slot indices:
    a frame that starts in a slot can be timestamped a few milliseconds later."""
    rows = list(read_pcap(path))
    if not rows:
        return None
    t0 = rows[0][0]
    dur = rows[-1][0] - t0
    period = SLOT_S * FRAME_LEN
    types = collections.Counter()
    ph_beacon, ph_other = [], []
    per_slot_src = collections.defaultdict(set)
    for t, fr in rows:
        ftype, src = decode(fr)
        types[ftype] += 1
        ph = ((t - t0) % period) / SLOT_S          # 0..21 in slot units
        (ph_beacon if ftype == 0 else ph_other).append(ph)
        if src is not None and ftype in (0, 1, 3):
            per_slot_src[int((t - t0) / SLOT_S)].add(src)
    ph_beacon = np.array(ph_beacon); ph_other = np.array(ph_other)
    # the EB cell is slot offset 0; a frame timestamped up to one slot later is
    # still the same transmission, so the cell is measured as phase < 2.
    eb_cell = lambda a: float((a < 2).mean()) if len(a) else float('nan')
    co = sum(1 for v in per_slot_src.values() if len(v) >= 2)
    return dict(
        frames=len(rows), duration_s=round(dur, 1),
        beacons=types.get(0, 0), data=types.get(1, 0), acks=types.get(2, 0),
        cmds=types.get(3, 0),
        beacon_per_min=round(types.get(0, 0) / max(dur, 1) * 60, 1),
        frames_per_min=round(len(rows) / max(dur, 1) * 60, 1),
        beacon_in_eb_cell=round(eb_cell(ph_beacon), 4),
        other_in_eb_cell=round(eb_cell(ph_other), 4),
        busy_slots=len(per_slot_src),
        co_tx_slots=co,
        co_tx_share=round(co / max(len(per_slot_src), 1), 5),
    )


def main():
    out = []
    sets = [('multiattack', 'dataset_v3/multiattack/pcaps/*.pcap'),
            ('single', 'dataset_v3/single/pcaps/*-a5-w*.pcap')]
    for kind, pat in sets:
        for p in sorted(glob.glob(pat)):
            name = os.path.basename(p)[:-5]
            r = analyse(p)
            if not r:
                print('  unreadable:', name); continue
            r['run'] = name; r['kind'] = kind
            m = re.search(r'_multi-([a-z-]+)\+([a-z-]+)-n(\d+)', name)
            if m:
                r['families'] = f'{m.group(1)}+{m.group(2)}'; r['scale'] = m.group(3)
            else:
                m2 = re.search(r'_([a-z-]+)-n(\d+)-', name)
                r['families'] = m2.group(1) if m2 else '?'
                r['scale'] = m2.group(2) if m2 else '?'
            out.append(r)
            print(f"  {name[:58]:58} frames={r['frames']:7d} EB/min={r['beacon_per_min']:6.1f} "
                  f"co_tx={r['co_tx_share']:.3f}", flush=True)
    d = pd.DataFrame(out)
    d.to_csv('pcap_interference_runs.csv', index=False)

    lines = []
    lines.append('### Enhanced Beacon rate: concurrent runs vs single-attack runs ###')
    des_multi = d[(d.kind == 'multiattack') & d.families.str.contains('timekeep')]
    des_single = d[(d.kind == 'single') & (d.families == 'timekeep')]
    oth_multi = d[(d.kind == 'multiattack') & ~d.families.str.contains('timekeep')]
    for lbl, sub in [('concurrent runs containing Desync', des_multi),
                     ('single-attack Desync runs', des_single),
                     ('concurrent runs without Desync', oth_multi),
                     ('all single-attack a5 runs', d[d.kind == 'single'])]:
        if len(sub):
            lines.append(f'  {lbl:38} n={len(sub):3d}  EB/min = {sub.beacon_per_min.mean():6.1f} '
                         f'+/- {sub.beacon_per_min.std():.1f}   '
                         f'beacons in EB cell = {sub.beacon_in_eb_cell.mean():.3f}')
    lines.append('')
    lines.append('### Enhanced Beacon cell integrity ###')
    for lbl, sub in [('concurrent runs', d[d.kind == 'multiattack']),
                     ('single-attack runs', d[d.kind == 'single'])]:
        lines.append(f'  {lbl:38} beacons inside the EB cell = {sub.beacon_in_eb_cell.mean():.4f}, '
                     f'other traffic inside it = {sub.other_in_eb_cell.mean():.4f}')
    lines.append('')
    lines.append('### Co-transmission (slots with 2+ distinct senders) ###')
    for lbl, sub in [('concurrent runs', d[d.kind == 'multiattack']),
                     ('single-attack runs', d[d.kind == 'single'])]:
        lines.append(f'  {lbl:38} n={len(sub):3d}  share = {sub.co_tx_share.mean():.4f} '
                     f'+/- {sub.co_tx_share.std():.4f}')
    txt = '\n'.join(lines)
    open('pcap_interference_summary.txt', 'w').write(txt + '\n')
    print('\n' + txt)
    print('\nwrote: pcap_interference_runs.csv, pcap_interference_summary.txt')


if __name__ == '__main__':
    main()
