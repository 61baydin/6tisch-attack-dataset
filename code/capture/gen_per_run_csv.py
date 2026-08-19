#!/usr/bin/env python3
"""Emit a clean CSV (header + 20 columns) for every run log.
Creates a csv/ subdirectory under single/, multiattack/ and multiseed/,
so each run ships raw .log + .pcap + clean .csv."""
import re, glob, os, csv

ROOT='dataset_v3'
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
COLS=['timestamp','node_id','parent_id','rank','buf_occupancy','dio_sent','dao_sent',
      'dis_sent','nbr_count','tx_slot_count','parent_switch_count','rssi','route_count',
      'delta_tx','delta_rx','app_packet_count','forward_ratio','bcast_tx','is_attacker','attack_type']

total_runs=0; total_rows=0
for kind in ('single','multiattack','multiseed'):
    outdir=f'{ROOT}/{kind}/csv'; os.makedirs(outdir, exist_ok=True)
    for fn in sorted(glob.glob(f'{ROOT}/{kind}/logs/*.log')):
        stem=os.path.basename(fn)[:-4]
        n=0
        with open(f'{outdir}/{stem}.csv','w',newline='') as out:
            w=csv.writer(out, lineterminator='\n'); w.writerow(COLS)
            for ln in open(fn):
                g=RX.search(ln)
                if not g: continue
                v=[x.strip() for x in g.group(1).split(',') if x.strip()]
                if len(v)==20: w.writerow(v); n+=1
        total_runs+=1; total_rows+=n
    print(f"{kind}: {len(glob.glob(f'{ROOT}/{kind}/csv/*.csv'))} csv")
print(f"toplam {total_runs} kosu, {total_rows:,} satir -> per-run CSV")
