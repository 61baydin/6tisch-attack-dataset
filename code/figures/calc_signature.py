#!/usr/bin/env python3
"""Decrease and 6P signature counts, new canonical 21-mote a5 (attacker vs normal)."""
import re,glob,collections
import numpy as np
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
# 0ts 1node 2parent 3rank 4buf 5dio 6dao 7dis 8nbr 9txs 10psw 11rssi 12route 13dtx 14drx 15app 16fr 17bc 18isa 19at
def parse(fn):
    out=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20: out.append(v)
    return out
def canon(a,pl):
    fs=[f for f in glob.glob(f'dataset_v3/single/logs/*_{a}-n21-{pl}-a5-w*.log') if 'cooja' not in f and parse(f)]
    return sorted(fs,key=lambda f:f.split('_')[1]+f.split('_')[2])[-1] if fs else None
def rows_for(a,atype):
    atk=[];nor=[]
    for pl in ['core','mid','edge']:
        f=canon(a,pl)
        if not f: continue
        rows=parse(f)
        # Parent-rank lookup for rank_increase (within-run)
        by=collections.defaultdict(list)
        for v in rows: by[v[1]].append((v[0],v[3]))
        for k in by: by[k].sort()
        for v in rows:
            pid=v[2]
            ri=None
            if pid in by:
                arr=[r for tt,r in by[pid] if tt<=v[0]]
                if arr: ri=v[3]-arr[-1]
            rec=dict(rank=v[3],buf=v[4],txs=v[9],ctrl=v[5]+v[6]+v[7],ri=ri)
            if v[18]==1 and v[19]==atype: atk.append(rec)
            elif v[19]==0: nor.append(rec)
    return atk,nor
def mean(lst,k):
    vals=[r[k] for r in lst if r[k] is not None]
    return np.mean(vals) if vals else float('nan')
print("=== Decreased Rank (atype=2) ===")
a,n=rows_for('decrease',2)
print(f"  rank:          attacker {mean(a,'rank'):.0f}  vs normal {mean(n,'rank'):.0f}")
print(f"  rank_increase: attacker {mean(a,'ri'):.0f}   vs normal {mean(n,'ri'):.0f}")
print("=== 6P / slot-exhaustion (atype=6) ===")
a,n=rows_for('slot-exhaustion',6)
print(f"  buf_occupancy: attacker {mean(a,'buf'):.2f} vs normal {mean(n,'buf'):.2f}")
print(f"  tx_slot_count: attacker {mean(a,'txs'):.2f} vs normal {mean(n,'txs'):.2f}")
print(f"  control(dio+dao+dis last cumulative): attacker {mean(a,'ctrl'):.0f} vs normal {mean(n,'ctrl'):.0f}")
