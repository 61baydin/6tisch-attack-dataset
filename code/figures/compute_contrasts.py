#!/usr/bin/env python3
"""Feature-signature contrasts for the new dataset, computed the way the
paper's Fig. feature_signature intends:
  ppm  = per-minute rate of app_packet_count (cumulative counter)
  ctrl = per-minute rate of (dio_sent+dao_sent+dis_sent) (cumulative counters)
  rank = mean RPL rank (instantaneous)
  buf  = mean buffer occupancy (instantaneous)
Rates/means taken over the attack window (ts>=1500 s) for both the attacker
pool and the normal pool, pooled over all placement runs (a5+a1) of a scale.
Prints Python literals ready to paste into gen_figures_placement.py.
"""
import re, glob, numpy as np
from pathlib import Path
LR=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
ATT=['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
WIN=1500
def rows(fn):
    o=[]
    for ln in open(fn):
        m=LR.search(ln)
        if not m: continue
        v=[int(x) for x in m.group(1).split(',') if x.strip()!='']
        if len(v)==20: o.append(v)
    return o
def node_rate(recs, col):
    recs=sorted(recs);
    if len(recs)<2: return 0.0
    dt=(recs[-1][0]-recs[0][0])/60.0
    return (recs[-1][col]-recs[0][col])/dt if dt>0 else 0.0
for sc in ['21','31']:
    P={'ppm':([],[]),'ctrl':([],[]),'rank':([],[]),'buf':([],[])}  # (atk,nrm) per attack
    res={k:([],[]) for k in P}
    print(f"\n# ---- n{sc} ----")
    for atk in ATT:
        # gather per-node windowed rows, split atk/nrm
        byn_atk={}; byn_nrm={}
        for fn in glob.glob(f'dataset_v3/single/logs/*_{atk}-n{sc}-*-a5-w*.log'):
            if Path(fn).name.startswith('cooja_'): continue
            for v in rows(fn):
                if v[0]<WIN: continue
                key=(fn,v[1]); is_a=v[18]==1
                (byn_atk if is_a else byn_nrm).setdefault(key,[]).append(v)
        def pool(byn):
            ppm=[node_rate(r,15) for r in byn.values()]
            ctrl=[node_rate(r,5)+node_rate(r,6)+node_rate(r,7) for r in byn.values()]
            rank=[np.mean([x[3] for x in r]) for r in byn.values()]
            buf=[np.mean([x[4] for x in r]) for r in byn.values()]
            f=lambda a: float(np.mean(a)) if a else 0.0
            return f(ppm),f(ctrl),f(rank),f(buf)
        a=pool(byn_atk); n=pool(byn_nrm)
        for i,k in enumerate(['ppm','ctrl','rank','buf']):
            res[k][0].append(round(a[i],2)); res[k][1].append(round(n[i],2))
    for k in ['ppm','ctrl','rank','buf']:
        print(f"    atk_{k} = {res[k][0]}")
        print(f"    nrm_{k} = {res[k][1]}")
