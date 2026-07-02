#!/usr/bin/env python3
"""Scenario-based 5-min time series: PDR and energy (radio TX+RX).
Per attack, 2 panels (21 / 31 mote) x 3 lines (core/mid/edge), a5.
NO baseline; attack onset is already visible in the curve. Canonical 20-column logs.
Usage: python3 gen_timeseries.py <attack>   (e.g. blackhole)
"""
import re,glob,sys,collections
from pathlib import Path
import numpy as np
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
# 0ts 1node 2parent 3rank 4buf 5dio 6dao 7dis 8nbr 9txs 10psw 11rssi 12route 13dtx 14drx 15app ...
DISP={'blackhole':'Blackhole','dis':'DIS Flooding','flooding':'App Flooding','decrease':'Decreased Rank','slot-exhaustion':'6P Exhaustion','timekeep':'TSCH Desync','shared-slot':'Shared Cell'}
BIN=300
def parse(fn):
    out=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20: out.append(v)
    return out
def canon(a,scale,pl):
    fs=[f for f in glob.glob(f'2026-06-1[45]_*_{a}-n{scale}-{pl}-a5-w*.log') if 'cooja' not in f and parse(f)]
    return sorted(fs,key=lambda f:f.split('_')[1]+f.split('_')[2])[-1] if fs else None
def series(fn):
    """5-min window: PDR and mean radio (dtx+drx)."""
    rows=parse(fn)
    by=collections.defaultdict(list)
    for v in rows: by[v[1]].append(v)
    root=[n for n,vs in by.items() if sorted(vs,key=lambda x:x[0])[-1][2]==0]
    senders=[n for n in by if n not in root]
    root=root[0] if root else None
    tmax=max(v[0] for v in rows); bins=list(range(0,int(tmax)+BIN,BIN))
    def cumapp(node,T):
        a=[v[15] for v in sorted(by[node],key=lambda x:x[0]) if v[0]<=T]; return a[-1] if a else 0
    xs=[];pdr=[];en=[]
    for i in range(1,len(bins)):
        lo,hi=bins[i-1],bins[i]; mid=hi//60
        if root is not None:
            dr=cumapp(root,hi)-cumapp(root,lo)
            ds=sum(cumapp(n,hi)-cumapp(n,lo) for n in senders)
            if ds>0: pdr.append((mid,min(dr/ds,1.0)))   # PDR <= 1.0 (window-boundary artefact clipped)
        wr=[v for v in rows if lo<v[0]<=hi]
        # Energest tick -> ms  (exp5438/msp430: ENERGEST_SECOND=32768)
        if wr: en.append((mid,np.mean([(v[13]+v[14])*1000.0/32768.0 for v in wr])))
    return pdr,en
def plot(attack,metric):
    fig,ax=plt.subplots(figsize=(7.8,4.6))
    cols={'core':'tab:red','mid':'tab:orange','edge':'tab:blue'}
    scale='21'   # 21-mote only (meaningful and readable)
    for pl in ['core','mid','edge']:
        f=canon(attack,scale,pl)
        if not f: continue
        pdr,en=series(f)
        data=pdr if metric=='pdr' else en
        if data:
            xs,ys=zip(*data); ax.plot(xs,ys,marker='o',ms=4,color=cols[pl],label=pl)
    ax.axvspan(20,25,alpha=0.10,color='gray')
    ax.set_xlabel('Time (min)'); ax.grid(alpha=0.3); ax.legend(fontsize=9,title='placement')
    if metric=='pdr':
        ax.set_ylabel('Network PDR (5-min)'); ax.set_ylim(0,1.05)
        ttl=f'{DISP[attack]}: network PDR time series (21-mote, a5)\ngray band = attack onset window'
        out=f'paper/figures/ts_pdr_{attack}'
    else:
        ax.set_ylabel('Radio-on time  TX+RX (ms / sample)')
        ttl=f'{DISP[attack]}: radio-on time time series (21-mote, a5)'
        out=f'paper/figures/ts_energy_{attack}'
    ax.set_title(ttl,fontsize=12)
    plt.tight_layout(); plt.savefig(out+'.pdf',bbox_inches='tight'); plt.savefig(out+'.png',dpi=140,bbox_inches='tight')
    print('Wrote',out)
attack=sys.argv[1] if len(sys.argv)>1 else 'blackhole'
plot(attack,'pdr'); plot(attack,'energy')
