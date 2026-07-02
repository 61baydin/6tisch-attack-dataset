#!/usr/bin/env python3
"""Additional attack-effect time series (21-mote a5, 5-min):
 1) ts_control_dis_6p : control-packet load (DIO+DAO+DIS rate), DIS | 6P, per-placement
 2) ts_rank_decrease  : mean rank, attacker vs normal, Decreased Rank
Gray band = attack onset window."""
import re,glob,collections
import numpy as np
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
BIN=300
# 0ts 1node 2par 3rank 4buf 5dio 6dao 7dis ... 18isatk 19atype
def parse(fn):
    o=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20:o.append(v)
    return o
def canon(a,scale,pl):
    fs=[f for f in glob.glob(f'2026-06-1[45]_*_{a}-n{scale}-{pl}-a5-w*.log') if 'cooja' not in f and parse(f)]
    return sorted(fs,key=lambda f:f.split('_')[1]+f.split('_')[2])[-1] if fs else None
def control_series(fn):
    """per 5-min window: network-wide mean control-message rate (dio+dao+dis increment)."""
    rows=parse(fn); by=collections.defaultdict(list)
    for v in rows: by[v[1]].append((v[0],v[5]+v[6]+v[7]))
    for k in by: by[k].sort()
    tmax=max(v[0] for v in rows); bins=list(range(0,int(tmax)+BIN,BIN))
    def cum(nid,T):
        a=[c for t,c in by[nid] if t<=T]; return a[-1] if a else 0
    xs,ys=[],[]
    for i in range(1,len(bins)):
        inc=[cum(n,bins[i])-cum(n,bins[i-1]) for n in by]
        xs.append(bins[i]//60); ys.append(np.mean(inc))
    return xs,ys
def rank_series(fn):
    """per 5-min window: attacker vs normal; absolute rank AND rank_increase."""
    rows=parse(fn)
    lut=collections.defaultdict(list)
    for v in rows: lut[v[1]].append((v[0],v[3]))
    for k in lut: lut[k].sort()
    def prank(pid,t):
        a=[r for tt,r in lut[pid] if tt<=t] if pid in lut else []
        return a[-1] if a else None
    tmax=max(v[0] for v in rows); bins=list(range(0,int(tmax)+BIN,BIN))
    xs=[];aA=[];nA=[];aI=[];nI=[]
    for i in range(1,len(bins)):
        lo,hi=bins[i-1],bins[i]
        wa=[v for v in rows if lo<v[0]<=hi and v[18]==1 and v[3]>0]
        wn=[v for v in rows if lo<v[0]<=hi and v[18]==0 and v[3]>0]
        def inc(ws):
            o=[]
            for v in ws:
                pr=prank(v[2],v[0])
                if pr is not None: o.append(v[3]-pr)
            return o
        xs.append(hi//60)
        aA.append(np.mean([v[3] for v in wa]) if wa else np.nan)
        nA.append(np.mean([v[3] for v in wn]) if wn else np.nan)
        ia=inc(wa); ino=inc(wn)
        aI.append(np.mean(ia) if ia else np.nan); nI.append(np.mean(ino) if ino else np.nan)
    return xs,aA,nA,aI,nI

# --- Figure 1: control load (DIS only) ---
cols={'core':'tab:red','mid':'tab:orange','edge':'tab:blue'}
fig,ax=plt.subplots(figsize=(7.8,4.6))
for pl in ['core','mid','edge']:
    f=canon('dis','21',pl)
    if not f: continue
    xs,ys=control_series(f); ax.plot(xs,ys,marker='o',ms=4,color=cols[pl],label=pl)
ax.axvspan(20,25,alpha=0.10,color='gray')
ax.set_xlabel('Time (min)'); ax.set_ylabel('Control message rate (DIO+DAO+DIS / 5-min, network avg.)')
ax.grid(alpha=0.3); ax.legend(fontsize=9,title='placement')
ax.set_title('Attack effect: control-packet load (DIS Flooding, 21-mote a5)\ngray band = attack onset window',fontsize=11)
plt.tight_layout(); plt.savefig('paper/figures/ts_control_dis.pdf',bbox_inches='tight'); plt.savefig('paper/figures/ts_control_dis.png',dpi=140,bbox_inches='tight')
print('Wrote ts_control_dis')

# --- Figure 2: rank, decrease (2 panels: absolute rank | rank_increase) ---
cols={'core':'tab:red','mid':'tab:orange','edge':'tab:blue'}
fig,(axA,axB)=plt.subplots(1,2,figsize=(11,4.6))
nA_x=collections.defaultdict(list); nI_x=collections.defaultdict(list)
for pl in ['core','mid','edge']:
    f=canon('decrease','21',pl)
    if not f: continue
    xs,aA,nA,aI,nI=rank_series(f)
    axA.plot(xs,aA,marker='o',ms=4,color=cols[pl],label=f'attacker ({pl})')
    axB.plot(xs,aI,marker='o',ms=4,color=cols[pl],label=f'attacker ({pl})')
    for x,va,vi in zip(xs,nA,nI):
        if not np.isnan(va): nA_x[x].append(va)
        if not np.isnan(vi): nI_x[x].append(vi)
xs=sorted(nA_x)
axA.plot(xs,[np.mean(nA_x[x]) for x in xs],'--',color='dimgray',lw=2,label='normal (avg.)')
axB.plot(xs,[np.mean(nI_x[x]) for x in xs],'--',color='dimgray',lw=2,label='normal (avg.)')
for ax,t,yl in [(axA,'Absolute rank (placement-dependent, misleading)','Mean RPL rank'),
                (axB,'rank\\_increase $=$ rank$-$parent (consistent signature)','Mean rank\\_increase')]:
    ax.axvspan(20,25,alpha=0.10,color='gray'); ax.set_title(t,fontsize=11)
    ax.set_xlabel('Time (min)'); ax.set_ylabel(yl); ax.grid(alpha=0.3); ax.legend(fontsize=8)
fig.suptitle('Attack effect: Decreased Rank (21-mote, a5)',fontsize=12)
plt.tight_layout(); plt.savefig('paper/figures/ts_rank_decrease.pdf',bbox_inches='tight'); plt.savefig('paper/figures/ts_rank_decrease.png',dpi=140,bbox_inches='tight')
print('Wrote ts_rank_decrease')
