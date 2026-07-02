#!/usr/bin/env python3
"""Difficulty spectrum: attacks sorted by LR group-aware F1, color-zoned."""
from pathlib import Path
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt
# LR group-aware F1 (average of 21 and 31), from analyze_canonical output
data=[('App Flooding',1.00),('6P Exhaustion',1.00),('DIS Flooding',0.99),
      ('Decreased Rank',0.80),('Blackhole',0.72),('TSCH Desync',0.67),
      ('TSCH Shared Cell',0.27)]
data=sorted(data,key=lambda x:x[1])
names=[d[0] for d in data]; vals=[d[1] for d in data]
def col(v): return '#2ca02c' if v>=0.90 else ('#ff7f0e' if v>=0.5 else '#d62728')
fig,ax=plt.subplots(figsize=(9,4.5))
bars=ax.barh(names,vals,color=[col(v) for v in vals])
for b,v in zip(bars,vals): ax.text(v+0.01,b.get_y()+b.get_height()/2,'%.2f'%v,va='center',fontweight='bold',fontsize=10)
ax.axvline(0.90,color='gray',ls=':',lw=1); ax.axvline(0.50,color='gray',ls=':',lw=1)
ax.set_xlim(0,1.08); ax.set_xlabel('LR group-aware F1 (21+31 avg.)')
ax.set_title('Attack detection difficulty spectrum\ngreen: easy (>=0.90)  orange: medium  red: hard (TSCH Shared, robust)')
ax.grid(axis='x',alpha=0.3)
plt.tight_layout(); plt.savefig('paper/figures/difficulty_spectrum.pdf',bbox_inches='tight'); plt.savefig('paper/figures/difficulty_spectrum.png',dpi=140,bbox_inches='tight')
print('Wrote difficulty_spectrum')
