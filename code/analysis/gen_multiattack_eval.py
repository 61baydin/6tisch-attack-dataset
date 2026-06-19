#!/usr/bin/env python3
"""Coklu-saldiri (es-zamanli iki saldiri) tespit analizi, dataset_v3/multiattack.
36 kosu havuzlanir; grup-farkinda (StratifiedGroupKFold k=5, grup=run|node).
(a) ikili saldirgan tespiti F1; (b) cok-sinifli attack_type F1 + confusion.
Boylece ayni agda iki saldiri es-zamanli iken model her ikisini ayirabiliyor mu gorulur.
Cikti: konsol tablosu + paper/figures/confusion_matrix_multiattack.{pdf,png}
"""
import re, glob, warnings, collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import f1_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt

FAM={0:'NONE',1:'Blackhole',2:'Decrease',3:'DIS',4:'Flooding',5:'Shared',6:'6P',7:'Desync'}
BASE=['rank','buf_occupancy','dio_sent','dao_sent','dis_sent','nbr_count','tx_slot_count',
      'parent_switch_count','rssi','route_count','delta_tx','delta_rx','app_packet_count']
COLS=['timestamp','node_id','parent_id']+BASE+['forward_ratio','bcast_tx','is_attacker','attack_type']
FEAT=BASE+['forward_ratio','bcast_tx','rank_increase','d_app']
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")

def parse(fn):
    out=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20: out.append(v)
    return out

rows=[]
for fn in sorted(glob.glob('dataset_v3/multiattack/logs/*.log')):
    if 'cooja' in fn: continue
    rid=Path(fn).stem
    for v in parse(fn): rows.append(v+[rid])
df=pd.DataFrame(rows,columns=COLS+['run_id'])
df=df[df.parent_id!=0].sort_values(['run_id','node_id','timestamp']).reset_index(drop=True)
# turetilmis (kosu-ici)
inc=np.full(len(df),np.nan)
for rid,g in df.groupby('run_id'):
    lut=collections.defaultdict(list)
    for t,nid,rk in zip(g.timestamp,g.node_id,g['rank']): lut[nid].append((t,rk))
    for k in lut: lut[k].sort()
    for idx,t,pid,rk in zip(g.index,g.timestamp,g.parent_id,g['rank']):
        if pid in lut:
            arr=[r for tt,r in lut[pid] if tt<=t]
            if arr: inc[idx]=rk-arr[-1]
df['rank_increase']=pd.Series(inc,index=df.index).fillna(0)
df['d_app']=df.groupby(['run_id','node_id'])['app_packet_count'].diff().fillna(0).clip(lower=0)

X=StandardScaler().fit_transform(df[FEAT].values.astype(float))
g=(df.run_id.astype(str)+'|'+df.node_id.astype(str)).values
cv=StratifiedGroupKFold(5,shuffle=True,random_state=42)

# (a) ikili saldirgan tespiti
yb=df.is_attacker.values.astype(int)
ypb=np.empty_like(yb)
for tr,te in cv.split(X,yb,g):
    m=LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)
    m.fit(X[tr],yb[tr]); ypb[te]=m.predict(X[te])
print("### COKLU-SALDIRI (36 kosu, grup-farkinda) ###")
print(f"Ikili saldirgan tespiti (is_attacker) F1 = {f1_score(yb,ypb,zero_division=0):.3f}")

# (b) cok-sinifli attack_type
ym=df.attack_type.values
ypm=np.empty_like(ym)
for tr,te in cv.split(X,ym,g):
    m=LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)
    m.fit(X[tr],ym[tr]); ypm[te]=m.predict(X[te])
labels=sorted(set(ym)); names=[FAM[i] for i in labels]
macro=f1_score(ym,ypm,labels=labels,average='macro')
print(f"Cok-sinifli attack_type makro-F1 = {macro:.3f}  (siniflar: {names})")
for lb in labels:
    f=f1_score((ym==lb).astype(int),(ypm==lb).astype(int),zero_division=0)
    print(f"  {FAM[lb]:10}: F1={f:.2f}  (n={int((ym==lb).sum())})")

cm=confusion_matrix(ym,ypm,labels=labels).astype(float)
rs=cm.sum(1,keepdims=True); cmn=np.where(rs>0,cm/rs*100,0)
fig,ax=plt.subplots(figsize=(7,6))
im=ax.imshow(cmn,cmap='Blues',vmin=0,vmax=100,aspect='auto')
ax.set_xticks(range(len(names))); ax.set_xticklabels(names,rotation=35,ha='right',fontsize=9)
ax.set_yticks(range(len(names))); ax.set_yticklabels(names,fontsize=9)
ax.set_xlabel('Predicted'); ax.set_ylabel('True')
ax.set_title('Multi-attack multi-class confusion (row %%)\nLR, StratifiedGroupKFold k=5, macro-F1=%.3f'%macro,fontsize=10)
for i in range(len(names)):
    for j in range(len(names)):
        v=cmn[i,j]
        if v>0: ax.text(j,i,'%.0f'%v,ha='center',va='center',fontsize=8,color='white' if v>50 else 'black')
plt.colorbar(im,ax=ax,label='row %')
plt.tight_layout()
plt.savefig('paper/figures/confusion_matrix_multiattack.pdf',bbox_inches='tight')
plt.savefig('paper/figures/confusion_matrix_multiattack.png',dpi=140,bbox_inches='tight')
print("Wrote confusion_matrix_multiattack")
