#!/usr/bin/env python3
"""New dataset multi-class confusion matrix (LR, group-aware), 21-mote a5,
canonical 20-column + 17 features."""
import re,glob,warnings,collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import confusion_matrix, f1_score
from sklearn.preprocessing import StandardScaler
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt

ATT=['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
FAM={0:'NONE',1:'Blackhole',2:'Decrease',3:'DIS',4:'Flooding',5:'Shared',6:'6P',7:'Desync'}
BASE=['rank','buf_occupancy','dio_sent','dao_sent','dis_sent','nbr_count','tx_slot_count','parent_switch_count','rssi','route_count','delta_tx','delta_rx','app_packet_count']
NEW=['forward_ratio','bcast_tx']
COLS=['timestamp','node_id','parent_id']+BASE+NEW+['is_attacker','attack_type']
FEAT=BASE+NEW+['rank_increase','d_app']
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
SCALE='21'

def parse(fn):
    out=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20: out.append(v)
    return out
def canon(attack,pl):
    fs=[f for f in glob.glob(f'dataset_v3/single/logs/*_{attack}-n{SCALE}-{pl}-a5-w*.log') if 'cooja' not in f and parse(f)]
    return sorted(fs,key=lambda f:f.split('_')[1]+f.split('_')[2])[-1] if fs else None

rows=[]
for atk in ATT:
    for pl in ['core','mid','edge']:
        f=canon(atk,pl)
        if f:
            for v in parse(f): rows.append(v+[Path(f).stem])
df=pd.DataFrame(rows,columns=COLS+['run_id'])
df=df[df.parent_id!=0].sort_values(['run_id','node_id','timestamp']).reset_index(drop=True)
# derived
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
y=df.attack_type.values
g=(df.run_id.astype(str)+'|'+df.node_id.astype(str)).values
cv=StratifiedGroupKFold(5,shuffle=True,random_state=42)
yp=np.empty_like(y)
for tr,te in cv.split(X,y,g):
    m=LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42)
    m.fit(X[tr],y[tr]); yp[te]=m.predict(X[te])
labels=sorted(set(y)); names=[FAM[i] for i in labels]
macro=f1_score(y,yp,labels=labels,average='macro')
print('MACRO-F1=%.3f'%macro)
cm=confusion_matrix(y,yp,labels=labels).astype(float)
rs=cm.sum(1,keepdims=True); cmn=np.where(rs>0,cm/rs*100,0)
fig,ax=plt.subplots(figsize=(9,7))
im=ax.imshow(cmn,cmap='Blues',vmin=0,vmax=100,aspect='auto')
ax.set_xticks(range(len(names))); ax.set_xticklabels(names,rotation=35,ha='right',fontsize=10)
ax.set_yticks(range(len(names))); ax.set_yticklabels(names,fontsize=10)
ax.set_xlabel('Predicted'); ax.set_ylabel('Actual')
ax.set_title('LR multi-class confusion matrix (row %%), 21-mote a5\nStratifiedGroupKFold k=5, macro-F1=%.3f'%macro,fontsize=11)
for i in range(len(names)):
    for j in range(len(names)):
        v=cmn[i,j]; ax.text(j,i,'%.0f'%v,ha='center',va='center',fontsize=9,color='white' if v>50 else 'black',fontweight='bold')
plt.colorbar(im,ax=ax,label='row %')
plt.tight_layout()
plt.savefig('paper/figures/confusion_matrix_lr.pdf',bbox_inches='tight')
plt.savefig('paper/figures/confusion_matrix_lr.png',dpi=140,bbox_inches='tight')
print('Wrote confusion_matrix_lr.pdf/.png')
