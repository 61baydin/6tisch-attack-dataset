#!/usr/bin/env python3
"""Detailed model comparison (NEW data, 21-mote a5, 17 features).
Point models: LR, RF, Decision Tree, kNN.  Sequence models: 1D-CNN, LSTM.
Group-aware = StratifiedGroupKFold k=5 (group=node); naive = StratifiedKFold k=5.
LOGO is impractical for DL; all models are compared fairly on the same windows/folds.
Output: per-attack GROUP F1 table + average naive/group."""
import re,glob,warnings,collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier
from sklearn.naive_bayes import GaussianNB
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
import torch, torch.nn as nn
torch.manual_seed(42); np.random.seed(42)

W,KF,STRIDE,EP=16,5,2,8
ATT=['blackhole','decrease','dis','flooding','shared-slot','slot-exhaustion','timekeep']
DISP={'blackhole':'Blackhole','decrease':'Decrease','dis':'DIS','flooding':'AppFlood','shared-slot':'Shared','slot-exhaustion':'6P','timekeep':'Desync'}
ATYPE={a:i for i,a in enumerate(ATT,1)}
BASE=['rank','buf_occupancy','dio_sent','dao_sent','dis_sent','nbr_count','tx_slot_count','parent_switch_count','rssi','route_count','delta_tx','delta_rx','app_packet_count']
COLS=['timestamp','node_id','parent_id']+BASE+['forward_ratio','bcast_tx','is_attacker','attack_type']
FEAT=BASE+['forward_ratio','bcast_tx','rank_increase','d_app']
RX=re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
def parse(fn):
    o=[]
    for ln in open(fn):
        m=RX.search(ln)
        if m:
            v=[int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v)==20:o.append(v)
    return o
def canon(scale,a,pl):
    fs=[f for f in glob.glob(f'dataset_v3/single/logs/*_{a}-n{scale}-{pl}-a5-w*.log') if 'cooja' not in f and parse(f)]
    return sorted(fs)[-1] if fs else None
def load_run(scale,a,pl):
    """SINGLE run: derived features are computed PER-RUN."""
    f=canon(scale,a,pl)
    if not f: return None
    df=pd.DataFrame(parse(f),columns=COLS).sort_values(['node_id','timestamp']).reset_index(drop=True)
    df=df[df.parent_id!=0].reset_index(drop=True)
    lut=collections.defaultdict(list)
    for t,nid,rk in zip(df.timestamp,df.node_id,df['rank']): lut[nid].append((t,rk))
    for k in lut: lut[k].sort()
    inc=np.full(len(df),np.nan)
    for idx,t,pid,rk in zip(df.index,df.timestamp,df.parent_id,df['rank']):
        if pid in lut:
            arr=[r for tt,r in lut[pid] if tt<=t]
            if arr: inc[idx]=rk-arr[-1]
    df['rank_increase']=pd.Series(inc,index=df.index).fillna(0)
    df['d_app']=df.groupby('node_id')['app_packet_count'].diff().fillna(0).clip(lower=0)
    return df
def windows(a,atype):
    """21+31 mote, a5, 6 runs/attack. Group = run|node (run-aware)."""
    Xs,ys,gs=[],[],[]
    for scale in ['21','31']:
        for pl in ['core','mid','edge']:
            df=load_run(scale,a,pl)
            if df is None: continue
            rid=f"{scale}{pl}"
            for nid,grp in df.groupby('node_id'):
                F=grp[FEAT].values.astype(np.float32)
                lab=((grp.attack_type.values==atype)&(grp.is_attacker.values==1)).astype(np.int64)
                n=len(grp)
                if n<W: continue
                for s in range(0,n-W+1,STRIDE):
                    Xs.append(F[s:s+W]); ys.append(lab[s+W-1]); gs.append(f"{rid}|{nid}")
    return np.array(Xs),np.array(ys),np.array(gs)
class CNN(nn.Module):
    def __init__(s,d,h=48):
        super().__init__(); s.c1=nn.Conv1d(d,h,3,padding=1); s.c2=nn.Conv1d(h,h,3,padding=1); s.fc=nn.Linear(h,1)
    def forward(s,x):
        z=x.transpose(1,2); z=torch.relu(s.c1(z)); z=torch.relu(s.c2(z)); return s.fc(z.max(2).values).squeeze(-1)
class LSTM(nn.Module):
    def __init__(s,d,h=48):
        super().__init__(); s.r=nn.LSTM(d,h,batch_first=True); s.fc=nn.Linear(h,1)
    def forward(s,x): o,_=s.r(x); return s.fc(o[:,-1,:]).squeeze(-1)
class GRU(nn.Module):
    def __init__(s,d,h=48):
        super().__init__(); s.r=nn.GRU(d,h,batch_first=True); s.fc=nn.Linear(h,1)
    def forward(s,x): o,_=s.r(x); return s.fc(o[:,-1,:]).squeeze(-1)
class BiLSTM(nn.Module):
    def __init__(s,d,h=48):
        super().__init__(); s.r=nn.LSTM(d,h,batch_first=True,bidirectional=True); s.fc=nn.Linear(2*h,1)
    def forward(s,x): o,_=s.r(x); return s.fc(o[:,-1,:]).squeeze(-1)
class CNNLSTM(nn.Module):
    def __init__(s,d,h=48):
        super().__init__(); s.c=nn.Conv1d(d,h,3,padding=1); s.r=nn.LSTM(h,h,batch_first=True); s.fc=nn.Linear(h,1)
    def forward(s,x):
        z=torch.relu(s.c(x.transpose(1,2))).transpose(1,2); o,_=s.r(z); return s.fc(o[:,-1,:]).squeeze(-1)
class TCN(nn.Module):
    def __init__(s,d,h=48):
        super().__init__(); s.c1=nn.Conv1d(d,h,3,padding=1,dilation=1); s.c2=nn.Conv1d(h,h,3,padding=2,dilation=2); s.c3=nn.Conv1d(h,h,3,padding=4,dilation=4); s.fc=nn.Linear(h,1)
    def forward(s,x):
        z=x.transpose(1,2); z=torch.relu(s.c1(z)); z=torch.relu(s.c2(z)); z=torch.relu(s.c3(z)); return s.fc(z.max(2).values).squeeze(-1)
class TransformerClf(nn.Module):
    def __init__(s,d,h=48,nhead=4,nl=2):
        super().__init__(); s.proj=nn.Linear(d,h)
        enc=nn.TransformerEncoderLayer(h,nhead,h*2,batch_first=True,dropout=0.1)
        s.tr=nn.TransformerEncoder(enc,nl); s.fc=nn.Linear(h,1)
    def forward(s,x): z=s.proj(x); z=s.tr(z); return s.fc(z.mean(1)).squeeze(-1)
def train_nn(mk,Xtr,ytr,Xte,posw):
    m=mk(); opt=torch.optim.Adam(m.parameters(),lr=1e-3)
    lf=nn.BCEWithLogitsLoss(pos_weight=torch.tensor([posw],dtype=torch.float32))
    Xt=torch.tensor(Xtr); yt=torch.tensor(ytr,dtype=torch.float32); idx=np.arange(len(Xt)); m.train()
    for ep in range(EP):
        np.random.shuffle(idx)
        for i in range(0,len(idx),256):
            b=idx[i:i+256]; opt.zero_grad(); lf(m(Xt[b]),yt[b]).backward(); opt.step()
    m.eval()
    with torch.no_grad(): return (torch.sigmoid(m(torch.tensor(Xte))).numpy()>=0.5).astype(int)
PT={'LR':lambda:LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42),
    'RF':lambda:RandomForestClassifier(n_estimators=100,max_depth=10,class_weight='balanced',n_jobs=-1,random_state=42),
    'GBoost':lambda:GradientBoostingClassifier(n_estimators=100,max_depth=3,random_state=42),
    'DT':lambda:DecisionTreeClassifier(max_depth=10,class_weight='balanced',random_state=42),
    'SVM':lambda:SVC(kernel='rbf',class_weight='balanced',random_state=42),
    'kNN':lambda:KNeighborsClassifier(n_neighbors=5),
    'MLP':lambda:MLPClassifier(hidden_layer_sizes=(64,),max_iter=300,random_state=42),
    'NB':lambda:GaussianNB(),
    'LightGBM':lambda:LGBMClassifier(n_estimators=100,class_weight='balanced',random_state=42,verbose=-1)}
KEYS=['LR','RF','GBoost','XGBoost','LightGBM','DT','SVM','kNN','MLP','NB','1D-CNN','LSTM','GRU','BiLSTM','CNN-LSTM','TCN','Transformer']
def eval_split(X,y,g,splitter,grouped):
    nf=X.shape[2]; acc={k:[] for k in KEYS}
    sp=splitter.split(X,y,g) if grouped else splitter.split(X,y)
    for tr,te in sp:
        if len(np.unique(y[tr]))<2 or len(np.unique(y[te]))<2: continue
        sc=StandardScaler().fit(X[tr].reshape(-1,nf))
        Xtr=sc.transform(X[tr].reshape(-1,nf)).reshape(X[tr].shape).astype(np.float32)
        Xte=sc.transform(X[te].reshape(-1,nf)).reshape(X[te].shape).astype(np.float32)
        posw=max(1.0,(y[tr]==0).sum()/max(1,(y[tr]==1).sum()))
        for k in ['LR','RF','GBoost','DT','SVM','kNN','MLP','NB','LightGBM']:
            m=PT[k](); m.fit(Xtr[:,-1,:],y[tr]); acc[k].append(f1_score(y[te],m.predict(Xte[:,-1,:]),zero_division=0))
        mxg=XGBClassifier(n_estimators=100,max_depth=4,scale_pos_weight=posw,eval_metric='logloss',random_state=42,verbosity=0)
        mxg.fit(Xtr[:,-1,:],y[tr]); acc['XGBoost'].append(f1_score(y[te],mxg.predict(Xte[:,-1,:]),zero_division=0))
        acc['1D-CNN'].append(f1_score(y[te],train_nn(lambda:CNN(nf),Xtr,y[tr],Xte,posw),zero_division=0))
        acc['LSTM'].append(f1_score(y[te],train_nn(lambda:LSTM(nf),Xtr,y[tr],Xte,posw),zero_division=0))
        acc['GRU'].append(f1_score(y[te],train_nn(lambda:GRU(nf),Xtr,y[tr],Xte,posw),zero_division=0))
        acc['BiLSTM'].append(f1_score(y[te],train_nn(lambda:BiLSTM(nf),Xtr,y[tr],Xte,posw),zero_division=0))
        acc['CNN-LSTM'].append(f1_score(y[te],train_nn(lambda:CNNLSTM(nf),Xtr,y[tr],Xte,posw),zero_division=0))
        acc['TCN'].append(f1_score(y[te],train_nn(lambda:TCN(nf),Xtr,y[tr],Xte,posw),zero_division=0))
        acc['Transformer'].append(f1_score(y[te],train_nn(lambda:TransformerClf(nf),Xtr,y[tr],Xte,posw),zero_division=0))
    return {k:(float(np.mean(v)) if v else float('nan')) for k,v in acc.items()}
GRP={k:[] for k in KEYS}; NAI={k:[] for k in KEYS}; PERATK={}
for a in ATT:
    X,y,g=windows(a,ATYPE[a])
    if len(set(y))<2 or y.sum()<KF or len(set(g[y==1]))<KF:
        print('skip',a,flush=True); continue
    gr=eval_split(X,y,g,StratifiedGroupKFold(KF,shuffle=True,random_state=42),True)
    na=eval_split(X,y,g,StratifiedKFold(KF,shuffle=True,random_state=42),False)
    PERATK[a]=gr
    for k in KEYS:
        if not np.isnan(gr[k]): GRP[k].append(gr[k])
        if not np.isnan(na[k]): NAI[k].append(na[k])
    print('done',a,flush=True)
print("\n### PER-ATTACK GROUP-AWARE F1 (StratifiedGroupKFold k=5) ###")
print("Attack     "+''.join(f"{k:>9}" for k in KEYS))
for a in ATT:
    if a in PERATK: print(f"{DISP[a]:11}"+''.join(f"{PERATK[a][k]:>9.2f}" for k in KEYS))
print("\n### AVERAGE ###")
print("Model        Naive   Group   Diff")
for k in KEYS:
    n=np.mean(NAI[k]); gg=np.mean(GRP[k]); print(f"{k:11}{n:>7.2f}{gg:>8.2f}{n-gg:>+8.2f}")
