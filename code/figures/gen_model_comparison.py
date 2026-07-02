#!/usr/bin/env python3
"""17-model group-aware F1 comparison figure (paper headline).
Values from dataset_v3 gen_model_compare_full.py output (windowed W=16,
StratifiedGroupKFold k=5, 21+31 scale pooled)."""
from pathlib import Path
import matplotlib; matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

OUT=Path('figures')
# (model, group_F1, naive_F1) - _v3_models.txt AVERAGE block
DATA=[
 ('1D-CNN',0.77,0.93,'DL'),('GRU',0.76,0.91,'DL'),('BiLSTM',0.76,0.94,'DL'),
 ('CNN-LSTM',0.76,0.95,'DL'),('Transformer',0.75,0.95,'DL'),('LSTM',0.74,0.93,'DL'),
 ('TCN',0.74,0.95,'DL'),
 ('RF',0.70,0.89,'CL'),('DT',0.70,0.83,'CL'),('GBoost',0.68,0.85,'CL'),
 ('LightGBM',0.68,0.98,'CL'),('XGBoost',0.67,0.96,'CL'),('LR',0.65,0.71,'CL'),
 ('MLP',0.65,0.98,'CL'),('SVM',0.64,0.85,'CL'),('NB',0.61,0.64,'CL'),('kNN',0.60,0.92,'CL'),
]
DATA=sorted(DATA,key=lambda x:-x[1])
names=[d[0] for d in DATA]; grp=[d[1] for d in DATA]; naive=[d[2] for d in DATA]
fam=[d[3] for d in DATA]
y=np.arange(len(names))[::-1]  # best on top

fig,ax=plt.subplots(figsize=(8,6.5))
for yi,g,n,f in zip(y,grp,naive,fam):
    # naive->group gap (leakage) light gray bar
    ax.plot([g,n],[yi,yi],color='0.78',lw=2,zorder=1)
    ax.scatter(n,yi,marker='o',s=34,color='0.65',zorder=2)
    c='#1f77b4' if f=='DL' else '#d62728'
    ax.scatter(g,yi,marker='D',s=58,color=c,edgecolor='black',lw=0.5,zorder=3)
ax.set_yticks(y); ax.set_yticklabels(names,fontsize=10)
ax.set_xlabel('Mean per-attack F1 (detection)',fontsize=11)
ax.set_xlim(0.55,1.02)
ax.axvline(0.74,ls=':',color='0.4',lw=1)
ax.grid(True,axis='x',ls=':',alpha=0.5)
from matplotlib.lines import Line2D
leg=[Line2D([0],[0],marker='D',color='w',markerfacecolor='#1f77b4',markeredgecolor='k',markersize=9,label='Deep (windowed) - group-aware'),
     Line2D([0],[0],marker='D',color='w',markerfacecolor='#d62728',markeredgecolor='k',markersize=9,label='Classical/ensemble - group-aware'),
     Line2D([0],[0],marker='o',color='0.65',markersize=8,label='Naive (row-level) - leakage'),
     Line2D([0],[0],color='0.78',lw=2,label='Naive$-$group leakage gap')]
ax.legend(handles=leg,fontsize=8.5,loc='lower right',framealpha=0.95)
ax.set_title('Seventeen-model detection comparison (W=16 windows,\nStratifiedGroupKFold $k$=5, 21+31-mote pooled)',fontsize=11)
plt.tight_layout()
plt.savefig(OUT/'model_comparison.pdf',bbox_inches='tight')
plt.savefig(OUT/'model_comparison.png',dpi=140,bbox_inches='tight')
print('Wrote model_comparison.pdf/.png')
