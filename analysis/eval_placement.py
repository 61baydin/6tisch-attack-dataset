#!/usr/bin/env python3
"""Full ML eval on the placement chain at a given scale.

Computes:
  - Multi-class XGBoost confusion matrix
  - Binary F1 (RF, LR, XGB, LightGBM) under LOGO group-aware + StratifiedKFold naive
  - RF Gini feature importance

Usage: python3 eval_placement.py [21|31]
"""
import sys, re, glob, warnings, json
from pathlib import Path
import numpy as np
import pandas as pd
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import (LeaveOneGroupOut, StratifiedKFold,
                                      StratifiedGroupKFold)
from sklearn.metrics import f1_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier

SCALE = sys.argv[1] if len(sys.argv) > 1 else '21'
SLUG = 'v2' if SCALE == '21' else 'v3-30'

ATTACK_FAMILIES = {0:'NONE',1:'BLACKHOLE',2:'DECREASE',3:'DIS',
                   4:'FLOODING',5:'SHARED',6:'SLOT_EXH',7:'TIMEKEEP'}

ATTACKS = ['blackhole','decrease','dis','flooding','shared-slot',
           'slot-exhaustion','timekeep']
DISPLAY = {'blackhole':'Blackhole','decrease':'Decreased Rank',
           'dis':'DIS Flooding','flooding':'Application Flooding',
           'shared-slot':'TSCH Shared Cell','slot-exhaustion':'6P Cell Exhaustion',
           'timekeep':'TSCH Desynchronization'}

LR = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")

def parse_log(fn):
    rows = []
    with open(fn) as f:
        for line in f:
            m = LR.search(line)
            if not m: continue
            vals = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
            if len(vals) >= 18: rows.append(vals[:18])
    return rows


def main():
    print(f"=== Placement chain eval, {SCALE}-mote ===")
    all_rows = []
    files = []
    for atk in ATTACKS:
        for pl in ['core','mid','edge']:
            files += sorted(glob.glob(f'2026-05*_{atk}-{SLUG}-{pl}-multirun-*.log'))
            files += sorted(glob.glob(f'2026-05*_{atk}-{SLUG}-{pl}-a1-multirun-*.log'))
    files = [f for f in files if not Path(f).name.startswith('cooja_')]
    print(f"Logs: {len(files)}")
    for fn in files:
        for v in parse_log(fn):
            all_rows.append(v + [Path(fn).stem])
    cols = ['timestamp','node_id','parent_id','rank','buf_occupancy',
            'dio_sent','dao_sent','dis_sent','nbr_count','tx_slot_count',
            'parent_switch_count','rssi','route_count','delta_tx',
            'delta_rx','app_packet_count','is_attacker','attack_type','run_id']
    df = pd.DataFrame(all_rows, columns=cols)
    print(f"Records: {len(df)} (atk {(df.is_attacker==1).sum()}, "
          f"norm {(df.is_attacker==0).sum()})")
    print("Per-class:")
    print(df.attack_type.value_counts().sort_index().to_string())

    feat = ['rank','buf_occupancy','dio_sent','dao_sent','dis_sent',
            'nbr_count','tx_slot_count','parent_switch_count','rssi',
            'route_count','delta_tx','delta_rx','app_packet_count']
    X = StandardScaler().fit_transform(df[feat].values)
    y = df.attack_type.values
    groups = (df.run_id.astype(str)+'|'+df.node_id.astype(str)).values

    # --- Multi-class XGBoost CM ---
    print("\n--- Multi-class XGBoost CM ---")
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                          eval_metric='mlogloss', n_jobs=-1, random_state=42,
                          verbosity=0)
    y_pred = np.empty_like(y)
    for fold,(tr,te) in enumerate(cv.split(X,y,groups), 1):
        model.fit(X[tr], y[tr])
        y_pred[te] = model.predict(X[te])
        print(f"  fold {fold}: acc={(y_pred[te]==y[te]).mean():.3f}",
              flush=True)
    labels = sorted(set(y))
    names = [ATTACK_FAMILIES[i] for i in labels]
    cm = confusion_matrix(y, y_pred, labels=labels)
    cm_norm = cm.astype(float)
    rs = cm_norm.sum(axis=1, keepdims=True)
    cm_norm = np.where(rs>0, cm_norm/rs*100., 0.)
    print("\nConfusion matrix row%:")
    print(pd.DataFrame(cm_norm, index=names, columns=names).round(1).to_string())
    print("\nClassification report:")
    print(classification_report(y, y_pred, labels=labels, target_names=names,
                                 digits=3, zero_division=0))

    fig, ax = plt.subplots(figsize=(9.5, 7.5))
    im = ax.imshow(cm_norm, cmap='Blues', vmin=0, vmax=100, aspect='auto')
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=35, ha='right', fontsize=10)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=10)
    ax.set_xlabel('Predicted class', fontsize=11)
    ax.set_ylabel('True class', fontsize=11)
    title = (f'XGBoost: multi-class confusion matrix (row %), '
             f'{SCALE}-mote placement chain\n'
             'StratifiedGroupKFold, k=5, group=(run, node)')
    ax.set_title(title, fontsize=12)
    for i in range(len(names)):
        for j in range(len(names)):
            v = cm_norm[i,j]
            col = 'white' if v > 50 else 'black'
            ax.text(j, i, f'{v:.0f}', ha='center', va='center',
                    fontsize=9, color=col, fontweight='bold')
    plt.colorbar(im, ax=ax, label='row percentage')
    plt.tight_layout()
    out_dir = Path('paper/figures'); out_dir.mkdir(parents=True, exist_ok=True)
    suffix = '' if SCALE == '21' else '_31mote'
    fig.savefig(out_dir / f'confusion_matrix_xgboost{suffix}.pdf',
                bbox_inches='tight')
    fig.savefig(out_dir / f'confusion_matrix_xgboost{suffix}.png',
                dpi=140, bbox_inches='tight')
    plt.close(fig)
    print(f'  Wrote confusion_matrix_xgboost{suffix}.pdf', flush=True)

    # --- Binary F1 per attack across 4 classifiers ---
    print("\n--- Binary F1 (4 classifiers) ---")
    print(f"{'Attack':<23} {'Model':<10} {'GroupF1':>8} {'NaiveF1':>8} {'Delta':>7}",
          flush=True)
    print('-'*60, flush=True)
    results = {}
    for atype, aname in [(i, DISPLAY[a]) for i,a in enumerate(ATTACKS, 1)]:
        mask = (df.attack_type==0) | (df.attack_type==atype)
        idx = np.where(mask)[0]
        X_a = X[idx]
        y_a = ((df.attack_type.values==atype) & (df.is_attacker.values==1))[idx].astype(int)
        g_a = groups[idx]
        atk_grps = set(g_a[y_a==1])
        if not atk_grps: continue

        models = {
            'RF': RandomForestClassifier(n_estimators=100, max_depth=10,
                  class_weight='balanced', n_jobs=-1, random_state=42),
            'LR': LogisticRegression(max_iter=1000, class_weight='balanced',
                  random_state=42),
            'XGBoost': XGBClassifier(n_estimators=200, max_depth=6,
                  learning_rate=0.1, eval_metric='logloss', n_jobs=-1,
                  random_state=42, verbosity=0),
            'LightGBM': LGBMClassifier(n_estimators=200, learning_rate=0.1,
                  max_depth=-1, class_weight='balanced', n_jobs=-1,
                  random_state=42, verbose=-1),
        }
        for mname, m in models.items():
            # Group F1 via LOGO (only on attacker-bearing folds)
            logo = LeaveOneGroupOut()
            fg = []
            for tr,te in logo.split(X_a, y_a, g_a):
                if not (set(g_a[te]) & atk_grps): continue
                mc = type(m)(**m.get_params())
                mc.fit(X_a[tr], y_a[tr])
                fg.append(f1_score(y_a[te], mc.predict(X_a[te]),
                                   zero_division=0))
            g_f1 = float(np.mean(fg)) if fg else 0.0
            # Naive F1 via StratifiedKFold k=5
            skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
            fn_ = []
            for tr,te in skf.split(X_a, y_a):
                mc = type(m)(**m.get_params())
                mc.fit(X_a[tr], y_a[tr])
                fn_.append(f1_score(y_a[te], mc.predict(X_a[te]),
                                    zero_division=0))
            n_f1 = float(np.mean(fn_))
            delta = n_f1 - g_f1
            results[(aname, mname)] = (g_f1, n_f1, delta)
            print(f"{aname:<23} {mname:<10} {g_f1:>8.3f} {n_f1:>8.3f} {delta:>+7.3f}",
                  flush=True)

    suffix = '' if SCALE == '21' else '_31mote'
    with open(f'binary_eval_placement{suffix}.csv', 'w') as f:
        f.write('attack,model,group_f1,naive_f1,delta\n')
        for (a,m),(g,n,d) in results.items():
            f.write(f'{a},{m},{g:.4f},{n:.4f},{d:.4f}\n')
    print(f"\nWrote binary_eval_placement{suffix}.csv")

    # --- Feature importance (RF on pooled multi-class) ---
    print("\n--- RF Feature importance (pooled multi-class) ---")
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    imps = np.zeros(len(feat))
    for fold,(tr,te) in enumerate(cv.split(X,y,groups), 1):
        rf = RandomForestClassifier(n_estimators=100, max_depth=10,
                                     class_weight='balanced', n_jobs=-1,
                                     random_state=42)
        rf.fit(X[tr], y[tr])
        imps += rf.feature_importances_
        print(f"  fold {fold} done", flush=True)
    imps /= 5
    for f,i in sorted(zip(feat, imps), key=lambda x:-x[1]):
        print(f"  {f}: {i:.3f}", flush=True)

if __name__ == '__main__':
    main()
