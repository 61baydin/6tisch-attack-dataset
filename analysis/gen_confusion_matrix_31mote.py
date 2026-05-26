#!/usr/bin/env python3
"""31-mote analogue of gen_confusion_matrix.py: pool all 42 31-mote
scale-chain logs (7 attacks x 3 placements x 2 densities) and produce
the same XGBoost group-aware multi-class confusion matrix figure."""
import glob, re
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler

try:
    from xgboost import XGBClassifier
    HAVE_XGB = True
except ImportError:
    HAVE_XGB = False


ATTACK_FAMILIES = {
    0: 'NONE', 1: 'BLACKHOLE', 2: 'DECREASE', 3: 'DIS',
    4: 'FLOODING', 5: 'SHARED', 6: 'SLOT_EXH', 7: 'TIMEKEEP',
}

LOG_PATTERNS = [
    '2026-05-1*_blackhole-v3-30-*-multirun-*.log',
    '2026-05-1*_decrease-v3-30-*-multirun-*.log',
    '2026-05-1*_dis-v3-30-*-multirun-*.log',
    '2026-05-1*_flooding-v3-30-*-multirun-*.log',
    '2026-05-1*_shared-slot-v3-30-*-multirun-*.log',
    '2026-05-1*_slot-exhaustion-v3-30-*-multirun-*.log',
    '2026-05-1*_timekeep-v3-30-*-multirun-*.log',
]


def parse_log(filename):
    rows = []
    with open(filename) as f:
        for line in f:
            m = re.search(r"b'[\s]*([0-9,\-\s]+)'", line)
            if not m:
                continue
            vals = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
            if len(vals) >= 18:
                rows.append(vals[:18])
    return rows


def main():
    print("Loading 31-mote scale-chain logs ...")
    all_rows = []
    for pattern in LOG_PATTERNS:
        files = sorted(f for f in glob.glob(pattern)
                       if not Path(f).name.startswith('cooja_'))
        for fn in files:
            for vals in parse_log(fn):
                all_rows.append(vals + [Path(fn).stem])

    cols = ['timestamp', 'node_id', 'parent_id', 'rank', 'buf_occupancy',
            'dio_sent', 'dao_sent', 'dis_sent', 'nbr_count', 'tx_slot_count',
            'parent_switch_count', 'rssi', 'route_count', 'delta_tx',
            'delta_rx', 'app_packet_count', 'is_attacker', 'attack_type',
            'run_id']
    df = pd.DataFrame(all_rows, columns=cols)
    print(f"  Loaded {len(df)} rows from {df['run_id'].nunique()} runs.")
    print(df['attack_type'].value_counts().sort_index().to_string())

    feature_cols = ['rank', 'buf_occupancy', 'dio_sent', 'dao_sent',
                    'dis_sent', 'nbr_count', 'tx_slot_count',
                    'parent_switch_count', 'rssi', 'route_count',
                    'delta_tx', 'delta_rx', 'app_packet_count']
    X = df[feature_cols].values
    y = df['attack_type'].values
    groups = (df['run_id'].astype(str) + '|' + df['node_id'].astype(str)).values

    X_scaled = StandardScaler().fit_transform(X)
    cv = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)

    if not HAVE_XGB:
        print("xgboost not installed, aborting.")
        return

    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1,
                          eval_metric='mlogloss', n_jobs=-1, random_state=42,
                          verbosity=0)
    print("\n--- XGBoost (31-mote pooled, StratifiedGroupKFold k=5) ---")
    y_pred = np.empty_like(y)
    for fold, (tr, te) in enumerate(cv.split(X_scaled, y, groups), 1):
        model.fit(X_scaled[tr], y[tr])
        y_pred[te] = model.predict(X_scaled[te])
        acc = (y_pred[te] == y[te]).mean()
        print(f"  fold {fold}: acc={acc:.3f}, train={len(tr)}, test={len(te)}")

    labels_sorted = sorted(set(y))
    names = [ATTACK_FAMILIES[i] for i in labels_sorted]
    cm = confusion_matrix(y, y_pred, labels=labels_sorted)
    cm_norm = cm.astype(float)
    row_sums = cm_norm.sum(axis=1, keepdims=True)
    cm_norm = np.where(row_sums > 0, cm_norm / row_sums * 100.0, 0.0)

    print("\nConfusion matrix (counts):")
    print(pd.DataFrame(cm, index=names, columns=names).to_string())
    print("\nConfusion matrix (row %):")
    print(pd.DataFrame(cm_norm, index=names, columns=names).round(1).to_string())

    print("\nClassification report (group-aware):")
    print(classification_report(y, y_pred,
                                 labels=labels_sorted,
                                 target_names=names,
                                 digits=3, zero_division=0))

    fig, ax = plt.subplots(figsize=(9.5, 7.5))
    im = ax.imshow(cm_norm, cmap='Blues', vmin=0, vmax=100, aspect='auto')
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=35, ha='right', fontsize=10)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=10)
    ax.set_xlabel('Predicted class', fontsize=11)
    ax.set_ylabel('True class', fontsize=11)
    ax.set_title('XGBoost: multi-class confusion matrix (row %), 31-mote scale chain\n'
                 'StratifiedGroupKFold, k=5, group=(run, node)', fontsize=12)
    for i in range(len(names)):
        for j in range(len(names)):
            v = cm_norm[i, j]
            col = 'white' if v > 50 else 'black'
            ax.text(j, i, f'{v:.0f}', ha='center', va='center',
                    fontsize=9, color=col, fontweight='bold')
    plt.colorbar(im, ax=ax, label='row percentage')
    plt.tight_layout()

    out_dir = Path('paper/figures'); out_dir.mkdir(parents=True, exist_ok=True)
    out_pdf = out_dir / 'confusion_matrix_xgboost_31mote.pdf'
    out_png = out_dir / 'confusion_matrix_xgboost_31mote.png'
    fig.savefig(out_pdf, bbox_inches='tight')
    fig.savefig(out_png, dpi=140, bbox_inches='tight')
    plt.close(fig)
    print(f'  Wrote {out_pdf}')


if __name__ == '__main__':
    main()
