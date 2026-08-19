#!/usr/bin/env python3
"""Per-attack feature importance (reviewer item R1-4).

The paper refers to a feature-importance ranking twice but never showed it, and the
only file on disk predates the current 17-feature schema. This recomputes it on
dataset_v3 with the released feature set, using the Random Forest of the benchmark
and averaging Gini importance over the group-aware folds rather than a single fit,
so the ranking is not an artefact of one train/test split.

Output: feature_importance_v3.csv (per attack x feature), feature_importance_top.csv
"""
import numpy as np, pandas as pd, warnings
warnings.filterwarnings('ignore')
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.preprocessing import StandardScaler
from eval_window_sweep import ATT, ATYPE, DISP, FEAT, load_run

KF = 5
PRETTY = {'rank': 'rank', 'buf_occupancy': 'buf_occupancy', 'dio_sent': 'dio_sent',
          'dao_sent': 'dao_sent', 'dis_sent': 'dis_sent', 'nbr_count': 'nbr_count',
          'tx_slot_count': 'tx_slot_count', 'parent_switch_count': 'parent_switch_count',
          'rssi': 'rssi', 'route_count': 'route_count', 'delta_tx': 'delta_tx',
          'delta_rx': 'delta_rx', 'app_packet_count': 'app_packet_count',
          'forward_ratio': 'forward_ratio', 'bcast_tx': 'bcast_tx',
          'rank_increase': 'rank_increase', 'd_app': 'd_app'}


def records(attack, atype):
    frames = []
    for scale in ['21', '31']:
        for pl in ['core', 'mid', 'edge']:
            df = load_run(scale, attack, pl)
            if df is None:
                continue
            df = df.copy(); df['run_id'] = f'{scale}{pl}'
            frames.append(df)
    if not frames:
        return None
    d = pd.concat(frames, ignore_index=True)
    X = d[FEAT].values.astype(float)
    y = ((d.attack_type.values == atype) & (d.is_attacker.values == 1)).astype(int)
    g = (d.run_id.astype(str) + '|' + d.node_id.astype(str)).values
    return X, y, g


def main():
    rows = []
    for a in ATT:
        r = records(a, ATYPE[a])
        if r is None:
            continue
        X, y, g = r
        cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
        imps = []
        for tr, te in cv.split(X, y, g):
            if len(np.unique(y[tr])) < 2:
                continue
            sc = StandardScaler().fit(X[tr])
            m = RandomForestClassifier(n_estimators=100, max_depth=10,
                                       class_weight='balanced', n_jobs=-1, random_state=42)
            m.fit(sc.transform(X[tr]), y[tr])
            imps.append(m.feature_importances_)
        imp = np.mean(imps, axis=0); sd = np.std(imps, axis=0)
        for f, v, s in zip(FEAT, imp, sd):
            rows.append(dict(attack=DISP[a], feature=PRETTY[f], importance=round(float(v), 4),
                             std=round(float(s), 4)))
        top = sorted(zip(FEAT, imp), key=lambda t: -t[1])[:4]
        print(f'{DISP[a]:24} ' + ', '.join(f'{f}={v:.3f}' for f, v in top), flush=True)
    d = pd.DataFrame(rows)
    d.to_csv('feature_importance_v3.csv', index=False)
    piv = d.pivot(index='feature', columns='attack', values='importance')
    piv.to_csv('feature_importance_v3_matrix.csv')
    top = (d.sort_values(['attack', 'importance'], ascending=[True, False])
             .groupby('attack').head(3)
             .assign(rank=lambda x: x.groupby('attack').cumcount() + 1))
    top.to_csv('feature_importance_top.csv', index=False)
    print('\nwrote: feature_importance_v3.csv, feature_importance_v3_matrix.csv, feature_importance_top.csv')


if __name__ == '__main__':
    main()
