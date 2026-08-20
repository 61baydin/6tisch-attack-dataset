#!/usr/bin/env python3
"""Two ablations.

  A. Feature-plane ablation. The dataset's headline claim is that it adds TSCH and 6P
     telemetry to the RPL and application layers that earlier datasets already carry.
     That claim should be quantified rather than asserted, so detection is re-scored
     with the feature set restricted to each plane in turn.

  B. Component ablation of the layered detector, including the control the design
     needs: the layered detector uses a linear stage A and an ensemble stage B, so a
     flat ensemble must be evaluated too, otherwise a gain from the model class would
     be misread as a gain from the layering.

Output: ablation_feature_planes.csv, ablation_layered_components.csv, ablation_summary.txt
"""
import warnings, collections
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import LeaveOneGroupOut, StratifiedGroupKFold
from sklearn.metrics import f1_score
from sklearn.preprocessing import StandardScaler
from scipy import stats
from eval_window_sweep import ATT, ATYPE, DISP, FEAT, load_run
from eval_layered_detector import records_pooled, KF

RPL = ['rank', 'dio_sent', 'dao_sent', 'dis_sent', 'nbr_count', 'parent_switch_count',
       'route_count', 'rank_increase']
APP = ['app_packet_count', 'd_app']
MAC = ['buf_occupancy', 'tx_slot_count', 'bcast_tx', 'forward_ratio']
PHY = ['rssi']
ENERGY = ['delta_tx', 'delta_rx']
PLANES = {
    'RPL only': RPL,
    'RPL + application': RPL + APP,
    'RPL + application + energy/PHY': RPL + APP + ENERGY + PHY,
    'full (adds TSCH/6P MAC)': FEAT,
    'full minus MAC': [f for f in FEAT if f not in MAC],
}


def records(attack, atype):
    frames = []
    for scale in ['21', '31']:
        for pl in ['core', 'mid', 'edge']:
            df = load_run(scale, attack, pl)
            if df is None:
                continue
            df = df.copy(); df['run_id'] = f'{scale}{pl}'
            frames.append(df)
    d = pd.concat(frames, ignore_index=True)
    y = ((d.attack_type.values == atype) & (d.is_attacker.values == 1)).astype(int)
    g = (d.run_id.astype(str) + '|' + d.node_id.astype(str)).values
    return d, y, g


def logo_f1(X, y, g):
    f1s = []
    for tr, te in LeaveOneGroupOut().split(X, y, g):
        if len(np.unique(y[tr])) < 2 or y[te].sum() == 0:
            continue
        sc = StandardScaler().fit(X[tr])
        m = LogisticRegression(max_iter=1000, class_weight='balanced', random_state=42)
        m.fit(sc.transform(X[tr]), y[tr])
        f1s.append(f1_score(y[te], m.predict(sc.transform(X[te])), zero_division=0))
    return float(np.mean(f1s)) if f1s else float('nan')


def feature_planes():
    rows = []
    for a in ATT:
        d, y, g = records(a, ATYPE[a])
        for name, cols in PLANES.items():
            f1 = logo_f1(d[cols].values.astype(float), y, g)
            rows.append(dict(attack=DISP[a], plane=name, n_features=len(cols), f1=round(f1, 3)))
            print(f'  {DISP[a]:24} {name:32} F1={f1:.3f}', flush=True)
    return pd.DataFrame(rows)


def layered_components():
    """Flat LR, flat RF, layered LR+RF, layered LR+LR; per fold at both scales."""
    rows = []
    for scale in ('21', '31'):
        X, y, g = records_pooled(scale)
        labels = sorted(set(y))
        cv = StratifiedGroupKFold(KF, shuffle=True, random_state=42)
        for fi, (tr, te) in enumerate(cv.split(X, y, g)):
            sc = StandardScaler().fit(X[tr]); Xtr, Xte = sc.transform(X[tr]), sc.transform(X[te])
            def mac(name, yp):
                rows.append(dict(scale=scale, fold=fi, model=name,
                                 macro_f1=f1_score(y[te], yp, labels=labels, average='macro',
                                                   zero_division=0)))
            mac('flat LR', LogisticRegression(max_iter=1000, class_weight='balanced',
                                              random_state=42).fit(Xtr, y[tr]).predict(Xte))
            mac('flat RF', RandomForestClassifier(n_estimators=200, max_depth=12,
                                                  class_weight='balanced', n_jobs=-1,
                                                  random_state=42).fit(Xtr, y[tr]).predict(Xte))
            # both stage-A model classes, so the layering is not confounded with the
            # model class: a flat ensemble must be compared with a layered ensemble.
            a_tr = (y[tr] > 0).astype(int); m = a_tr == 1
            stageA = {'LR': LogisticRegression(max_iter=1000, class_weight='balanced',
                                               random_state=42),
                      'RF': RandomForestClassifier(n_estimators=200, max_depth=12,
                                                   class_weight='balanced', n_jobs=-1,
                                                   random_state=42)}
            for an, sa in stageA.items():
                sa.fit(Xtr, a_tr); pa = sa.predict(Xte)
                for bn, sb in [('RF', RandomForestClassifier(n_estimators=200, max_depth=12,
                                                             class_weight='balanced', n_jobs=-1,
                                                             random_state=42)),
                               ('LR', LogisticRegression(max_iter=1000, class_weight='balanced',
                                                         random_state=42))]:
                    sb.fit(Xtr[m], y[tr][m])
                    out = np.zeros(len(te), dtype=int)
                    if pa.sum():
                        out[pa == 1] = sb.predict(Xte[pa == 1])
                    mac(f'layered {an}+{bn}', out)
            print(f'  {scale}-mote fold{fi} done', flush=True)
    return pd.DataFrame(rows)


def main():
    import os
    if os.path.exists('ablation_feature_planes.csv'):
        fp = pd.read_csv('ablation_feature_planes.csv')
        print('=== A. feature-plane ablation: cached ===', flush=True)
    else:
        print('=== A. feature-plane ablation ===', flush=True)
        fp = feature_planes(); fp.to_csv('ablation_feature_planes.csv', index=False)
    piv = fp.pivot(index='attack', columns='plane', values='f1')
    piv = piv[list(PLANES.keys())]
    piv.loc['MEAN'] = piv.mean().round(3)

    print('\n=== B. layered component ablation ===', flush=True)
    lc = layered_components(); lc.to_csv('ablation_layered_components.csv', index=False)
    means = lc.groupby('model')['macro_f1'].mean().round(3)
    pv = lc.pivot_table(index=['scale', 'fold'], columns='model', values='macro_f1')

    lines = ['### A. Feature-plane ablation (per-record LR, LeaveOneGroupOut) ###',
             piv.round(3).to_string(), '']
    full = piv.loc['MEAN', 'full (adds TSCH/6P MAC)']
    for k in PLANES:
        lines.append(f'  {k:32} mean F1 = {piv.loc["MEAN", k]:.3f}   '
                     f'difference to full = {piv.loc["MEAN", k] - full:+.3f}')
    lines += ['', '### B. Layered component ablation (multi-class macro-F1) ###']
    for k, v in means.items():
        lines.append(f'  {k:16} {v:.3f}')
    for a, b in [('layered RF+RF', 'flat RF'), ('layered LR+RF', 'flat RF'),
                 ('layered LR+LR', 'flat LR'), ('flat RF', 'flat LR'),
                 ('layered RF+RF', 'layered LR+RF')]:
        w = stats.wilcoxon(pv[a], pv[b])
        lines.append(f'  {a} vs {b}: paired p = {w.pvalue:.4f}, '
                     f'mean difference = {float((pv[a]-pv[b]).mean()):+.3f}, '
                     f'wins {int((pv[a]>pv[b]).sum())}/{len(pv)}')
    txt = '\n'.join(lines)
    open('ablation_summary.txt', 'w').write(txt + '\n')
    print('\n' + txt)
    print('\nwrote: ablation_feature_planes.csv, ablation_layered_components.csv, ablation_summary.txt')


if __name__ == '__main__':
    main()
