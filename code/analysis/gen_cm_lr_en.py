#!/usr/bin/env python3
"""Sekil 17 ve 18: cok-sinifli karmasa matrisi (LR, grup-farkinda), 21- ve
31-mote a5 zincirleri. Eksen ve baslik metinleri Ingilizce, yazi puntolari buyutulmus
(IEEE Access hakem maddeleri R3-8 ve R4-I35).

Kullanim:  python3 gen_cm_lr_en.py [cikti_dizini]
"""
import re, sys, glob, warnings, collections
from pathlib import Path
import numpy as np, pandas as pd
warnings.filterwarnings('ignore')
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score
from sklearn.preprocessing import StandardScaler
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt

ATT = ['blackhole', 'decrease', 'dis', 'flooding', 'shared-slot',
       'slot-exhaustion', 'timekeep']
FAM = {0: 'NONE', 1: 'Blackhole', 2: 'Decrease', 3: 'DIS', 4: 'Flooding',
       5: 'Shared', 6: '6P', 7: 'Desync'}
BASE = ['rank', 'buf_occupancy', 'dio_sent', 'dao_sent', 'dis_sent',
        'nbr_count', 'tx_slot_count', 'parent_switch_count', 'rssi',
        'route_count', 'delta_tx', 'delta_rx', 'app_packet_count']
NEW = ['forward_ratio', 'bcast_tx']
COLS = ['timestamp', 'node_id', 'parent_id'] + BASE + NEW + ['is_attacker', 'attack_type']
FEAT = BASE + NEW + ['rank_increase', 'd_app']
RX = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")

OUTDIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('paper/figures')


def parse(fn):
    out = []
    for ln in open(fn):
        m = RX.search(ln)
        if m:
            v = [int(x) for x in m.group(1).split(',') if x.strip()]
            if len(v) == 20:
                out.append(v)
    return out


def canon(attack, pl, scale):
    fs = [f for f in glob.glob(
        f'dataset_v3/single/logs/*_{attack}-n{scale}-{pl}-a5-w*.log')
        if 'cooja' not in f and parse(f)]
    return sorted(fs, key=lambda f: f.split('_')[1] + f.split('_')[2])[-1] if fs else None


def build(scale):
    rows = []
    for atk in ATT:
        for pl in ['core', 'mid', 'edge']:
            f = canon(atk, pl, scale)
            if f:
                for v in parse(f):
                    rows.append(v + [Path(f).stem])
    df = pd.DataFrame(rows, columns=COLS + ['run_id'])
    df = df[df.parent_id != 0].sort_values(
        ['run_id', 'node_id', 'timestamp']).reset_index(drop=True)
    inc = np.full(len(df), np.nan)
    for rid, g in df.groupby('run_id'):
        lut = collections.defaultdict(list)
        for t, nid, rk in zip(g.timestamp, g.node_id, g['rank']):
            lut[nid].append((t, rk))
        for k in lut:
            lut[k].sort()
        for idx, t, pid, rk in zip(g.index, g.timestamp, g.parent_id, g['rank']):
            if pid in lut:
                arr = [r for tt, r in lut[pid] if tt <= t]
                if arr:
                    inc[idx] = rk - arr[-1]
    df['rank_increase'] = pd.Series(inc, index=df.index).fillna(0)
    df['d_app'] = df.groupby(['run_id', 'node_id'])['app_packet_count'] \
                    .diff().fillna(0).clip(lower=0)
    return df


def run(scale, out_stem, title_scale):
    df = build(scale)
    X = StandardScaler().fit_transform(df[FEAT].values.astype(float))
    y = df.attack_type.values
    g = (df.run_id.astype(str) + '|' + df.node_id.astype(str)).values
    cv = StratifiedGroupKFold(5, shuffle=True, random_state=42)
    yp = np.empty_like(y)
    for tr, te in cv.split(X, y, g):
        m = LogisticRegression(max_iter=1000, class_weight='balanced',
                               random_state=42)
        m.fit(X[tr], y[tr]); yp[te] = m.predict(X[te])
    labels = sorted(set(y)); names = [FAM[i] for i in labels]
    macro = f1_score(y, yp, labels=labels, average='macro')
    acc = accuracy_score(y, yp)
    per = f1_score(y, yp, labels=labels, average=None)
    print(f'[n{scale}] rows={len(df)} MACRO-F1={macro:.3f} ACC={acc:.2f}')
    print('   per-class F1: ' + ', '.join(f'{n}={v:.2f}' for n, v in zip(names, per)))
    # Metrikleri de yaz: makaledeki cok-sinifli sayilar boylece kaynakli olur.
    pd.DataFrame([dict(scale=int(scale), rows=len(df), macro_f1=round(macro, 4),
                       accuracy=round(acc, 4),
                       **{f'f1_{n}': round(float(v), 4) for n, v in zip(names, per)})]) \
      .to_csv(f'core_multiclass_{scale}.csv', index=False)

    cm = confusion_matrix(y, yp, labels=labels).astype(float)
    rs = cm.sum(1, keepdims=True); cmn = np.where(rs > 0, cm / rs * 100, 0)
    fig, ax = plt.subplots(figsize=(9, 7))
    im = ax.imshow(cmn, cmap='Blues', vmin=0, vmax=100, aspect='auto')
    ax.set_xticks(range(len(names)))
    ax.set_xticklabels(names, rotation=35, ha='right', fontsize=13)
    ax.set_yticks(range(len(names)))
    ax.set_yticklabels(names, fontsize=13)
    ax.set_xlabel('Predicted class', fontsize=14)
    ax.set_ylabel('True class', fontsize=14)
    ax.set_title('LR multi-class confusion matrix (row %%), %s a5\n'
                 'StratifiedGroupKFold k=5, macro-F1=%.3f' % (title_scale, macro),
                 fontsize=14)
    for i in range(len(names)):
        for j in range(len(names)):
            v = cmn[i, j]
            ax.text(j, i, '%.0f' % v, ha='center', va='center', fontsize=12,
                    color='white' if v > 50 else 'black', fontweight='bold')
    cb = plt.colorbar(im, ax=ax)
    cb.set_label('row percentage', fontsize=13)
    cb.ax.tick_params(labelsize=12)
    plt.tight_layout()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    plt.savefig(OUTDIR / f'{out_stem}.pdf', bbox_inches='tight')
    # PNG output disabled (paper uses PDF only)
    # plt.savefig(OUTDIR / f'{out_stem}.png', dpi=140, bbox_inches='tight')
    plt.close(fig)
    print('   wrote', OUTDIR / f'{out_stem}.pdf')


if __name__ == '__main__':
    run('21', 'confusion_matrix_lr', '21-mote')
    run('31', 'confusion_matrix_lr_31mote', '31-mote')
