#!/usr/bin/env python3
"""Friedman and Nemenyi tests over the per-fold scores (reviewer item R4-I22).

Input: sweep_w16_perfold.csv, the group-aware F1 of every (attack, fold, model). Blocks
are (attack, fold) pairs and treatments are the classifiers. The Friedman test asks
whether the classifiers differ at all; the Nemenyi post-hoc identifies which pairs are
separated. Critical difference: CD = q_alpha * sqrt(k(k+1)/(6N)) with
q_alpha = studentized_range.ppf(1-alpha, k, inf)/sqrt(2).

Output: stats_friedman_ranks.csv, stats_nemenyi_matrix.csv,
        figures/critical_difference.pdf
"""
import sys
import numpy as np, pandas as pd
from scipy.stats import friedmanchisquare, studentized_range, rankdata, norm
import matplotlib; matplotlib.use('Agg'); import matplotlib.pyplot as plt

SRC = sys.argv[1] if len(sys.argv) > 1 else 'sweep_w16_perfold.csv'
ALPHA = 0.05


def main():
    df = pd.read_csv(SRC)
    df = df[df.W == 16] if 'W' in df.columns else df
    piv = df.pivot_table(index=['attack', 'fold'], columns='model', values='f1')
    piv = piv.dropna(axis=0, how='any')
    models = list(piv.columns); k = len(models); N = len(piv)
    print(f'blocks (attack x fold): {N}, models: {k}')

    stat, p = friedmanchisquare(*[piv[m].values for m in models])
    print(f'Friedman chi2 = {stat:.2f}, p = {p:.3e}')

    # average ranks (1 = best)
    ranks = np.vstack([rankdata(-piv.iloc[i].values) for i in range(N)])
    avg = ranks.mean(0)
    order = np.argsort(avg)
    q = studentized_range.ppf(1 - ALPHA, k, np.inf) / np.sqrt(2)
    CD = q * np.sqrt(k * (k + 1) / (6.0 * N))
    print(f'Nemenyi critical difference (alpha={ALPHA}) = {CD:.3f}')

    out = pd.DataFrame(dict(model=[models[i] for i in order],
                            mean_f1=[round(float(piv[models[i]].mean()), 3) for i in order],
                            avg_rank=[round(avg[i], 2) for i in order]))
    out['friedman_chi2'] = round(stat, 2); out['friedman_p'] = p
    out['nemenyi_CD'] = round(CD, 3); out['n_blocks'] = N
    out.to_csv('stats_friedman_ranks.csv', index=False)
    print(out.to_string(index=False))

    # pairwise Nemenyi p-values (studentized range approximation)
    P = np.ones((k, k))
    se = np.sqrt(k * (k + 1) / (6.0 * N))
    for i in range(k):
        for j in range(i + 1, k):
            z = abs(avg[i] - avg[j]) / se
            pv = min(1.0, studentized_range.sf(z * np.sqrt(2), k, np.inf))
            P[i, j] = P[j, i] = pv
    pd.DataFrame(P, index=models, columns=models).round(4).to_csv('stats_nemenyi_matrix.csv')

    # critical-difference diagram
    fig, ax = plt.subplots(figsize=(9, 0.42 * k + 1.6))
    ys = np.arange(k)
    ax.barh(ys, [avg[i] for i in order], color='#4878A8', height=0.6)
    ax.set_yticks(ys); ax.set_yticklabels([models[i] for i in order], fontsize=12)
    ax.invert_yaxis()
    ax.set_xlabel('Average rank over %d (attack, fold) blocks; lower is better' % N, fontsize=13)
    best = avg[order[0]]
    ax.axvline(best + CD, color='crimson', ls='--', lw=1.6)
    ax.text(best + CD, k - 0.4, '  best rank + CD = %.2f' % (best + CD), color='crimson',
            fontsize=12, va='top')
    ax.set_title('Friedman test and Nemenyi critical difference (alpha=%.2f, CD=%.2f)\n'
                 'group-aware windowed benchmark, W=16' % (ALPHA, CD), fontsize=13)
    ax.tick_params(labelsize=12)
    plt.tight_layout()
    plt.savefig('paper/figures/critical_difference.pdf', bbox_inches='tight')
    plt.savefig('paper/figures/critical_difference.png', dpi=140, bbox_inches='tight')
    print('wrote: stats_friedman_ranks.csv, stats_nemenyi_matrix.csv, '
          'paper/figures/critical_difference.pdf')


if __name__ == '__main__':
    main()
