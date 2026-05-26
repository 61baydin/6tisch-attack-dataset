#!/usr/bin/env python3
"""Per-source PDR aggregation on the placement chain (a5+a1) at a given scale.

Pools the 6 placement cells per attack (core/mid/edge × {a5, a1}) so each
attack family's per-source PDR is the pooled average across all 6 cells.
"""
import sys, os, glob
sys.path.insert(0, '/home/msc/doktora_contiki/6tisch-ng-sra')
os.chdir('/home/msc/doktora_contiki/6tisch-ng-sra')

SCALE = sys.argv[1] if len(sys.argv) > 1 else '21'
SLUG = 'v2' if SCALE == '21' else 'v3-30'
SUFFIX = '' if SCALE == '21' else '_31mote'

os.environ['MIN_LOG_DATE'] = '2026-05-13_00-00'
import damage_analysis as da
from pathlib import Path

ATTACKS = ['blackhole','decrease','dis','flooding','shared-slot',
           'slot-exhaustion','timekeep']

summary = []
per_run = []
for atk in ATTACKS:
    files = []
    for pl in ['core','mid','edge']:
        files += sorted(glob.glob(f'2026-05*_{atk}-{SLUG}-{pl}-multirun-*.log'))
        files += sorted(glob.glob(f'2026-05*_{atk}-{SLUG}-{pl}-a1-multirun-*.log'))
    files = [f for f in files if not Path(f).name.startswith('cooja_')]
    runs = []
    for f in files:
        r = da.aggregate_run(f, is_baseline=False)
        if r is None: continue
        r['attack'] = atk
        runs.append(r)
        per_run.append(r)
    if runs:
        summary.append(da.summarize_attack(atk, runs))

da.print_summary_table(summary)

out_sum = Path(f'damage_placement{SUFFIX}_summary.csv')
out_per = Path(f'damage_placement{SUFFIX}_per_run.csv')
da.write_csv(summary, out_sum)
da.write_per_run_csv(per_run, out_per)
print(f"\nWrote {out_sum.name}, {out_per.name}")
