# Reproducing the results

All commands are run from the repository root.

## 0. Dependencies

```bash
python3 -m pip install --user numpy pandas scikit-learn>=1.0 scipy matplotlib xgboost lightgbm
```
Regenerating the dataset itself additionally needs Contiki-NG + Cooja and the
`msp430-gcc` toolchain (and `net-tools` for `tunslip6`); see Section 3.

## 1. Make the logs visible to the analysis scripts

The analysis scripts glob the telemetry logs by name from the current
directory. Flatten the four dataset folders into the working directory once:

```bash
ln -sf dataset/*/*.log .        # or: cp dataset/*/*.log .
```

## 2. Regenerate tables (F1, confusion, feature importance)

```bash
python3 analysis/eval_placement_a5.py 21     # Tables VI/VII + confusion (21-mote)
python3 analysis/eval_placement_a5.py 31     # Tables VI/VII + confusion (31-mote)
python3 analysis/analyze_full.py             # Tables IX/X/XI/XII (placement/scale/ablation)
python3 analysis/analyze_new.py              # gate per-attack group-aware F1 summary
```
`eval_placement_a5.py` prints the binary F1 table (RF/LR/XGBoost/LightGBM,
group-aware vs naive), the multi-class confusion matrix and classification
report, and the RF feature importances; it also writes
`confusion_matrix_xgboost{,_31mote}.{pdf,png}` and `binary_eval_a5{,_31mote}.csv`.

## 3. Regenerate figures

```bash
python3 analysis/gen_topology_figures.py        # topology_{21,30}mote(+_a5_placement)
python3 analysis/gen_figures_placement.py        # feature_signature (21-mote)
python3 analysis/gen_result_figures_31mote.py    # feature_signature_31mote
python3 -c "import sys; sys.path.insert(0,'analysis'); import gen_result_figures as g; g.fig_placement_heatmap()"   # placement_heatmap
python3 analysis/gen_attack_diagrams.py          # attack mechanism diagrams (static)
python3 analysis/gen_background_figures.py        # protocol-stack diagrams (static)
```
Outputs land in `paper/figures/` (or the script's configured output dir).

## 4. Regenerate the dataset from scratch (optional)

The headless generation harness is in `capture/`:

1. `sudo bash capture/setup_parallel_workers.sh` (one-time, NWORKERS namespaces).
2. The dispatcher fans out the 84 runs across worker namespaces; each worker
   builds a per-run variant CSC from the base scenarios in `csc/`, launches
   Cooja headless, starts `tunslip6` + `udp_listener_ipv6.py`, captures the
   telemetry, and validates it with `validate_run_log.py`:
   ```bash
   NWORKERS=6 sudo bash capture/dispatcher.sh        # full 84-run sweep
   NWORKERS=6 sudo bash capture/dispatcher.sh dis    # single attack family
   ```
Cooja random seed is fixed (123456) in every base CSC, so a re-run reproduces
the released logs deterministically (same attacker IDs per cell from master
seed 42).

## Evaluation caveat

Always evaluate with the group key `(run_id, node_id)`. Naive row-level k-fold
inflates per-attack F1 by up to +0.83 through per-node identity leakage; the
`analyze_*` / `eval_placement*` scripts report both so the gap is visible.
