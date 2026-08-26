# Reproducing the results

All commands are run from the repository root. Scripts use dataset-relative paths,
so place (or symlink) the dataset under the expected layout first.

## 0. Dependencies
```bash
python3 -m pip install numpy pandas "scikit-learn>=1.3" scipy matplotlib xgboost lightgbm torch
# pcap inspection (optional): wireshark / tshark
```

## 1. Get the data
The full dataset (206 runs: logs, pcaps, csv) ships in this repository under `data/`:
84 single-attacker placement runs plus 2 attacker-free baseline runs in `data/single/`,
36 concurrent two-attacker runs in `data/multiattack/`, and the 84-run three-seed
replication in `data/multiseed/`.
The scripts read paths under `dataset_v3/`, so expose the in-repo data with one symlink:
```bash
ln -s data dataset_v3
```
This makes `dataset_v3/single/logs/*`, `dataset_v3/multiattack/logs/*` and
`dataset_v3/multiseed/logs/*` resolve. The
detection/figure pipeline uses the logs/csv; the pcaps are present for radio-level
analysis (Wireshark/tshark).

## 2. Regenerate the detection results
```bash
# headline 17-model windowed benchmark (group-aware)  -> Fig. model_comparison
python3 code/analysis/gen_model_compare_full.py
# the four core per-record tables in one pass:
#   f1_main, beyond_f1, identity_ablation, placement/scale
# writes core_f1_main.csv, core_beyond_f1.csv,
#        core_identity_ablation.csv, core_placement.csv
python3 code/analysis/eval_core_tables.py all
# single-attacker a1: naive row-level cells and the group-aware control
#   writes core_a1_naive.csv (-> a1 heatmap) and core_a1_group.csv
python3 code/analysis/eval_a1_naive.py
# concurrent multi-attack (binary + multi-class)        -> confusion_matrix_multiattack
python3 code/analysis/gen_multiattack_eval.py
python3 code/analysis/gen_multiattack_seedspread.py    # 3-seed mean±std
# RF feature importance
python3 code/analysis/gen_fi_new.py
```

`eval_core_tables.py` is the reference implementation of the protocol described in
Section V-C of the paper: LeaveOneGroupOut on `(run_id, node_id)` for the group-aware
columns, StratifiedKFold(k=5) for the naive columns, `LogisticRegression(max_iter=1000,
class_weight='balanced')` and `RandomForestClassifier(100 trees, max_depth=10,
class_weight='balanced')`, `random_state=42` throughout, with the scaler fitted on the
training split of each fold. Its four CSVs reproduce the corresponding tables cell for
cell; copies are kept in `results/`.

## 3. Regenerate the figures
```bash
python3 code/figures/gen_background_figures.py    # stack, slotframe, 6P handshake
python3 code/figures/gen_topology_figures.py      # 21/31-mote topologies
python3 code/figures/gen_attack_diagrams.py       # attack mechanism diagrams
python3 code/analysis/compute_contrasts_spread.py # within-run contrasts, nine runs per family
                                                  #   -> contrast_summary.csv, contrast_per_run.csv
python3 code/analysis/gen_contrast_errorbars.py   # feature_signature (both scales), with error bars
python3 code/figures/gen_placement_heatmap.py     # placement heatmap (reads core_placement.csv)
python3 code/analysis/gen_cm_lr_en.py             # multi-class confusion (LR), English labels
python3 code/figures/gen_model_comparison.py      # 17-model comparison (reads core_model_comparison.csv)
python3 code/figures/gen_a1_heatmap.py            # a1 heatmap (reads core_a1_naive.csv)
```

The naive (row-level) half of the model comparison is produced by
`code/analysis/eval_naive_baseline.py`, which re-scores the same W=16 windows under
`StratifiedKFold(k=5)` and merges the result with the group-aware per-fold scores from
`sweep_w16_perfold.csv` into `core_model_comparison.csv`. Every figure in the paper is
now generated from a released CSV; none carries hard-coded values.

## 4. Regenerate the dataset from firmware (optional)
The attack-client firmware sources are in `attacks/` (one directory per attack, plus
the `border-router-*` pair and the `attacker-analyzer/` telemetry module), and the
Cooja scenarios are in `csc/`: `rpl-border-<attack>-v3.csc` for the 21-mote topology and
`rpl-border-<attack>-v3-30.csc` for the 31-mote one. Both carry `TIMEOUT(3600000)`, the
60-minute run length used throughout, and the fixed radio seed 123456; `gen_csc_variant.py`
rewrites the attacker mote set, the radio seed and the pcap path per run. Building them requires
the Contiki-NG/4emac fork (`CONTIKI=../../../..`, `MAKE_MAC=MAKE_MAC_4EMAC`,
`MAKE_ROUTING=MAKE_ROUTING_RPL_CLASSIC`; see the main repository); each attack-client
Makefile pulls in `os/services/simple-energest` and the `attacker-analyzer` module.

The capture harness then drives Cooja headless. It needs the built firmware and a
`tunslip6` bridge (run by the user, requires sudo).
```bash
code/capture/setup_parallel_workers.sh     # parallel network namespaces
code/capture/dispatcher.sh                 # single-attacker 84-run plan
code/capture/dispatcher_multiattack.sh     # 36 concurrent runs (seeds 42,43,44)
code/capture/udp_listener_ipv6.py          # capture telemetry -> .log
code/capture/validate_run_log.py           # post-run validation
code/capture/gen_per_run_csv.py            # clean header-prefixed .csv next to each .log
```
The Cooja radio seed is fixed (123456); the dispatcher seed selects attacker IDs.
The dispatchers call the rest of the harness themselves: `multirun_worker.sh` and
`multirun_multiattack.sh` drive one run each, `tunslip6_keeper_ns.sh` and
`teardown_parallel_workers.sh` manage the per-worker network namespaces, and
`gen_multiattack_csc.py` builds the concurrent two-attacker scenarios.

## 5. Revision analyses (added in the resubmission)

All of these run on the released data and need no new simulation.

```bash
# window-length sweep (W = 4, 8, 16, 32, 64) and per-fold scores
python3 code/analysis/eval_window_sweep.py --w 16 --models all --resource --out sweep_w16
python3 code/analysis/eval_window_sweep.py --w 4,8,32,64 --models deep --out sweep_rest

# Friedman + Nemenyi over the per-fold scores  -> critical_difference figure
python3 code/analysis/stats_tests.py sweep_w16_perfold.csv

# grouping-key audit: (run,node) vs node vs run
python3 code/analysis/eval_loro.py

# detection delay from attack onset
python3 code/analysis/eval_time_to_detect.py

# hyperparameter robustness of the model ranking
python3 code/analysis/eval_hparam_robustness.py

# three-seed replication: per-cell distributions, CIs, placement/scale tests
python3 code/analysis/eval_multiseed.py

# confusion matrices, English labels and enlarged fonts
python3 code/analysis/gen_cm_lr_en.py
```

Outputs are written next to the working directory and a copy of every result
table is kept in `results/` for reference.

### Regenerating the replication corpus

The `multiseed/` chain was produced with the same harness as `single/`, with the
Cooja radio seed overridden per run:

```bash
NWORKERS=8 STAGGER_S=90 ATKCOUNTS="5" SCALES="21 30" \
  RADIO_SEEDS="7331 9173" WITH_BASELINE=0 \
  bash code/capture/dispatcher.sh
```

`RADIO_SEEDS` rewrites `<randomseed>` in each generated scenario file and tags the
run name with `-s<seed>`, so the replication runs never collide with the published
single-seed chain. `SKIP_EXISTING=1` (the default) makes the dispatcher resumable
after an interruption, and `KEEP_INVALID=1` retains a run whose attack window
falls outside the validator's expected interval, which is how the two atypical
cells noted in the README were preserved.

### Analyses added after the first revision round

```bash
# per-attack Random Forest feature importance, averaged over group-aware folds
python3 code/analysis/eval_feature_importance.py

# physical-layer interference between simultaneous attacks, measured on the pcaps
python3 code/analysis/eval_pcap_interference.py

# telemetry-suppression ablation: attacker rows withheld, benign nodes only
python3 code/analysis/eval_suppression.py

# the two figures these analyses feed
python3 code/analysis/gen_revision_figures.py figures/

# feature-plane ablation and the layered-detector component ablation
python3 code/analysis/eval_ablations.py
```

### Detector derived from the benchmark

```bash
# multi-scale temporal ensemble (binary) and layered attribution (multi-class)
python3 code/analysis/eval_layered_detector.py
```

The multi-scale ensemble is reported as a negative result: it does not separate from
the single-scale network under a Friedman test. The layered detector improves
multi-class macro-F1 by 0.071 and does so in every fold.

### Ablations

```bash
# feature-plane ablation and the component ablation of the layered detector
python3 code/analysis/eval_ablations.py
```

The component ablation is the control the layered design requires: layering is
compared against a flat classifier of the same model class, which shows that most of
the apparent gain over a linear baseline is the model class rather than the layering.
