# Reproducing the results

All commands are run from the repository root. Scripts use dataset-relative paths,
so place (or symlink) the dataset under the expected layout first.

## 0. Dependencies
```bash
python3 -m pip install numpy pandas "scikit-learn>=1.3" scipy matplotlib xgboost lightgbm torch
# pcap inspection (optional): wireshark / tshark
```

## 1. Get the data
All telemetry logs and CSVs (122 runs) ship in this repository under `data/`. The
scripts read paths under `dataset_v3/`, so expose the in-repo data with one symlink:
```bash
ln -s data dataset_v3
```
This makes `dataset_v3/single/logs/*` and `dataset_v3/multiattack/logs/*` resolve.
The pcaps are not needed for the detection/figure pipeline; for radio-level analysis,
download them from Zenodo (README §6) into `data/single/pcaps/` and
`data/multiattack/pcaps/`.

## 2. Regenerate the detection results
```bash
# headline 17-model windowed benchmark (group-aware)  -> Fig. model_comparison
python3 code/analysis/gen_model_compare_full.py
# per-record per-attack difficulty spectrum (LOGO)     -> Table f1_main
python3 code/analysis/analyze_canonical.py
# per-placement F1                                      -> placement table/heatmap
python3 code/analysis/analyze_placement.py
# identity-leakage ablation                             -> Table identity_ablation
python3 code/analysis/calc_identity.py
# single-attacker a1 naive RF                           -> a1 heatmap
python3 code/analysis/gen_a1_f1.py
# concurrent multi-attack (binary + multi-class)        -> confusion_matrix_multiattack
python3 code/analysis/gen_multiattack_eval.py
python3 code/analysis/gen_multiattack_seedspread.py    # 3-seed mean±std
# RF feature importance
python3 code/analysis/gen_fi_new.py
```

## 3. Regenerate the figures
```bash
python3 code/figures/gen_background_figures.py    # stack, slotframe, 6P handshake
python3 code/figures/gen_topology_figures.py      # 21/31-mote topologies
python3 code/figures/gen_attack_diagrams.py       # attack mechanism diagrams
python3 code/figures/gen_result_figures.py        # feature_signature + placement heatmap
python3 code/figures/gen_cm_new.py                # multi-class confusion (LR)
python3 code/figures/gen_model_comparison.py      # 17-model comparison
```

## 4. Regenerate the dataset from firmware (optional)
The attack-client firmware sources are in `attacks/` (one directory per attack, plus
the `border-router-*` pair and the `attacker-analyzer/` telemetry module), and the
Cooja scenarios are in `csc/` (`rpl-border-<attack>-v2.csc`). Building them requires
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
```
The Cooja radio seed is fixed (123456); the dispatcher seed selects attacker IDs.
