# 6TiSCHSet-2026: A Multi-Layer 6TiSCH Attack Dataset and Leakage-Aware IDS Benchmark

[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.22113021.svg)](https://doi.org/10.5281/zenodo.22113021)

Companion artefact for the paper **"6TiSCHSet-2026: A Multi-Layer Attack Dataset and
Leakage-Aware Intrusion-Detection Benchmark for IETF 6TiSCH Networks"** (Burak Aydin, Hakan Aydin, Yichao Jin, Sedat Gormus, 2026).

This repository is **self-contained**: it carries the **code** (capture/generation
harness, ML and figure pipeline), the **firmware sources and Cooja scenarios**, the
**documentation** (schema, run manifest), and the **full dataset for all 206 runs**:
labelled telemetry (`.log`), per-run radio captures (`.pcap`), and clean `.csv`
(~2.3 GB total).

---

## 1. Dataset at a glance

Seven attack families spanning five planes of the IETF 6TiSCH stack, plus six
concurrent two-attacker combinations:

| Plane | Attack | `attack_type` |
|---|---|---|
| Data | Blackhole | 1 |
| Routing | Decreased Rank | 2 |
| Control | DIS Flooding | 3 |
| Application | Application Flooding | 4 |
| MAC (TSCH) | TSCH Shared Cell Contention | 5 |
| MAC (6P) | 6P Cell Allocation Exhaustion | 6 |
| MAC (TSCH) | TSCH Desynchronization | 7 |
| n/a | benign (NONE) | 0 |

**206 Cooja runs, ~2.08 M labelled records** (Contiki-NG + custom `4emac` MAC,
emulated `exp5438` motes):

| Chain | Runs | Records | Design |
|---|---|---|---|
| `single/` | 86 | ~881 k | 7 attacks × 2 scales (21/31 motes) × 3 placements (core/mid/edge) × 2 densities (1/5 attackers) = 84, + 2 benign baselines |
| `multiattack/` | 36 | ~348 k | 6 two-attacker combinations × 3 attacker-selection seeds × 2 scales |
| `multiseed/` | 84 | ~854 k | the 42 five-attacker placement cells repeated under two further Cooja radio seeds (7331, 9173); with the published seed 123456 this gives 3 replicas per cell |

The `single/` and `multiattack/` chains are the benchmark corpus reported in the
paper (122 runs, ~1.23 M records, of which ~1.21 M come from the attacked runs). The `multiseed/` chain is the replication
corpus behind the confidence intervals and the seed-variability analysis: it
shares the firmware, topology, attacker-selection rule and analysis protocol with
`single/`, so the only source of variation is the radio realisation. The
`radio_seed` column of `manifest.csv` identifies the seed of every run.

Every run ships **three files with a shared stem**: raw telemetry `.log`, radio
capture `.pcap`, and a clean header-prefixed `.csv`. This holds for all three
chains, so the replication corpus can be re-analysed at the radio level as well.

Two cells of the replication corpus behave differently from the rest and are kept
deliberately: `flooding-n21-core-a5-s9173` starts its attack at 2438 s instead of
about 1350 s, and `blackhole-n31-edge-a5-s7331` produces only 11 attacker records
because the parent-lost watchdog reboots the attacker motes. Both are documented
in the paper as evidence of seed-dependent firmware behaviour.

## 2. Record schema

20 integer columns per telemetry record (3 identifiers, 15 features, 2 labels);
the ML pipeline adds two derived features. Full definitions in
[`schema.md`](schema.md). Identifiers (`node_id`, `parent_id`, `timestamp`) are
**excluded** from the ML feature set to prevent per-node identity leakage.

## 3. Repository layout

```
.
├── README.md            this file
├── REPRODUCING.md       commands to regenerate every table/figure
├── schema.md            20-column + derived-feature schema
├── manifest.csv         index of all 206 runs (incl. `radio_seed` column)
├── ETHICS.md            responsible-use statement
├── LICENSE              code license (MIT)
├── DATA-LICENSE.md      data license (CC-BY-4.0)
├── attacks/             attack-client firmware sources (one dir per attack)
│   ├── <attack>-attack-client/  six attack implementations (.c/.h/Makefile);
│   │                     the seventh is flooding-client/
│   ├── client/           regular node firmware; server/  sink/border-router
│   └── attacker-analyzer/ telemetry module that emits the labelled records
├── csc/                 Cooja scenario files (rpl-border-<attack>-v3.csc, -v3-30.csc)
├── code/
│   ├── capture/         Cooja-headless run generation harness
│   ├── analysis/        group-aware ML / detection benchmark
│   └── figures/         figure generators
├── results/             result tables of the paper as CSV (sweeps, tests, delays)
└── data/
    ├── single/{logs,pcaps,csv}/       all 86 single-attacker runs
    ├── multiattack/{logs,pcaps,csv}/  all 36 concurrent two-attacker runs
    └── multiseed/{logs,pcaps,csv}/    84 three-seed replication runs
```

Each run's `.log`, `.pcap`, and `.csv` share the same stem (see [`schema.md`](schema.md)).

## 4. Evaluation protocol (important)

Detection is benchmarked **group-aware**: cross-validation folds are split on the
group key `(run_id, node_id)` (LeaveOneGroupOut for per-record per-attack tasks,
StratifiedGroupKFold for the windowed 17-model comparison and the multi-class task).
This prevents the same node from appearing in both train and test, which is the
per-node **identity leakage** that inflates naive row-level cross-validation by up to
+0.89 F1. **Please report group-aware scores** when using this dataset.

## 5. Quick start

```bash
python3 -m pip install numpy pandas "scikit-learn>=1.3" scipy matplotlib xgboost lightgbm torch
# the scripts read paths under dataset_v3/; expose the in-repo data with one symlink:
ln -s data dataset_v3
python3 code/analysis/gen_model_compare_full.py   # 17-model windowed benchmark
```
The full ML/figure pipeline runs from the repository alone (the pcaps are used only for
radio-level analysis, not for the detection benchmark).

See [`REPRODUCING.md`](REPRODUCING.md) for the full table/figure reproduction list and
for regenerating the dataset from firmware with the capture harness.

## 6. Data availability

The complete dataset for all 206 runs, labelled telemetry (`.log`), radio captures
(`.pcap`), and clean `.csv` (~2.3 GB total), is in this repository under `data/`. No
external download is required: clone the repository and the full pipeline runs.

## 7. Citation

If you use this dataset, the evaluation protocol or the analysis code, please cite
the companion paper. If you use the dataset itself, please also cite the archived
deposit, so that the exact snapshot you worked with is identifiable.

```bibtex
@ARTICLE{11703443,
  author={Aydin, Burak and Aydin, Hakan and Jin, Yichao and Gormus, Sedat},
  journal={IEEE Access}, 
  title={6TiSCHSet-2026: A Multi-Layer Attack Dataset and Leakage-Aware Intrusion-Detection Benchmark for IETF 6TiSCH Networks}, 
  year={2026},
  volume={14},
  number={},
  pages={147867-147900},
  doi={10.1109/ACCESS.2026.3736663}}
```

```bibtex
@misc{sixtischset2026dataset,
  author       = {Aydin, Burak and Aydin, Hakan and Jin, Yichao and Gormus, Sedat},
  title        = {{6TiSCHSet-2026}: A Multi-Layer {6TiSCH} Attack Dataset and
                  Leakage-Aware {IDS} Benchmark},
  year         = {2026},
  publisher    = {Zenodo},
  doi          = {10.5281/zenodo.22113021},
  note         = {[Online]. Available: \url{https://doi.org/10.5281/zenodo.22113021}}
}
```

The DOI above is the *concept* DOI and always resolves to the latest version. Use the
version DOI of a specific release if you need to pin the exact snapshot. This README
will be updated with the article DOI once the paper is published.

## 8. License

Code: **MIT** ([`LICENSE`](LICENSE)). Data: **CC-BY-4.0**
([`DATA-LICENSE.md`](DATA-LICENSE.md)). See [`ETHICS.md`](ETHICS.md) for responsible-use
terms: the repository includes working attack firmware and is released **for defensive
intrusion-detection research only**.
