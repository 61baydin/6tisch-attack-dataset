# 6TiSCHSet-2026: A Multi-Layer 6TiSCH Attack Dataset and Leakage-Aware IDS Benchmark

Companion artefact for the paper **"6TiSCHSet-2026: A Multi-Layer Attack Dataset and
Leakage-Aware Intrusion-Detection Benchmark for IETF 6TiSCH Networks"** (Aydin, Aydin, Jin, Gormus, 2026).

This repository is **self-contained**: it carries the **code** (capture/generation
harness, ML and figure pipeline), the **firmware sources and Cooja scenarios**, the
**documentation** (schema, run manifest), and the **full dataset for all 122 runs**:
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

**122 Cooja runs, ~1.21 M labelled records** (Contiki-NG + custom `4emac` MAC,
emulated `exp5438` motes):

| Chain | Runs | Records | Design |
|---|---|---|---|
| `single/` | 86 | ~865 k | 7 attacks × 2 scales (21/31 motes) × 3 placements (core/mid/edge) × 2 densities (1/5 attackers) = 84, + 2 benign baselines |
| `multiattack/` | 36 | ~348 k | 6 two-attacker combinations × 3 attacker-selection seeds × 2 scales |

Every run ships **three files with a shared stem**: raw telemetry `.log`, radio
capture `.pcap`, and a clean header-prefixed `.csv`.

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
├── manifest.csv         index of all 122 runs
├── ETHICS.md            responsible-use statement
├── LICENSE              code license (MIT)
├── DATA-LICENSE.md      data license (CC-BY-4.0)
├── attacks/             attack-client firmware sources (one dir per attack)
│   ├── *-attack-client/  the seven attack implementations (.c/.h/Makefile)
│   ├── client/           regular node firmware; server/  sink/border-router
│   └── attacker-analyzer/ telemetry module that emits the labelled records
├── csc/                 Cooja scenario files (rpl-border-<attack>-v2.csc)
├── code/
│   ├── capture/         Cooja-headless run generation harness
│   ├── analysis/        group-aware ML / detection benchmark
│   └── figures/         figure generators
└── data/
    ├── single/{logs,pcaps,csv}/       all 86 single-attacker runs
    └── multiattack/{logs,pcaps,csv}/  all 36 concurrent two-attacker runs
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

The complete dataset for all 122 runs, labelled telemetry (`.log`), radio captures
(`.pcap`), and clean `.csv` (~2.3 GB total), is in this repository under `data/`. No
external download is required: clone the repository and the full pipeline runs.

## 7. Citation

```bibtex
@article{aydin2026sixtischset,
  title   = {{6TiSCHSet-2026}: A Multi-Layer Attack Dataset and Leakage-Aware
             Intrusion-Detection Benchmark for IETF 6TiSCH Networks},
  author  = {Aydin, Burak and Aydin, Hakan and Jin, Yichao and Gormus, Sedat},
  journal = {IEEE Access (submitted)},
  year    = {2026}
}
```

## 8. License

Code: **MIT** ([`LICENSE`](LICENSE)). Data: **CC-BY-4.0**
([`DATA-LICENSE.md`](DATA-LICENSE.md)). See [`ETHICS.md`](ETHICS.md) for responsible-use
terms: the repository includes working attack firmware and is released **for defensive
intrusion-detection research only**.
