# A Multi-Layer 6TiSCH Attack Dataset and Leakage-Aware IDS Benchmark

Companion artefact for the paper **"A Multi-Layer 6TiSCH Attack Dataset and
Leakage-Aware Intrusion-Detection Benchmark"** (Aydın, Aydın, Jin, Görmüş, 2026).

This repository contains the **code** (capture/generation harness, ML and figure
pipeline), the **firmware sources and Cooja scenarios**, the **documentation**
(schema, run manifest), and the **labelled telemetry (`.log`) and clean `.csv` for all
122 runs**. The per-run **radio captures** (`.pcap`, ~2.1 GB) are archived on Zenodo —
see [Data availability](#data-availability).

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
| — | benign (NONE) | 0 |

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
    ├── single/{logs,csv}/       all 86 single-attacker runs (.log + clean .csv)
    ├── multiattack/{logs,csv}/  all 36 concurrent two-attacker runs
    └── pcaps/                   sample/ pcaps + README.md (full ~2.1 GB set on Zenodo)
```

The full `single/` and `multiattack/` chains (logs, pcaps, csv) live on Zenodo;
`data/sample/` shows the exact file format so the pipeline can be tried without the
full download.

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
The full ML/figure pipeline runs from the repository alone (the pcaps are not needed
for detection; download them from Zenodo only for radio-level analysis).

See [`REPRODUCING.md`](REPRODUCING.md) for the full table/figure reproduction list and
for regenerating the dataset from firmware with the capture harness.

## 6. Data availability

The labelled telemetry (`.log`) and clean `.csv` for all 122 runs are in this
repository under `data/`. The per-run **radio captures** (`.pcap`, ~2.1 GB) are too
large for GitHub and are archived at:

> **Zenodo DOI:** `10.5281/zenodo.XXXXXXX` *(to be assigned on publication)*

The Zenodo archive (telemetry + pcaps + csv) is the citable, versioned dataset of
record; this repository mirrors everything except the pcaps.

## 7. Citation

```bibtex
@article{aydin2026sixtisch,
  title   = {A Multi-Layer 6TiSCH Attack Dataset and Leakage-Aware
             Intrusion-Detection Benchmark},
  author  = {Ayd{\i}n, Burak and Ayd{\i}n, Hakan and Jin, Yichao and G{\"o}rm{\"u}s, Sedat},
  journal = {(under review)},
  year    = {2026}
}
```

## 8. License

Code: **MIT** ([`LICENSE`](LICENSE)). Data: **CC-BY-4.0**
([`DATA-LICENSE.md`](DATA-LICENSE.md)). See [`ETHICS.md`](ETHICS.md) for responsible-use
terms — the repository includes working attack firmware and is released **for defensive
intrusion-detection research only**.
