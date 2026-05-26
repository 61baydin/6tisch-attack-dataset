# 6TiSCH Multi-Layer Attack Dataset

Companion artefact for the paper **"A Multi-Layer Attack Dataset for Intrusion Detection in IETF 6TiSCH Networks"** (Aydın, Aydın, Görmüş, 2026).

This repository contains the labelled telemetry dataset, the Cooja simulation scenarios, and the analysis pipeline required to reproduce every table and figure in the paper.

---

## 1. Dataset overview

The dataset covers **seven attack families** spanning **five protocol planes** of the IETF 6TiSCH stack:

| Plane | Attack | `attack_type` ID |
|---|---|---|
| Data | Blackhole | 1 |
| Routing | Decreased Rank | 2 |
| Control | DIS Flooding | 3 |
| Application | Application Flooding | 4 |
| MAC | TSCH Shared Cell Contention | 5 |
| MAC | 6P Cell Allocation Exhaustion | 6 |
| MAC | TSCH Desynchronization | 7 |
| (benign) | NONE | 0 |

Two topology scales share the same **placement-stratified design**: 7 attacks × 3 placements (core/mid/edge) × 2 attacker densities (1, 5) = **42 runs per scale**.

| Folder | Scale | Density | #runs | Records |
|---|---|---|---|---|
| `dataset/21mote_a5/` | 21-mote | 5 attackers | 21 | ~131k |
| `dataset/21mote_a1/` | 21-mote | 1 attacker | 21 | ~30k |
| `dataset/31mote_a5/` | 31-mote | 5 attackers | 21 | ~166k |
| `dataset/31mote_a1/` | 31-mote | 1 attacker | 21 | ~58k |
| **Total** | | | **84** | **~385k** |

File-name convention: `YYYY-MM-DD_HH-MM-SS_{attack}-{scale}-{placement}[-a1]-multirun-{idx}.log`
where `scale ∈ {v2, v3-30}` (21- and 31-mote) and `placement ∈ {core, mid, edge}`.

---

## 2. Telemetry schema

Each `.log` file contains text lines emitted by `udp_listener_ipv6.py`. The payload is an 18-column CSV record per line, embedded inside a Python `b'...'` byte-string prefix. Columns 1–16 are features; columns 17–18 are ground-truth labels.

| # | Column | Type | Source | Description |
|---|---|---|---|---|
| 1 | `timestamp` | int (s) | analyzer | seconds since simulation start |
| 2 | `node_id` | int | analyzer | mote ID |
| 3 | `parent_id` | int | RPL | current preferred parent ID |
| 4 | `rank` | int | RPL | RPL rank |
| 5 | `buf_occupancy` | int | MAC | packets queued in MAC buffer |
| 6 | `dio_sent` | int | RPL | cumulative DIO sent |
| 7 | `dao_sent` | int | RPL | cumulative DAO sent |
| 8 | `dis_sent` | int | RPL | cumulative DIS sent |
| 9 | `nbr_count` | int | RPL | neighbour-table size |
| 10 | `tx_slot_count` | int | TSCH | cumulative TX slots taken |
| 11 | `parent_switch_count` | int | RPL | cumulative parent changes |
| 12 | `rssi` | int (dBm) | PHY | last received packet RSSI |
| 13 | `route_count` | int | RPL | active downstream routes |
| 14 | `delta_tx` | int (ticks) | Energest | TX energy delta since last record |
| 15 | `delta_rx` | int (ticks) | Energest | RX energy delta since last record |
| 16 | `app_packet_count` | int | app | cumulative application packets sent |
| 17 | `is_attacker` | {0,1} | oracle | 1 iff the row is from an active attacker |
| 18 | `attack_type` | {0..7} | oracle | 0 if benign; 1..7 for the seven attack families |

`node_id` and `parent_id` are kept for traceability and group-key construction but **must be excluded from the ML feature set** to avoid per-node identity leakage. `timestamp` is also excluded from features because it grows monotonically within each run.

Canonical parsing regex: `r"b'\s*([0-9,\-\s]+)\s*'"`; rows with fewer than 18 comma-separated integers should be discarded.

---

## 3. Experiment timeline

Every run is **30 min long**, identical across the 84 files:

| Window | Duration | Telemetry | Attack |
|---|---|---|---|
| Warm-up | 0–3 min | suppressed | none (DODAG join, TSCH/RPL convergence) |
| Benign | 3–5 min | on, `is_attacker=0` | attacker behaves as a benign mote |
| Attack | 5–30 min | on, `is_attacker=1` | attack-mode loop active |

Telemetry emission is suppressed during warm-up so that early DODAG-convergence transients are not labelled as the steady-state "normal" distribution.

---

## 4. Methodology

### 4.1 Placement-stratified design
Each run draws its attackers exclusively from one of three distance-to-sink tertiles (**core / mid / edge**). At 21 motes: core = {2,3,4,5,7,8}, mid = {6,9,10,11,12,21}, edge = {13..20}. At 31 motes an analogous core/mid/edge partition is applied to the 6×5 grid.

### 4.2 Per-source PDR (damage taxonomy)
The sink instruments per-source receive counters, embedding the originating mote ID in the upper 8 bits of each 32-bit UDP payload. For each run the non-sink motes are partitioned into three disjoint pools:
- **Attacker** (𝒜): motes with at least one `is_attacker=1` row.
- **Victim** (𝒱): non-sink, non-attacker motes whose `parent_id` equals some attacker's `node_id` at any time within the attack window.
- **Bystander** (ℬ): all other non-sink motes.

The per-pool PDR is the ratio of sink-received to mote-sent application packets aggregated over each pool, evaluated **on the attack window only** (5–30 min).

### 4.3 Group-aware ML evaluation
- **Group key:** `(run_id, node_id)` — every (run, node) pair forms one group; cross-validation never lets the same group appear in both train and test.
- **Binary per-attack:** LeaveOneGroupOut (LOGO) over attacker-bearing groups on the 5-attacker placement cells. Mean F1 across folds.
- **Multi-class (8 classes):** StratifiedGroupKFold(k=5) on the pooled 5-attacker placement cells (~105 attacker-bearing groups make exhaustive LOGO prohibitive).
- **Reference classifiers:** Random Forest (100 trees, max_depth=10, class_weight="balanced"), Logistic Regression (max_iter=1000, class_weight="balanced", L2 with C=1.0), XGBoost (100 / 300 estimators, max_depth=6, lr=0.1), LightGBM (100 estimators, lr=0.1, class_weight="balanced"). `random_state=42` everywhere. No per-attack hyperparameter tuning.

### 4.4 Excluded features
`node_id`, `parent_id`, and `timestamp` are removed from the feature set before training. `node_id` and `parent_id` would leak per-node identity into the test fold; `timestamp` grows monotonically within each run and would let a row-level split trivially separate the benign window (3–5 min) from the attack window (5–30 min) by a single threshold.

---

## 5. Repository layout

```
for_github/
├── README.md                # this file
├── REPRODUCING.md           # step-by-step reproduction guide
├── dataset/
│   ├── 21mote_a5/           # 21 logs · 21-mote · 5-attacker
│   ├── 21mote_a1/           # 21 logs · 21-mote · 1-attacker
│   ├── 31mote_a5/           # 21 logs · 31-mote · 5-attacker
│   └── 31mote_a1/           # 21 logs · 31-mote · 1-attacker
├── csc/
│   ├── 21mote/              # 7 v2 Cooja scenarios
│   └── 31mote/              # 7 v3-30 Cooja scenarios
├── analysis/
│   ├── eval_placement_a5.py           # main ML benchmark (Tab IX, X)
│   ├── eval_placement.py              # full placement-stratified eval (a1 + a5)
│   ├── damage_analysis_placement.py   # per-source PDR (Tab VII, VIII)
│   ├── damage_analysis.py             # damage-pool analyser
│   ├── attack_detection_row_based_ml.py  # row-based ML pipeline
│   ├── gen_confusion_matrix.py            # Fig. multi-class CM (21-mote)
│   ├── gen_confusion_matrix_31mote.py     # Fig. multi-class CM (31-mote)
│   ├── gen_result_figures.py              # vic_pdr_bars, feature_signature (21)
│   ├── gen_result_figures_31mote.py       # vic_pdr_bars, feature_signature (31)
│   ├── gen_figures_placement.py           # placement heatmap
│   ├── gen_background_figures.py          # stack_6tisch, tsch_slotframe, sixp_handshake
│   ├── gen_attack_diagrams.py             # per-attack tree diagrams
│   └── feature_importance_chain.py        # RF Gini importance
├── capture/
│   ├── udp_listener_ipv6.py    # UDP receiver that produces .log files
│   └── fix_tunslip.sh          # tun0 cleanup helper
└── figures/                  # output directory for generated figures
```

---

## 6. Software dependencies

- Python 3.10+
- numpy, pandas, scikit-learn 1.3+
- xgboost 3.2+, lightgbm 4.6+
- matplotlib (headless backend Agg is used by default)
- For new captures only: Contiki-NG fork at <https://github.com/61baydin/6tisch-attack-dataset> (4emac MAC, attack-analyzer, 7 attack-client examples), Java 11 + Apache Ant (Cooja).

Install Python deps in a venv:
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install numpy pandas scikit-learn xgboost lightgbm matplotlib
```

---

## 7. Quick start

Reproduce the paper's main F1 table (Tab IX / X) on the 21-mote dataset:
```bash
cd analysis/
ln -s ../dataset/21mote_a5/*.log .
python3 eval_placement_a5.py 21
```

Reproduce the same on the 31-mote dataset:
```bash
ln -s ../dataset/31mote_a5/*.log .
python3 eval_placement_a5.py 31
```

See [REPRODUCING.md](REPRODUCING.md) for the full table/figure reproduction recipe.

---

## 8. Citation

```bibtex
@article{aydin2026sixtisch,
  title  = {A Multi-Layer Attack Dataset for Intrusion Detection in IETF 6TiSCH Networks},
  author = {Ayd{\i}n, Burak and Ayd{\i}n, Hakan and G{\"o}rm{\"u}{\c s}, Sedat},
  year   = {2026},
  note   = {Preprint; final venue to be announced.}
}
```

## 9. License
Dataset and analysis code released for academic research use. The Contiki-NG fork follows the upstream Contiki-NG BSD 3-Clause licence.
