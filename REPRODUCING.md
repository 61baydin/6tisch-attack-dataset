# Reproducing the paper

This guide reproduces every numbered table and figure in **"A Multi-Layer Attack Dataset for Intrusion Detection in IETF 6TiSCH Networks"** from a fresh clone of this repository.

The dataset is already shipped under `dataset/`, so reproduction does **not** require running Cooja. Section 4 below explains how to regenerate the dataset itself if needed.

---

## 0. Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install numpy pandas scikit-learn xgboost lightgbm matplotlib
cd analysis/
```

All scripts below are run from inside `analysis/` and expect the `.log` files to be visible in the current directory. The fastest way is to symlink them in once:

```bash
ln -s ../dataset/21mote_a5/*.log .
ln -s ../dataset/21mote_a1/*.log .
ln -s ../dataset/31mote_a5/*.log .
ln -s ../dataset/31mote_a1/*.log .
```

Output figures land in `../figures/` (created automatically).

---

## 1. Detection F1 (Tables IX, X) and multi-class confusion (Figure 10)

```bash
python3 eval_placement_a5.py 21    # 21-mote · ~5 min
python3 eval_placement_a5.py 31    # 31-mote · ~10 min
```

Outputs:
- `binary_eval_a5.csv` / `binary_eval_a5_31mote.csv` — per-(attack, classifier) Group F1 + Naive F1 (Tab IX, X)
- `../figures/confusion_matrix_xgboost.{pdf,png}` (Fig. 10, 21-mote)
- `../figures/confusion_matrix_xgboost_31mote.{pdf,png}` (Fig. 11, 31-mote)
- Console log includes multi-class classification report and RF feature importance (used in §VII)

---

## 2. Per-source PDR (Tables VII, VIII; Figures 8, 9)

```bash
python3 damage_analysis_placement.py
python3 gen_result_figures.py        # vic_pdr_bars (21-mote)
python3 gen_result_figures_31mote.py # vic_pdr_bars (31-mote)
```

Outputs:
- `../figures/vic_pdr_bars.{pdf,png}` (Fig. 8, Tab VII)
- `../figures/vic_pdr_bars_31mote.{pdf,png}` (Fig. 9, Tab VIII)
- `../figures/feature_signature.{pdf,png}` (Fig. for §VI.B, 21-mote)
- `../figures/feature_signature_31mote.{pdf,png}` (31-mote)

---

## 3. Placement-sensitivity heatmap (Table XII, Figure 12)

```bash
python3 eval_placement.py 21    # writes a1+a5 placement breakdown
python3 eval_placement.py 31
python3 gen_figures_placement.py
```

Outputs:
- `placement_*_results.csv` — per-(attack, placement) F1 for RF and LR
- `../figures/placement_heatmap.{pdf,png}` (Fig. 12)

---

## 4. Methodology ablation (Table XV)

The ablation is computed from the outputs of steps 1 and 3 (no separate script). Compare:
- `placement_*_results.csv` row mean for a5 → Tab placement_summary RF column
- `placement_*_a1_results.csv` row mean → a1 row of Tab ablation

The Δ column is the per-placement difference; the +0.65 figure at the edge is the headline number from §VI.G.

---

## 5. Background figures (Figures 1, 2, 3)

These do not depend on the dataset:

```bash
python3 gen_background_figures.py
```

Outputs:
- `../figures/stack_6tisch.{pdf,png}` (Fig. 1, protocol stack)
- `../figures/tsch_slotframe.{pdf,png}` (Fig. 2, TSCH slotframe example)
- `../figures/sixp_handshake.{pdf,png}` (Fig. 3, 6P ADD handshake)

Per-attack tree diagrams (Figures 4–7 of §IV) are produced by:

```bash
python3 gen_attack_diagrams.py
```

---

## 6. Feature importance (§VII Discussion)

```bash
python3 feature_importance_chain.py 21
python3 feature_importance_chain.py 31
```

Console output prints the per-feature RF Gini importance averaged across 5 StratifiedGroupKFold folds, used in the Discussion paragraph on §VII.

---

## 7. Regenerating the dataset from scratch (optional)

Only required if you want to verify the entire data-generation pipeline; the 84 pre-collected `.log` files under `dataset/` already match the paper.

### 7.1 Build the Contiki-NG fork
```bash
# clone the fork
git clone https://github.com/61baydin/6tisch-attack-dataset.git
cd 6tisch-attack-dataset
# build attack-client firmware for the emulated exp5438 mote
for atk in blackhole-attack-client decrease-rank-attack-client \
           dis-attack-client flooding-client shared-slot-attack-client \
           slot-exhaustion-attack-client timekeep-attack-client; do
  make -C examples/tsch/rpl-udp/$atk TARGET=cooja clean
  make -C examples/tsch/rpl-udp/$atk TARGET=cooja
done
```

### 7.2 Run Cooja headless
For each `.csc` file in `csc/21mote/` (and `csc/31mote/` for the scaled topology), do:

```bash
# Terminal 1: bridge tun0 to the border router (requires sudo)
sudo ./tools/tunslip6 -a 127.0.0.1 -p 60001 fd00::5/64

# Terminal 2: telemetry capture
python3 capture/udp_listener_ipv6.py     # writes YYYY-MM-DD_HH-MM-SS.log

# Terminal 3: Cooja
java -mx2048m -jar tools/cooja/dist/cooja.jar \
     -nogui=$PATH_TO_CSC \
     -contiki=$PATH_TO_CONTIKI_NG
```

Each scenario runs for 30 simulated minutes (`TIMEOUT(1800000)` in the embedded `ScriptRunner`). The Cooja random seed is fixed at `123456` inside every `.csc` — do not change it; the placement-stratified design relies on bit-exact reproducibility.

### 7.3 Mass-run orchestration
The paper's 84 runs were generated through a multi-run wrapper that loops over `(scenario, placement, density, run_idx)` and renames each capture log to the convention described in `README.md` §1. The naming convention is required for `eval_placement_a5.py` and the rest of the analysis pipeline to discover the right files.

---

## 8. Cross-check against paper numbers

After step 1, the following values from `binary_eval_a5.csv` should match the paper (Tab IX / X) within rounding:

| Attack | RF group | RF naive | LR group | XGB group | LGBM group |
|---|---|---|---|---|---|
| Blackhole | 0.21 | 0.49 | 0.61 | 0.02 | 0.08 |
| Decreased Rank | 0.34 | 0.90 | 0.78 | 0.79 | 0.73 |
| DIS Flooding | 0.77 | 0.98 | 0.98 | 0.96 | 0.97 |
| Application Flooding | 0.50 | 0.97 | 0.74 | 0.92 | 0.97 |
| TSCH Shared Cell | 0.53 | 0.99 | 0.99 | 0.89 | 0.96 |
| 6P Cell Exhaustion | 0.69 | 1.00 | 0.95 | 0.84 | 0.77 |
| TSCH Desynchronization | 0.46 | 0.98 | 0.97 | 0.97 | 0.89 |

If a value differs by more than ±0.01, check that:
- All four `dataset/{21mote,31mote}_{a1,a5}/*.log` directories are symlinked into `analysis/`
- The `random_state=42` and `n_splits=5` defaults in `eval_placement_a5.py` are unchanged
- No additional `.log` files (from earlier captures) are present in `analysis/`

---

## 9. Hardware notes

The paper's runs were generated on an Intel-class server (~45 min per Cooja-headless 30-min simulated run). All Python analysis steps complete in under 15 min on a 4-core consumer laptop with 16 GB RAM. The full reproduction (analysis only, dataset already shipped) is comfortably under one hour.
