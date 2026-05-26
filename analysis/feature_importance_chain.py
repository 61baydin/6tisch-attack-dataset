#!/usr/bin/env python3
"""Compute Random Forest feature importances over the 2026-05-08 chain
logs (multi-class attack_type task) and write a top-N table for the
paper.

Output:
  feature_importance_chain.csv — importance per feature, sorted desc.

Usage:
  python3 feature_importance_chain.py
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path
from statistics import mean

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

REPO_ROOT = Path(__file__).resolve().parent
LINE_RE = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")

FEATURES = [
    "rank", "buf_occupancy", "dio_sent", "dao_sent", "dis_sent",
    "nbr_count", "tx_slot_count", "parent_switch_count", "rssi",
    "route_count", "delta_tx", "delta_rx", "app_packet_count",
]


def parse_log(path: str):
    rows = []
    with open(path) as f:
        for line in f:
            m = LINE_RE.search(line)
            if not m:
                continue
            parts = [p.strip() for p in m.group(1).split(",")]
            if len(parts) < 18:
                continue
            try:
                ints = [int(x) for x in parts[:18]]
            except ValueError:
                continue
            rows.append({
                "timestamp": ints[0], "node_id": ints[1], "parent_id": ints[2],
                "rank": ints[3], "buf_occupancy": ints[4], "dio_sent": ints[5],
                "dao_sent": ints[6], "dis_sent": ints[7], "nbr_count": ints[8],
                "tx_slot_count": ints[9], "parent_switch_count": ints[10],
                "rssi": ints[11], "route_count": ints[12], "delta_tx": ints[13],
                "delta_rx": ints[14], "app_packet_count": ints[15],
                "is_attacker": ints[16], "attack_type": ints[17],
            })
    return rows


def main() -> int:
    # Pick chain logs only.
    pat = re.compile(r"^2026-05-08_\d{2}-\d{2}-\d{2}_(.+)-v2-multirun-(\d+)\.log$")
    logs = [p for p in REPO_ROOT.iterdir()
            if pat.match(p.name) and p.name >= "2026-05-08_01-51"]

    print(f"[fi] reading {len(logs)} chain logs")
    all_rows = []
    for log in sorted(logs):
        rs = parse_log(str(log))
        for r in rs:
            r["log"] = log.name
        all_rows.extend(rs)
    print(f"[fi] total records: {len(all_rows)}")

    df = pd.DataFrame(all_rows)
    X = df[FEATURES].values.astype(np.float64)
    y = df["attack_type"].values.astype(int)

    print(f"[fi] features: {FEATURES}")
    print(f"[fi] class distribution: {dict(zip(*np.unique(y, return_counts=True)))}")

    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)

    rf = RandomForestClassifier(
        n_estimators=200, random_state=42,
        class_weight="balanced", n_jobs=-1, max_depth=None,
    )
    rf.fit(Xs, y)

    importances = list(zip(FEATURES, rf.feature_importances_))
    importances.sort(key=lambda kv: kv[1], reverse=True)

    print()
    print(f"{'Rank':>4}  {'Feature':<22}  {'Importance':>10}")
    print("-" * 42)
    for i, (feat, imp) in enumerate(importances, 1):
        print(f"{i:>4}  {feat:<22}  {imp:>10.4f}")

    out = REPO_ROOT / "feature_importance_chain.csv"
    pd.DataFrame(importances, columns=["feature", "importance"]).to_csv(out, index=False)
    print(f"\n[fi] wrote {out.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
