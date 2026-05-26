#!/usr/bin/env python3
"""
damage_analysis.py — Phase 1 (post-hoc) damage metrics from existing v2 multirun logs.

For each attack family (blackhole, decrease, dis, flooding, shared-slot,
slot-exhaustion, timekeep), parses the 3 multirun .log files and reports
per-attacker vs per-normal-node damage indicators:

  - app_pkts_sent       : final app_packet_count per node (sender-side)
  - tx_bytes_total      : sum(delta_tx)  during attack window
  - rx_bytes_total      : sum(delta_rx)  during attack window
  - fwd_ratio           : tx_bytes_total / rx_bytes_total
                          (< 1.0 -> node received more than it forwarded;
                           classic blackhole symptom)
  - ctrl_overhead       : last(dio_sent + dao_sent + dis_sent)
  - parent_switches     : last(parent_switch_count)
  - mean_buf_occ        : mean(buf_occupancy) during attack window
  - mean_rank           : mean(rank) during attack window
  - mean_rssi           : mean(rssi)
  - route_count_final   : last(route_count)

Network-level damage indicators per run:
  - sink_rx_total        : sum(delta_rx) of node 1 during attack window
                           (proxy for total data delivered to root)
  - net_app_throughput   : sum_over_non_sink(app_pkts_sent / attack_window_dur)

Latency is NOT computed here — true end-to-end latency requires a firmware
timestamp embedded in the app payload (Phase 2 work). The closest proxy
available from telemetry is parent_switches + mean_buf_occ (router queue
fill); both are reported.

CSV record format (1-indexed columns):
  1 timestamp_s | 2 node_id | 3 parent_id | 4 rank | 5 buf_occupancy
  6 dio_sent | 7 dao_sent | 8 dis_sent | 9 nbr_count | 10 tx_slot_count
  11 parent_switch_count | 12 rssi | 13 route_count
  14 delta_tx | 15 delta_rx | 16 app_packet_count
  17 is_attacker | 18 attack_type
"""

import csv
import glob
import os
import re
from collections import defaultdict
from pathlib import Path
from statistics import mean, stdev

REPO_ROOT = Path(__file__).resolve().parent
SINK_NODE_ID = 1
RUN_DURATION_S = 1800  # 30-min runs
APP_INTERVAL_S = 15    # NORMAL_SEND_INTERVAL in attack-client firmware

# Only consume logs from this timestamp onward. Plan-A blackhole hook +
# explicit-mote_id-encoded payloads landed 2026-05-08 ~01:50; older multirun
# logs predate either or both fixes and would pollute means. Override with
# MIN_LOG_DATE env var to widen. The comparison uses the first 16 chars of
# the filename (YYYY-MM-DD_HH-MM) so it is stable against timestamp lex order.
MIN_LOG_DATE = os.environ.get("MIN_LOG_DATE", "2026-05-08_01-51")

# Attack families => glob pattern fragment in filename. The "baseline"
# family has no attackers (all 20 non-sink motes run normal client firmware);
# its run has no is_attacker=1 rows, so aggregate_run uses a fallback start
# time (first telemetry tick).
ATTACK_PATTERNS = {
    "baseline":        "*_baseline-v2-multirun-*.log",
    "blackhole":       "*_blackhole-v2-multirun-*.log",
    "decrease-rank":   "*_decrease-v2-multirun-*.log",
    "dis":             "*_dis-v2-multirun-*.log",
    "flooding":        "*_flooding-v2-multirun-*.log",
    "shared-slot":     "*_shared-slot-v2-multirun-*.log",
    "slot-exhaustion": "*_slot-exhaustion-v2-multirun-*.log",
    "timekeep":        "*_timekeep-v2-multirun-*.log",
}

LINE_RE = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
# PDR_STATS line emitted by sink every ~30s, one per active source:
#   Received from ('fd00::200:0:0:1', 5678, 0, 0): b' PDR,<ts>,<src>,<count> '
PDR_RE = re.compile(r"b'\s*PDR,(\d+),(\d+),(\d+)\s*'")

def parse_log(path):
    """Return (telemetry_rows, pdr_records) tuple.

    pdr_records is a list of (ts, src_id, cum_rx_count) tuples.
    """
    rows = []
    pdr_records = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            mp = PDR_RE.search(line)
            if mp:
                pdr_records.append((int(mp.group(1)), int(mp.group(2)), int(mp.group(3))))
                continue
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
                "ts": ints[0],
                "node_id": ints[1],
                "parent_id": ints[2],
                "rank": ints[3],
                "buf_occ": ints[4],
                "dio": ints[5],
                "dao": ints[6],
                "dis": ints[7],
                "nbr": ints[8],
                "tx_slot": ints[9],
                "psw": ints[10],
                "rssi": ints[11],
                "route_count": ints[12],
                "delta_tx": ints[13],
                "delta_rx": ints[14],
                "app_pkts": ints[15],
                "is_attacker": ints[16],
                "attack_type": ints[17],
            })
    return rows, pdr_records

def split_by_node(rows):
    by_node = defaultdict(list)
    for r in rows:
        by_node[r["node_id"]].append(r)
    for n in by_node:
        by_node[n].sort(key=lambda r: r["ts"])
    return by_node

def attackers_in_run(by_node):
    return {n for n, rs in by_node.items() if any(r["is_attacker"] == 1 for r in rs)}

def attack_start_ts(by_node, fallback_min_ts=False):
    """Earliest timestamp at which any node reports is_attacker=1.

    For baseline runs (no attackers), pass fallback_min_ts=True to use the
    first telemetry tick as the window start instead of returning None.
    """
    starts = [r["ts"] for rs in by_node.values() for r in rs if r["is_attacker"] == 1]
    if starts:
        return min(starts)
    if fallback_min_ts:
        all_ts = [r["ts"] for rs in by_node.values() for r in rs]
        return min(all_ts) if all_ts else None
    return None

def per_node_metrics(rows, t_start, t_end):
    """Compute damage metrics over [t_start, t_end] for one node's rows."""
    sub = [r for r in rows if t_start <= r["ts"] <= t_end]
    if not sub:
        return None
    app_first = sub[0]["app_pkts"]
    app_last  = sub[-1]["app_pkts"]
    tx_total  = sum(r["delta_tx"] for r in sub)
    rx_total  = sum(r["delta_rx"] for r in sub)
    window_s  = max(1, sub[-1]["ts"] - sub[0]["ts"])
    app_pkts_sent = max(0, app_last - app_first)
    expected_pkts = window_s / APP_INTERVAL_S
    return {
        "n_rows": len(sub),
        "window_s": window_s,
        "app_pkts_sent": app_pkts_sent,
        "app_pkts_final": app_last,
        "app_pkts_per_min": (app_pkts_sent / window_s) * 60.0,
        "app_completion_pct": (100.0 * app_pkts_sent / expected_pkts) if expected_pkts > 0 else 0.0,
        "tx_bytes_total": tx_total,
        "rx_bytes_total": rx_total,
        "tx_bytes_per_s": tx_total / window_s,
        "rx_bytes_per_s": rx_total / window_s,
        "ctrl_overhead": sub[-1]["dio"] + sub[-1]["dao"] + sub[-1]["dis"]
                         - (sub[0]["dio"] + sub[0]["dao"] + sub[0]["dis"]),
        "parent_switches": max(0, sub[-1]["psw"] - sub[0]["psw"]),
        "mean_buf_occ": mean(r["buf_occ"] for r in sub),
        "mean_rank": mean(r["rank"] for r in sub),
        "mean_rssi": mean(r["rssi"] for r in sub if r["rssi"] != 0)
                       if any(r["rssi"] != 0 for r in sub) else 0.0,
        "route_count_final": sub[-1]["route_count"],
    }

def total_app_pkts(rs):
    """Sum app_pkts across rows accounting for mote-reboot resets.

    `app_pkts` is a static cumulative counter on the sender; it only resets
    when the mote reboots (4emac watchdog). When that happens the counter
    goes back to 0 then climbs again. To get the true total sent, we sum
    pre-reset peaks plus the final value.
    """
    rs = sorted(rs, key=lambda r: r["ts"])
    total = 0
    prev = 0
    for r in rs:
        v = r["app_pkts"]
        if v < prev:
            total += prev      # commit pre-reset peak
            prev = 0
        prev = v
    total += prev
    return total

def classify_motes(by_node, attackers, t_start, t_end):
    """Per-mote classification: attacker / victim (child of attacker during
    attack window) / bystander / sink."""
    cls = {}
    for n, rs in by_node.items():
        if n == SINK_NODE_ID:
            cls[n] = "sink"
            continue
        if n in attackers:
            cls[n] = "attacker"
            continue
        in_window = [r for r in rs if t_start <= r["ts"] <= t_end]
        parents = {r["parent_id"] for r in in_window}
        cls[n] = "victim" if any(p in attackers for p in parents) else "bystander"
    return cls

def aggregate_run(path, is_baseline=False):
    """Return dict of per-run aggregated damage metrics.

    For baseline runs (is_baseline=True), there are no is_attacker=1 rows;
    the window starts at the first telemetry tick and the attacker pool is
    empty. All non-sink motes are in the "normal" pool.
    """
    rows, pdr_records = parse_log(path)
    by_node = split_by_node(rows)
    attackers = attackers_in_run(by_node)
    t_start = attack_start_ts(by_node, fallback_min_ts=is_baseline)
    if t_start is None:
        return None
    t_end = max(r["ts"] for r in rows)
    classes = classify_motes(by_node, attackers, t_start, t_end)

    # Per-source sink rx counts: for each src, the maximum (= last seen)
    # cumulative count from PDR_STATS records.
    sink_rx_per_src = {}
    for ts, src, n in pdr_records:
        if src not in sink_rx_per_src or n > sink_rx_per_src[src]:
            sink_rx_per_src[src] = n

    # Per-source PDR. For each non-sink mote, total_app_pkts handles reboot
    # resets; sink_rx_per_src[src] is monotonic (sink doesn't reboot).
    # If the run has no PDR_STATS records (pre-instrumentation log), all
    # per-source PDR is undefined (NaN), not zero — sink simply wasn't
    # counting back then.
    per_src_pdr = {}
    sender_total_per_src = {}
    have_pdr_data = len(pdr_records) > 0
    for n, rs in by_node.items():
        if n == SINK_NODE_ID:
            continue
        sender_total = total_app_pkts(rs)
        sender_total_per_src[n] = sender_total
        if not have_pdr_data:
            per_src_pdr[n] = float("nan")
            continue
        sink_rx = sink_rx_per_src.get(n, 0)
        if sender_total > 0:
            per_src_pdr[n] = 100.0 * sink_rx / sender_total
        else:
            per_src_pdr[n] = float("nan")

    attacker_metrics = []
    normal_metrics = []
    sink_rx_bytes_total = 0
    # Network-PDR uses RUN-FINAL cumulative counts (col 16 of last telemetry
    # row) on both sink and senders, NOT attack-window deltas. Reason:
    # different nodes' first-window-rows fall at different ts, creating a
    # 1-2% sink-vs-sender skew when window-deltas are compared (sink saw
    # packets in 302-315s window that a client whose first-row is at 315s
    # excludes from its delta). Cumulative values share the same start (run
    # boot) and end (run end) for everyone, so the ratio is honest.
    sink_app_rx_run_final = 0
    sender_app_run_final = 0
    for node, rs in by_node.items():
        m = per_node_metrics(rs, t_start, t_end)
        if m is None:
            continue
        # Run-final cumulative count = app_pkts on the LAST telemetry row of
        # the entire run, regardless of attack window. Used only for NetPDR.
        run_final = max(r["app_pkts"] for r in rs)
        if node == SINK_NODE_ID:
            sink_rx_bytes_total = m["rx_bytes_total"]
            sink_app_rx_run_final = run_final
            continue  # sink not part of attacker/normal pools
        sender_app_run_final += run_final
        if node in attackers:
            attacker_metrics.append(m)
        else:
            normal_metrics.append(m)

    attack_window_dur = max(1, t_end - t_start)
    sender_app_total = sum(m["app_pkts_sent"] for m in normal_metrics + attacker_metrics)
    net_app_throughput = sender_app_total / attack_window_dur
    # Network-wide PDR: sink received / total sent over the ENTIRE run.
    network_pdr = (100.0 * sink_app_rx_run_final / sender_app_run_final) if sender_app_run_final > 0 else float("nan")

    # Pool per-source PDR by class (attacker / victim / bystander).
    pdr_by_class = {"attacker": [], "victim": [], "bystander": []}
    for n, pdr in per_src_pdr.items():
        if pdr != pdr:  # NaN — sender never sent
            continue
        cls = classes.get(n)
        if cls in pdr_by_class:
            pdr_by_class[cls].append(pdr)

    # Diagnostic: total sink rx vs sum of attributed per-source rx. A large
    # gap signals 6LoWPAN-compression artefacts in srcipaddr.u8[15] (or
    # whatever scheme is used for src_id extraction). Reviewer-relevant.
    sum_attributed = sum(sink_rx_per_src.get(n, 0)
                         for n in by_node if n != SINK_NODE_ID)
    unattributed_pkts = max(0, sink_app_rx_run_final - sum_attributed)
    pdr_attribution_pct = (100.0 * sum_attributed / sink_app_rx_run_final) \
        if sink_app_rx_run_final > 0 else float("nan")
    # Distinct src_ids that appeared in PDR_STATS (incl. unexpected ones
    # like 0 or out-of-range — diagnostic).
    distinct_src_ids = sorted(sink_rx_per_src.keys())

    return {
        "log": Path(path).name,
        "t_start": t_start,
        "t_end": t_end,
        "attack_window_s": attack_window_dur,
        "n_attackers": len(attacker_metrics),
        "n_normals": len(normal_metrics),
        "attackers": sorted(attackers),
        "sink_rx_total": sink_rx_bytes_total,
        "sink_app_rx_count": sink_app_rx_run_final,   # run-final cumulative
        "sender_app_total": sender_app_run_final,     # run-final cumulative
        "sender_app_window": sender_app_total,        # window-only delta (kept for ref)
        "network_pdr_pct": network_pdr,
        "net_app_throughput_pps": net_app_throughput,
        "n_pdr_records": len(pdr_records),
        "atk_pdr_pct_mean": mean(pdr_by_class["attacker"]) if pdr_by_class["attacker"] else float("nan"),
        "vic_pdr_pct_mean": mean(pdr_by_class["victim"]) if pdr_by_class["victim"] else float("nan"),
        "bys_pdr_pct_mean": mean(pdr_by_class["bystander"]) if pdr_by_class["bystander"] else float("nan"),
        "unattributed_pkts": unattributed_pkts,
        "pdr_attribution_pct": pdr_attribution_pct,
        "distinct_src_ids": distinct_src_ids,
        "attacker": attacker_metrics,
        "normal": normal_metrics,
    }

def pool(metric_list, key):
    vals = [m[key] for m in metric_list if m and key in m and m[key] == m[key]]  # drop NaN
    return (mean(vals), stdev(vals) if len(vals) > 1 else 0.0) if vals else (float("nan"), 0.0)

def summarize_attack(family, runs):
    """Pool per-run results into one row per attack family."""
    keys = [
        "app_pkts_sent", "app_pkts_per_min", "app_completion_pct",
        "tx_bytes_total", "rx_bytes_total", "tx_bytes_per_s", "rx_bytes_per_s",
        "ctrl_overhead", "parent_switches", "mean_buf_occ", "mean_rank",
        "mean_rssi", "route_count_final",
    ]
    out = {"attack": family, "n_runs": len(runs)}

    # Per-attack-window scalars (averaged across runs)
    out["attack_window_s_mean"] = mean(r["attack_window_s"] for r in runs)
    out["sink_rx_total_mean"]   = mean(r["sink_rx_total"]   for r in runs)
    out["sink_rx_total_std"]    = stdev([r["sink_rx_total"] for r in runs]) if len(runs) > 1 else 0.0
    out["sink_app_rx_count_mean"] = mean(r["sink_app_rx_count"] for r in runs)
    out["sender_app_total_mean"] = mean(r["sender_app_total"] for r in runs)
    pdr_vals = [r["network_pdr_pct"] for r in runs if r["network_pdr_pct"] == r["network_pdr_pct"]]
    out["network_pdr_pct_mean"] = mean(pdr_vals) if pdr_vals else float("nan")
    out["net_app_throughput_pps_mean"] = mean(r["net_app_throughput_pps"] for r in runs)
    out["n_attackers_mean"] = mean(r["n_attackers"] for r in runs)
    out["n_normals_mean"]   = mean(r["n_normals"]   for r in runs)
    # Per-source PDR by class — primary damage signal across attacks.
    for k in ("atk_pdr_pct_mean", "vic_pdr_pct_mean", "bys_pdr_pct_mean"):
        vals = [r[k] for r in runs if r[k] == r[k]]
        out[k] = mean(vals) if vals else float("nan")
    out["n_pdr_records_mean"] = mean(r["n_pdr_records"] for r in runs)

    # Pool attacker / normal node metrics across all runs
    all_attacker = [m for r in runs for m in r["attacker"]]
    all_normal   = [m for r in runs for m in r["normal"]]
    for k in keys:
        am, asd = pool(all_attacker, k)
        nm, nsd = pool(all_normal, k)
        out[f"atk_{k}_mean"] = am
        out[f"atk_{k}_std"]  = asd
        out[f"nrm_{k}_mean"] = nm
        out[f"nrm_{k}_std"]  = nsd
    return out

def fmt(x, nd=2):
    if x != x:  # NaN
        return "  nan "
    if abs(x) >= 1000:
        return f"{x:7.0f}"
    return f"{x:7.{nd}f}"

def print_summary_table(results):
    # Header — picks the most informative columns for a one-shot reviewer table
    cols = [
        ("attack", 16, "Attack"),
        ("n_runs", 5, "Runs"),
        ("atk_pdr_pct_mean", 8, "AtkPDR%"),
        ("vic_pdr_pct_mean", 8, "VicPDR%"),
        ("bys_pdr_pct_mean", 8, "BysPDR%"),
        ("atk_app_pkts_per_min_mean", 7, "AtkPpm"),
        ("nrm_app_pkts_per_min_mean", 7, "NrmPpm"),
        ("atk_ctrl_overhead_mean", 8, "AtkCtrl"),
        ("nrm_ctrl_overhead_mean", 8, "NrmCtrl"),
        ("atk_mean_rank_mean", 8, "AtkRank"),
        ("nrm_mean_rank_mean", 8, "NrmRank"),
        ("atk_mean_buf_occ_mean", 7, "AtkBuf"),
        ("nrm_mean_buf_occ_mean", 7, "NrmBuf"),
    ]
    header = " | ".join(f"{name:>{w}}" for _, w, name in cols)
    print(header)
    print("-" * len(header))
    for row in results:
        cells = []
        for key, w, _ in cols:
            v = row.get(key, "")
            if isinstance(v, str):
                cells.append(f"{v:>{w}}")
            elif isinstance(v, (int, float)):
                cells.append(f"{fmt(v):>{w}}")
            else:
                cells.append(f"{'':>{w}}")
        print(" | ".join(cells))

def write_csv(results, path):
    if not results:
        return
    fieldnames = list(results[0].keys())
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for row in results:
            w.writerow({k: row.get(k, "") for k in fieldnames})

def write_per_run_csv(per_run, path):
    if not per_run:
        return
    fieldnames = ["attack", "log", "t_start", "t_end", "attack_window_s",
                  "n_attackers", "n_normals", "attackers",
                  "sink_rx_total", "net_app_throughput_pps"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(fieldnames)
        for r in per_run:
            w.writerow([
                r["attack"], r["log"], r["t_start"], r["t_end"],
                r["attack_window_s"], r["n_attackers"], r["n_normals"],
                "|".join(str(x) for x in r["attackers"]),
                r["sink_rx_total"], f"{r['net_app_throughput_pps']:.4f}",
            ])

def main():
    summary = []
    per_run_records = []

    for family, pat in ATTACK_PATTERNS.items():
        # Only telemetry logs from udp_listener_ipv6.py — exclude Cooja stdout
        # captures (filenames prefixed with "cooja_") and pre-Plan-A logs
        # whose filename date is before MIN_LOG_DATE.
        files = sorted(p for p in glob.glob(str(REPO_ROOT / pat))
                       if not Path(p).name.startswith("cooja_")
                       and Path(p).name[:16] >= MIN_LOG_DATE)
        if not files:
            print(f"[skip] {family}: no logs match {pat}")
            continue
        runs = []
        for path in files:
            r = aggregate_run(path, is_baseline=(family == "baseline"))
            if r is None:
                print(f"[warn] {Path(path).name}: no labelled (is_attacker=1) rows")
                continue
            r["attack"] = family
            runs.append(r)
            per_run_records.append(r)
        if not runs:
            continue
        summary.append(summarize_attack(family, runs))

    # Output
    print_summary_table(summary)
    summary_csv = REPO_ROOT / "damage_analysis_summary.csv"
    per_run_csv = REPO_ROOT / "damage_analysis_per_run.csv"
    write_csv(summary, summary_csv)
    write_per_run_csv(per_run_records, per_run_csv)
    print(f"\nWrote: {summary_csv.name}  (one row per attack family)")
    print(f"Wrote: {per_run_csv.name}   (one row per run)")

if __name__ == "__main__":
    main()
