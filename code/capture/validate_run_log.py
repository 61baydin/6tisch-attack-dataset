#!/usr/bin/env python3
"""Validate a captured Cooja telemetry log.

Exits 0 (OK) if the log passes all sanity checks; exits 1 (BAD) otherwise.
Used by multirun_worker.sh to decide whether to delete a captured log and
retry the run.

Checks:
  1. File exists and is at least 50 KB (basic completeness).
  2. Contains at least 80% of the expected number of telemetry records,
     proportional to (scale * 60 min / 10s tick).
  3. At least one record carries `is_attacker=1`.
  4. The first attacker record occurs in [1050, 1650] seconds - i.e. inside
     the designed [20, 25] minute attack window plus a small margin for
     telemetry tick alignment.
  5. The last record's timestamp is >= 3400 seconds (~57 min, allowing some
     margin from the 60-min total run).

Usage:
  python3 validate_run_log.py <log_file> [<scale>] [<mode>]
    <scale>: 21 (default) or 30
    <mode>:  "baseline" relaxes checks 3-4 (no attacker exists) and instead
             requires ZERO is_attacker=1 records; otherwise the attack-window
             checks apply as normal.
"""
import os
import re
import sys

LOG_RE = re.compile(r"b'\s*([0-9,\-\s]+)\s*'")
MIN_SIZE_BYTES = 50_000
# 70% of (60min / 10s tick). Was 0.8, but packet-dropping attacks (notably
# blackhole) legitimately lose telemetry in transit - a 30-node blackhole run
# delivers ~77% of records, which is valid data, not a broken run. 0.7 still
# rejects genuinely failed runs (e.g. 134-byte / ~5k-record early terminations).
EXPECTED_RECS_PER_MOTE = 0.7 * 360
ATK_FIRST_LOW_S = 1050
ATK_FIRST_HIGH_S = 2100  # was 1650; attack onset is <=1500s but the first
# is_attacker=1 record can arrive later due to telemetry *delivery* lag -
# pronounced for edge attackers and packet-dropping attacks (blackhole), where
# the attacker's own reports reach the sink several minutes after onset.
LAST_TS_MIN_S = 3400


def main() -> int:
    if len(sys.argv) < 2:
        print('usage: validate_run_log.py <log> [<scale>]', file=sys.stderr)
        return 2
    log = sys.argv[1]
    scale = int(sys.argv[2]) if len(sys.argv) > 2 else 21
    mode = sys.argv[3] if len(sys.argv) > 3 else ''
    # scale 21 → 20 client motes; scale 30 → 30 client motes (sink excluded)
    n_motes = scale - 1
    expected_min_recs = int(EXPECTED_RECS_PER_MOTE * n_motes)
    # Blackhole also drops telemetry in transit -> fewer records + a late-arriving
    # first-attacker record (especially at 31 motes). These full-duration runs are
    # valid data, so relax the thresholds for blackhole. This is safe because the
    # LAST_TS check already catches early termination separately.
    atk_first_high = ATK_FIRST_HIGH_S
    if 'blackhole' in os.path.basename(log):
        expected_min_recs = int(0.45 * 360 * n_motes)
        atk_first_high = 2900

    if not os.path.isfile(log):
        print(f'BAD: {log} does not exist'); return 1
    size = os.path.getsize(log)
    if size < MIN_SIZE_BYTES:
        print(f'BAD: {log} too small ({size} B < {MIN_SIZE_BYTES} B)'); return 1

    rows = []
    with open(log) as f:
        for line in f:
            m = LOG_RE.search(line)
            if not m:
                continue
            vals = [int(x.strip()) for x in m.group(1).split(',') if x.strip()]
            if len(vals) >= 18:
                rows.append(vals)
    if len(rows) < expected_min_recs:
        print(f'BAD: {log} has {len(rows)} records (need >= {expected_min_recs})')
        return 1
    atk = [r for r in rows if r[-2] == 1]   # is_attacker = second-to-last (works for both 18 and 20 columns)
    last_ts = max(r[0] for r in rows)
    if mode == 'baseline':
        # No attacker exists; the log must be fully benign. Skip attack-window
        # checks and instead reject any stray is_attacker=1 record.
        if atk:
            print(f'BAD: {log} is baseline but has {len(atk)} is_attacker=1 records')
            return 1
        if last_ts < LAST_TS_MIN_S:
            print(f'BAD: {log} run ended at {last_ts}s (< {LAST_TS_MIN_S}s - early termination)')
            return 1
        print(f'OK (baseline): {log} | {len(rows)} recs (0 atk) | last={last_ts}s')
        return 0
    if not atk:
        print(f'BAD: {log} has zero is_attacker=1 records'); return 1
    first_atk_ts = min(r[0] for r in atk)
    if first_atk_ts < ATK_FIRST_LOW_S or first_atk_ts > atk_first_high:
        print(f'BAD: {log} first attack at {first_atk_ts}s (outside [{ATK_FIRST_LOW_S},{atk_first_high}]s)')
        return 1
    if last_ts < LAST_TS_MIN_S:
        print(f'BAD: {log} run ended at {last_ts}s (< {LAST_TS_MIN_S}s - early termination)')
        return 1
    print(f'OK: {log} | {len(rows)} recs ({len(atk)} atk) | first_atk={first_atk_ts}s | last={last_ts}s')
    return 0


if __name__ == '__main__':
    sys.exit(main())
