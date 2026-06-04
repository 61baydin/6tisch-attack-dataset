#!/usr/bin/env bash
# Run ONE fully-benign baseline simulation (zero attackers) per topology scale,
# capturing pure-normal telemetry for the 21- and 31-mote networks. Mirrors the
# dispatcher's namespace-isolated launch but for a single worker (cooja_w0), so
# it can run while the main 84-run dataset is untouched.
#
# Each run reuses the blackhole base CSC with an EMPTY attacker set; every mote
# is therefore a normal client and no attack firmware is ever exercised. Output
# logs:  <stamp>_baseline-n21-w0.log  and  <stamp>_baseline-n31-w0.log
#
# Prerequisite: the cooja_w0 namespace must exist (setup_parallel_workers.sh).
# tunslip6 is launched by the worker itself inside the namespace, so no separate
# manual tunslip6 is needed — only sudo for `ip netns exec` (prompted once).
#
# Usage:
#   bash run_baseline.sh            # both scales (21 then 31)
#   bash run_baseline.sh 21         # only the 21-mote baseline
set -euo pipefail
cd "$(dirname "$0")"

SCALES_ARG="${1:-}"
SCALES=(21 30)            # worker maps scale 30 -> 31-mote topology
[[ -n "$SCALES_ARG" ]] && SCALES=("$SCALES_ARG")
SEED=${SEED:-42}
MAX_ATTEMPTS=${MAX_ATTEMPTS:-2}

# Each scale runs concurrently in its OWN namespace+worker (w0, w1, ...). The
# namespaces are fully isolated (separate port 60001 / tunslip6 / tun0 / UDP
# listener), so there is no contention — wall-clock is max(scales), not sum.
mkdir -p dispatcher_logs
PIDS=()
for i in "${!SCALES[@]}"; do
  SCALE="${SCALES[$i]}"
  WID="$i"
  (
    attempt=1
    while (( attempt <= MAX_ATTEMPTS )); do
      echo "[baseline w${WID}] scale=${SCALE} attempt ${attempt}/${MAX_ATTEMPTS}"
      if sudo PATH="$PATH" ip netns exec "cooja_w${WID}" \
          env PATH="$PATH" bash multirun_worker.sh "$WID" baseline 0 "$SEED" core "$SCALE" \
          >> "dispatcher_logs/baseline_w${WID}.log" 2>&1; then
        echo "[baseline w${WID}] scale=${SCALE} OK"
        break
      fi
      echo "[baseline w${WID}] scale=${SCALE} attempt ${attempt} FAILED"
      attempt=$((attempt + 1))
      sleep 5
    done
    if (( attempt > MAX_ATTEMPTS )); then
      echo "[baseline w${WID}] scale=${SCALE} ABANDONED after ${MAX_ATTEMPTS} attempts"
    fi
  ) &
  PIDS+=($!)
done

echo "[baseline] spawned ${#PIDS[@]} concurrent worker(s) (PIDs: ${PIDS[*]})"
echo "[baseline] follow: tail -f dispatcher_logs/baseline_w*.log"
for pid in "${PIDS[@]}"; do wait "$pid"; done

echo
echo "[baseline] captured logs:"
ls -la 2026-*_baseline-n*-w[0-9].log 2>/dev/null || echo "  (none — check dispatcher_logs/baseline_w*.log)"
