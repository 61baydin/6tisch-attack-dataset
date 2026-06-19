#!/usr/bin/env bash
# Round-robin dispatcher: distributes 84 (or fewer) Cooja runs across
# NWORKERS parallel namespace-isolated workers. Each worker drains its own
# queue sequentially; the four queues progress in parallel.
#
# Prerequisites (manual, sudo):
#   1) sudo bash setup_parallel_workers.sh                 # one-time
#   2) For each worker in a tmux pane:
#         sudo bash tunslip6_keeper_ns.sh 0
#         sudo bash tunslip6_keeper_ns.sh 1
#         sudo bash tunslip6_keeper_ns.sh 2
#         sudo bash tunslip6_keeper_ns.sh 3
#   3) Then run this dispatcher (sudo needed for ip netns exec).
#
# Usage:
#   sudo bash dispatcher.sh                  # full 84-run sweep
#   sudo bash dispatcher.sh blackhole        # only that attack family (12 runs)
#   NWORKERS=2 sudo bash dispatcher.sh       # use only 2 workers
set -euo pipefail
cd "$(dirname "$0")"

NWORKERS=${NWORKERS:-4}
FILTER_ATTACK="${1:-}"        # optional: filter to one attack family
SEED_BASE=${SEED_BASE:-42}
STAGGER_S=${STAGGER_S:-150}   # worker baslangiclari arasi gecikme (build-race onleme)

ATTACKS=(decrease dis flooding shared-slot slot-exhaustion timekeep blackhole)
PLACEMENTS=(core mid edge)
ATKCOUNTS=(5 1)
SCALES=(21 30)

# Build run-spec list: 7 * 3 * 2 * 2 = 84
RUNS=()
for a in "${ATTACKS[@]}"; do
  [[ -n "$FILTER_ATTACK" && "$a" != "$FILTER_ATTACK" ]] && continue
  for s in "${SCALES[@]}"; do
    for p in "${PLACEMENTS[@]}"; do
      for n in "${ATKCOUNTS[@]}"; do
        # spec: attack atkcount seed placement scale
        RUNS+=("$a $n $SEED_BASE $p $s")
      done
    done
  done
done

# 2 baseline kosusu (sifir saldirgan, her olcek icin) -- sadece tam sweep'te
if [[ -z "$FILTER_ATTACK" ]]; then
  for s in "${SCALES[@]}"; do
    # spec: attack atkcount seed placement scale (baseline placement'i yok sayar)
    RUNS+=("baseline 0 $SEED_BASE core $s")
  done
fi

TOTAL=${#RUNS[@]}
echo "[dispatcher] total runs to execute: $TOTAL"
echo "[dispatcher] workers: $NWORKERS"
echo "[dispatcher] expected wall-clock: $((TOTAL * 90 / NWORKERS / 60)) hours"
echo

# Round-robin into per-worker queues
declare -A QUEUES
for i in "${!RUNS[@]}"; do
  w=$((i % NWORKERS))
  QUEUES[$w]+="${RUNS[$i]}|"
done

# Retry policy: each (attack, atkcount, seed, placement, scale) spec retries
# up to MAX_ATTEMPTS times until validate_run_log.py passes. Bad logs are
# deleted by the worker so 84 healthy logs are guaranteed at the end.
MAX_ATTEMPTS=${MAX_ATTEMPTS:-3}

# Spawn workers in parallel
PIDS=()
mkdir -p dispatcher_logs
for w in $(seq 0 $((NWORKERS - 1))); do
  queue="${QUEUES[$w]:-}"
  [[ -z "$queue" ]] && continue
  (
    # Build-race onleme: paylasimli build/cooja dizininde es-zamanli derleme
    # cakismasini (Mote type creation failed: Bad return value) engellemek icin
    # worker baslangiclarini kademelendir. Ilk worker firmware'i derler,
    # digerleri ~2dk sonra baslayip up-to-date binary'yi yeniden kullanir.
    sleep $(( w * STAGGER_S ))
    n_local=0
    IFS='|' read -ra items <<< "$queue"
    for item in "${items[@]}"; do
      [[ -z "$item" ]] && continue
      n_local=$((n_local + 1))
      attempt=1
      while (( attempt <= MAX_ATTEMPTS )); do
        echo "[w${w}] starting run ${n_local} attempt ${attempt}/${MAX_ATTEMPTS}: $item"
        if sudo PATH="$PATH" ip netns exec "cooja_w${w}" \
            env PATH="$PATH" bash multirun_worker.sh "$w" $item \
            >> "dispatcher_logs/worker${w}.log" 2>&1; then
          echo "[w${w}] run ${n_local} OK on attempt ${attempt}"
          break
        else
          echo "[w${w}] run ${n_local} attempt ${attempt} FAILED: $item"
          attempt=$((attempt + 1))
          sleep 5
        fi
      done
      if (( attempt > MAX_ATTEMPTS )); then
        echo "[w${w}] run ${n_local} ABANDONED after ${MAX_ATTEMPTS} attempts: $item" \
          | tee -a dispatcher_logs/abandoned.log
      fi
    done
    echo "[w${w}] all runs done ($n_local specs processed)"
  ) &
  PIDS+=($!)
done

echo "[dispatcher] spawned ${#PIDS[@]} workers (PIDs: ${PIDS[*]})"
echo "[dispatcher] watching... tail -f dispatcher_logs/worker*.log to follow"

# Wait for all workers
for pid in "${PIDS[@]}"; do
  wait "$pid"
done

echo
echo "[dispatcher] all workers finished. Captured logs:"
ls -la 2026-*_*-w[0-9].log 2>/dev/null | wc -l
echo "[dispatcher] pcap files:"
ls -la pcaps/ 2>/dev/null | wc -l
