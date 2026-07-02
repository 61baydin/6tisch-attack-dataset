#!/usr/bin/env bash
# Multi-attack dispatcher: 6 combos x 2 scales x 3 seeds = 36 runs.
# Each run: 2x attackA (core) + 2x attackB (edge) = 4 attackers, concurrent.
#
# Prerequisites (sudo): namespaces via setup_parallel_workers.sh + ALL attack
# firmwares pre-built (pre-build below to prevent build races).
# Run:  sudo NWORKERS=8 bash dispatcher_multiattack.sh
set -euo pipefail
cd "$(dirname "$0")"
NWORKERS=${NWORKERS:-8}
STAGGER_S=${STAGGER_S:-150}
SEEDS=(42 43 44)
SCALES=(21 30)
# combos: "attackA attackB" -> A placed at core, B placed at edge.
# RULE: location-sensitive attacks (blackhole/decrease: need children/traffic) are ALWAYS A (core);
# broadcast-based attacks (dis/flooding/shared/timekeep: work anywhere) are B (edge).
COMBOS=(
  "blackhole dis"            # data@core + control@edge
  "blackhole timekeep"       # data@core + MAC-time@edge
  "decrease flooding"        # routing@core + application@edge
  "decrease dis"             # routing@core + control@edge
  "shared-slot timekeep"     # MAC@core + MAC@edge (both robust)
  "flooding shared-slot"     # application@core + MAC@edge (both robust)
)

RUNS=()
for c in "${COMBOS[@]}"; do
  for s in "${SCALES[@]}"; do
    for seed in "${SEEDS[@]}"; do
      RUNS+=("$c $seed $s")   # spec: attackA attackB seed scale
    done
  done
done
TOTAL=${#RUNS[@]}
echo "[multi] total runs: $TOTAL | workers: $NWORKERS"

declare -A QUEUES
for i in "${!RUNS[@]}"; do QUEUES[$((i % NWORKERS))]+="${RUNS[$i]}|"; done

MAX_ATTEMPTS=${MAX_ATTEMPTS:-3}
mkdir -p dispatcher_logs
PIDS=()
for w in $(seq 0 $((NWORKERS - 1))); do
  queue="${QUEUES[$w]:-}"; [[ -z "$queue" ]] && continue
  (
    sleep $(( w * STAGGER_S ))
    IFS='|' read -ra items <<< "$queue"
    nl=0
    for item in "${items[@]}"; do
      [[ -z "$item" ]] && continue
      nl=$((nl+1)); attempt=1
      while (( attempt <= MAX_ATTEMPTS )); do
        echo "[w${w}] run ${nl} attempt ${attempt}: $item"
        if sudo PATH="$PATH" ip netns exec "cooja_w${w}" \
            env PATH="$PATH" bash multirun_multiattack.sh "$w" $item \
            >> "dispatcher_logs/multi_worker${w}.log" 2>&1; then
          echo "[w${w}] run ${nl} OK"; break
        else
          echo "[w${w}] run ${nl} attempt ${attempt} FAILED: $item"; attempt=$((attempt+1)); sleep 5
        fi
      done
      (( attempt > MAX_ATTEMPTS )) && echo "[w${w}] ABANDONED: $item" | tee -a dispatcher_logs/multi_abandoned.log
    done
    echo "[w${w}] done ($nl specs)"
  ) &
  PIDS+=($!)
done
echo "[multi] ${#PIDS[@]} workers started"
for pid in "${PIDS[@]}"; do wait "$pid"; done
echo "[multi] DONE. multi logs: $(ls 2026-*_multi-*-w[0-9].log 2>/dev/null | grep -v cooja | wc -l) | pcap: $(ls pcaps/2026-*_multi-*.pcap 2>/dev/null | wc -l)"
