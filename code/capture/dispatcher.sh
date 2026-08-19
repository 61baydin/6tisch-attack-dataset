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
# ATKCOUNTS / SCALES can be narrowed from the environment: ATKCOUNTS="5" SCALES="21 30"
read -ra ATKCOUNTS <<< "${ATKCOUNTS:-5 1}"
read -ra SCALES <<< "${SCALES:-21 30}"
# RADIO_SEEDS: Cooja <randomseed> values (space-separated). If left empty the
# default in the CSC (123456) is used and each cell runs once. For multi-seed
# replication use for example: RADIO_SEEDS="7331 9173"
read -ra RADIO_SEEDS <<< "${RADIO_SEEDS:-}"
(( ${#RADIO_SEEDS[@]} == 0 )) && RADIO_SEEDS=("")
WITH_BASELINE=${WITH_BASELINE:-1}

# Build run-spec list (attack x scale x placement x density x radio seed)
RUNS=()
for a in "${ATTACKS[@]}"; do
  [[ -n "$FILTER_ATTACK" && "$a" != "$FILTER_ATTACK" ]] && continue
  for s in "${SCALES[@]}"; do
    for p in "${PLACEMENTS[@]}"; do
      for n in "${ATKCOUNTS[@]}"; do
       for rs in "${RADIO_SEEDS[@]}"; do
        # spec: attack atkcount seed placement scale radioseed
        RUNS+=("$a $n $SEED_BASE $p $s ${rs:-default}")
       done
      done
    done
  done
done

# two baseline runs (zero attackers, one per scale) -- full sweep only
if [[ -z "$FILTER_ATTACK" && "$WITH_BASELINE" == "1" ]]; then
  for s in "${SCALES[@]}"; do
    # spec: attack atkcount seed placement scale radioseed
    RUNS+=("baseline 0 $SEED_BASE core $s ${RADIO_SEEDS[0]:-default}")
  done
fi

TOTAL=${#RUNS[@]}
echo "[dispatcher] total runs to execute: $TOTAL"
echo "[dispatcher] workers: $NWORKERS | radio seeds: ${RADIO_SEEDS[*]:-CSC default} | densities: ${ATKCOUNTS[*]} | scales: ${SCALES[*]}"
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

      # --- Resume: skip a cell that already has a valid log.
      # Restarting the dispatcher after a reboot or a closed terminal must not
      # repeat completed runs. Disable with SKIP_EXISTING=0.
      if [[ "${SKIP_EXISTING:-1}" == "1" ]]; then
        read -r r_atk r_cnt r_seed r_pl r_scale r_rseed <<< "$item"
        r_nodes=$([[ "$r_scale" == "21" ]] && echo 21 || echo 31)
        if [[ "$r_rseed" == "default" ]]; then r_stag=""; else r_stag="-s${r_rseed}"; fi
        if [[ "$r_atk" == "baseline" ]]; then
          r_glob="*_baseline-n${r_nodes}${r_stag}-w*.log"
        else
          r_glob="*_${r_atk}-n${r_nodes}-${r_pl}-a${r_cnt}${r_stag}-w*.log"
        fi
        r_hit=""
        for cand in $r_glob; do
          [[ -e "$cand" ]] || continue
          if python3 validate_run_log.py "$cand" "$r_scale" >/dev/null 2>&1; then
            r_hit="$cand"; break
          fi
        done
        if [[ -n "$r_hit" ]]; then
          echo "[w${w}] run ${n_local} SKIP (mevcut gecerli log: $r_hit): $item"
          continue
        fi
      fi

      attempt=1
      while (( attempt <= MAX_ATTEMPTS )); do
        echo "[w${w}] starting run ${n_local} attempt ${attempt}/${MAX_ATTEMPTS}: $item"
        # the last field of the spec is the radio seed; it reaches the worker
        # through the environment rather than as a positional argument
        spec_args="${item% *}"; spec_seed="${item##* }"
        [[ "$spec_seed" == "default" ]] && spec_seed=""
        if sudo PATH="$PATH" ip netns exec "cooja_w${w}" \
            env PATH="$PATH" RADIO_SEED="$spec_seed" bash multirun_worker.sh "$w" $spec_args \
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
