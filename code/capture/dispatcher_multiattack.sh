#!/usr/bin/env bash
# Coklu-saldiri dispatcher: 6 kombo x 2 olcek x 3 tohum = 36 kosu.
# Her kosu: 2x attackA (core) + 2x attackB (edge) = 4 saldirgan, es-zamanli.
#
# On kosul (sudo): setup_parallel_workers.sh ile namespace'ler + TUM saldiri
# firmware'lerinin derli olmasi (yarisi onlemek icin asagidaki pre-build).
# Calistirma:  sudo NWORKERS=8 bash dispatcher_multiattack.sh
set -euo pipefail
cd "$(dirname "$0")"
NWORKERS=${NWORKERS:-8}
STAGGER_S=${STAGGER_S:-150}
SEEDS=(42 43 44)
SCALES=(21 30)
# kombolar: "attackA attackB" -> A core'a, B edge'e yerlesir.
# KURAL: konuma-duyarli saldiri (blackhole/decrease: cocuk/trafik gerekir) HEP A (core);
# yayin-tabanli saldiri (dis/flooding/shared/timekeep: her yerde calisir) B (edge).
COMBOS=(
  "blackhole dis"            # veri@core + kontrol@edge
  "blackhole timekeep"       # veri@core + MAC-zaman@edge
  "decrease flooding"        # yonlendirme@core + uygulama@edge
  "decrease dis"             # yonlendirme@core + kontrol@edge
  "shared-slot timekeep"     # MAC@core + MAC@edge (ikisi de saglam)
  "flooding shared-slot"     # uygulama@core + MAC@edge (ikisi de saglam)
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
echo "[multi] toplam kosu: $TOTAL | worker: $NWORKERS"

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
    echo "[w${w}] bitti ($nl spec)"
  ) &
  PIDS+=($!)
done
echo "[multi] ${#PIDS[@]} worker basladi"
for pid in "${PIDS[@]}"; do wait "$pid"; done
echo "[multi] BITTI. multi log: $(ls 2026-*_multi-*-w[0-9].log 2>/dev/null | grep -v cooja | wc -l) | pcap: $(ls pcaps/2026-*_multi-*.pcap 2>/dev/null | wc -l)"
