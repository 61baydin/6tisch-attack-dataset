#!/usr/bin/env bash
# Namespace-aware variant of multirun_attack.sh, used by dispatcher.sh.
#
# Receives a worker id and a single (attack, scale, placement, atkcount)
# spec, runs ONE Cooja simulation inside cooja_w<WID> with a per-worker
# variant CSC, captures the telemetry log and renames it with a worker-id
# suffix so 4 workers writing concurrently never clobber each other.
#
# Run via dispatcher (which sudo's into the namespace), NOT directly:
#   sudo ip netns exec cooja_w0 bash multirun_worker.sh 0 blackhole 5 42 core 21
#
# Output filenames carry "_w<WID>" so 84 log files end up flat in the repo
# root, easy to glob.
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(pwd)"
# Cooja recompiles per motetype on load; msp430-gcc must be findable even
# under sudo+ip netns exec (which strips user's PATH).
export PATH="/opt/msp430/bin:${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}"

WID="${1:?worker id (0..3) required}"
ATTACK="${2:?attack name required}"
ATKCOUNT="${3:?attackers per run (1|5) required}"
SEED="${4:?seed required}"
PLACEMENT="${5:?core|mid|edge required}"
SCALE="${6:-21}"

# ===== Pool selection (must mirror multirun_attack.sh exactly) =====
case "$SCALE" in
  21)
    case "$PLACEMENT" in
      core) POOL="2 3 4 5 7 8" ;;
      mid)  POOL="6 9 10 11 12 13" ;;
      edge) POOL="14 15 16 17 18 19 20 21" ;;
      *)    echo "unknown placement: $PLACEMENT"; exit 1 ;;
    esac
    CSC_VERSION="v3"
    TOTAL_NODES=21
    ;;
  30)
    case "$PLACEMENT" in
      core) POOL="2 3 4 5 6 7 8 9 10 11" ;;
      mid)  POOL="12 13 14 15 16 17 18 19 20 21" ;;
      edge) POOL="22 23 24 25 26 27 28 29 30 31" ;;
      *)    echo "unknown placement: $PLACEMENT"; exit 1 ;;
    esac
    CSC_VERSION="v3-30"
    TOTAL_NODES=31
    ;;
  *) echo "unknown scale: $SCALE (must be 21|30)"; exit 1 ;;
esac

# Baseline mode: a fully-benign run with ZERO attackers. Reuses the blackhole
# base CSC (arbitrary) since gen_csc_variant with an empty attacker set marks
# every mote as a normal client -- no mote ever loads attack firmware.
VALIDATE_MODE=""
if [[ "$ATTACK" == "baseline" ]]; then
  ATKCOUNT=0
  ATTACKER_SET=""
  VALIDATE_MODE="baseline"
  BASE_CSC="examples/tsch/rpl-udp/rpl-border-blackhole-${CSC_VERSION}.csc"
else
  # Sample attacker IDs from the pool deterministically (seed + worker id)
  ATTACKER_SET=$(python3 -c "
import random
random.seed($SEED + 1000*$WID)
pool = [$(echo "$POOL" | tr ' ' ',')]
print(' '.join(str(x) for x in sorted(random.sample(pool, $ATKCOUNT))))
")
  BASE_CSC="examples/tsch/rpl-udp/rpl-border-${ATTACK}-${CSC_VERSION}.csc"
fi
[[ -f "$BASE_CSC" ]] || { echo "base CSC not found: $BASE_CSC"; exit 1; }

STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
if [[ "$ATTACK" == "baseline" ]]; then
  PLACEMENT_TAG=""
  ATKCOUNT_TAG=""
else
  PLACEMENT_TAG="-${PLACEMENT}"
  ATKCOUNT_TAG="-a${ATKCOUNT}"
fi
# Radio seed: without RADIO_SEED the default in the CSC (123456) is used.
# When set it is written into the CSC and appended to the run name as -s<seed>,
# so the glob patterns of the single-seed chain (*-a5-w*) never match replicas.
RADIO_SEED="${RADIO_SEED:-}"
if [[ -n "$RADIO_SEED" ]]; then SEED_TAG="-s${RADIO_SEED}"; else SEED_TAG=""; fi
TAG="${ATTACK}-n${TOTAL_NODES}${PLACEMENT_TAG}${ATKCOUNT_TAG}${SEED_TAG}-w${WID}"
COOJA_LOG="cooja_${STAMP}_${TAG}.log"
RUN_LOG="${STAMP}_${TAG}.log"
VARIANT_CSC="${BASE_CSC%.csc}${SEED_TAG}-w${WID}.csc"

# Per-run pcap path (under repo-root pcaps/ dir, includes worker id)
mkdir -p pcaps
PCAP_PATH="$(pwd)/pcaps/${STAMP}_${TAG}.pcap"

echo "[w${WID}] === RUN: ${TAG} | attackers=[${ATTACKER_SET// /,}] ==="

PCAP_PATH="$PCAP_PATH" COOJA_RANDOMSEED="$RADIO_SEED" python3 gen_csc_variant.py "$BASE_CSC" "$VARIANT_CSC" $ATTACKER_SET || {
  echo "[w${WID}] CSC gen failed"; exit 1
}

# Per-worker Cooja working dir (avoids COOJA.log clobber between workers).
WDIR="/tmp/cooja_w${WID}"
mkdir -p "$WDIR"

# Defensive: kill any stale Cooja left over from a previous failed attempt of
# THIS worker's variant CSC. Otherwise it keeps port 60001 bound and the new
# Cooja dies with "SerialSocketServer: Address already in use". The variant CSC
# basename is unique per worker, so this never touches sibling workers.
CSC_KEY="$(basename "$VARIANT_CSC")"
pkill -9 -f "$CSC_KEY" 2>/dev/null || true
sleep 1

# Launch Cooja headless inside the current namespace (caller is already in NS).
( cd "$WDIR" && java -mx2048m -jar "$REPO/tools/cooja/dist/cooja.jar" \
    -nogui="$REPO/$VARIANT_CSC" \
    -contiki="$REPO" \
    > "$REPO/$COOJA_LOG" 2>&1 ) &
COOJA_PID=$!

# Wait for port 60001 inside namespace (Cooja's SerialSocketServer)
port_up=0
for s in $(seq 1 120); do
  if ss -tln 2>/dev/null | grep -q ':60001 '; then port_up=1; break; fi
  sleep 1
done
if [[ "$port_up" -ne 1 ]]; then
  echo "[w${WID}] port 60001 never opened -- Cooja failed to start"
  kill "$COOJA_PID" 2>/dev/null || true
  pkill -9 -f "$CSC_KEY" 2>/dev/null || true
  exit 1
fi

# Start tunslip6 OURSELVES, now that 60001 is confirmed open. We are already
# inside the namespace as root (dispatcher did `ip netns exec`), so no external
# keeper is needed. An external keeper's blind 1s retry loop races with Cooja
# startup and systematically fails to connect ("Invalid argument"); launching
# tunslip6 here -- after the port is up -- is what the working manual test does.
# tunslip6 needs net-tools (ifconfig/netstat) to configure tun0. We track the
# exact PID because every worker's tunslip6 cmdline is identical, so a
# pkill-by-name would cross namespaces and kill siblings.
"$REPO/tools/tunslip6" -a 127.0.0.1 -p 60001 fd00::5/64 \
  > "$REPO/tunslip_w${WID}.log" 2>&1 &
TUNSLIP_PID=$!

# Wait for tun0 to come up (created and configured by our tunslip6 above)
for s in $(seq 1 30); do
  if ip link show tun0 >/dev/null 2>&1; then break; fi
  sleep 1
done
if ! ip link show tun0 >/dev/null 2>&1; then
  echo "[w${WID}] tun0 missing -- tunslip6 failed to connect/configure (see tunslip_w${WID}.log)"
  kill "$TUNSLIP_PID" 2>/dev/null || true
  kill "$COOJA_PID" 2>/dev/null || true
  pkill -9 -f "$CSC_KEY" 2>/dev/null || true
  exit 1
fi

# Per-worker UDP listener (binds inside namespace, writes directly to RUN_LOG
# with a metadata header so the log self-documents the scenario).
META="attack=${ATTACK} nodes=${TOTAL_NODES} placement=${PLACEMENT} atkcount=${ATKCOUNT} seed=${SEED} radioseed=${RADIO_SEED:-123456} worker=${WID} csc=${CSC_VERSION} attackers=${ATTACKER_SET// /,}"
python3 -u udp_listener_ipv6.py "$REPO/$RUN_LOG" "$META" >/dev/null 2>&1 &
LISTENER_PID=$!

wait "$COOJA_PID" || true
pkill -9 -f "$CSC_KEY" 2>/dev/null || true   # reap Cooja java ($COOJA_PID is only the subshell)
kill "$TUNSLIP_PID" 2>/dev/null || true       # stop our tunslip6 (tun0 disappears with it)
kill "$LISTENER_PID" 2>/dev/null || true
sleep 2

rm -f "$VARIANT_CSC"

if [[ -s "$REPO/$RUN_LOG" ]]; then
  LINES=$(wc -l < "$REPO/$RUN_LOG")
  echo "[w${WID}] captured $LINES rows -> $RUN_LOG"
  # Sanity-validate the log; on failure, delete and exit non-zero so the
  # dispatcher will requeue this spec.
  if python3 "$REPO/validate_run_log.py" "$REPO/$RUN_LOG" "$SCALE" "$VALIDATE_MODE"; then
    sleep 3; exit 0
  elif [[ "${KEEP_INVALID:-0}" == "1" ]]; then
    # Recovery mode: under some radio seeds the attack window shifts
    # deterministically (late start, or no start at all). The log is not corrupt,
    # only its timing falls outside the expected interval; KEEP_INVALID=1 keeps it
    # and the analysis reports the case separately.
    echo "[w${WID}] validation FAILED but KEEP_INVALID=1 -> log saklaniyor: $RUN_LOG"
    sleep 3; exit 0
  else
    echo "[w${WID}] validation FAILED, deleting $RUN_LOG (+pcap) for retry"
    rm -f "$REPO/$RUN_LOG" "$PCAP_PATH"
    sleep 3; exit 1
  fi
else
  echo "[w${WID}] WARNING: no telemetry captured ($RUN_LOG missing/empty)"
  rm -f "$REPO/$RUN_LOG" "$PCAP_PATH"
  sleep 3; exit 1
fi
