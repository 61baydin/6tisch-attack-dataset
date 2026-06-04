#!/usr/bin/env bash
# Per-namespace tunslip6 keeper. Run with sudo, one process per worker.
# Reconnects to Cooja's SerialSocketServer (loopback:60001) every time the
# Cooja process restarts within the namespace. Inside its namespace, tun0
# carries the 6LoWPAN fd00::/64 prefix exactly as the single-worker setup.
#
# Usage:
#   sudo bash tunslip6_keeper_ns.sh <worker_id>     # 0..3
#
# Keep running in the background (tmux pane) until you teardown.
set -euo pipefail

WID="${1:?worker id (0..3) required}"
NS="cooja_w${WID}"
REPO="$(cd "$(dirname "$0")" && pwd)"
TUNSLIP="${REPO}/tools/tunslip6"

if [[ $EUID -ne 0 ]]; then
  echo "error: run with sudo" >&2; exit 1
fi
if ! ip netns list | awk '{print $1}' | grep -qx "$NS"; then
  echo "error: namespace ${NS} missing. Run setup_parallel_workers.sh first." >&2
  exit 1
fi
if [[ ! -x "$TUNSLIP" ]]; then
  echo "error: ${TUNSLIP} not built. Run: make -C ${REPO}/tools tunslip6" >&2
  exit 1
fi

echo "[keeper-${WID}] entering ${NS}, looping tunslip6 connect to 127.0.0.1:60001"
while true; do
  # Inside the namespace, lo is private; connect to namespace's own loopback.
  ip netns exec "$NS" "$TUNSLIP" -a 127.0.0.1 -p 60001 fd00::5/64 \
    > "${REPO}/keeper_w${WID}.log" 2>&1 || true
  # tunslip6 exits when Cooja socket closes; wait briefly and reconnect.
  sleep 1
done
