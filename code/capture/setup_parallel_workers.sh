#!/usr/bin/env bash
# Creates 4 isolated Linux network namespaces (cooja_w0..3) so we can run
# four Cooja instances in parallel without port / tun conflicts. Each
# namespace gets its own loopback, its own tun0 (created by tunslip6 inside
# the namespace), and its own port 60001 / UDP 5678 (loopback-bound).
#
# Run once with sudo before launching the dispatcher:
#   sudo bash setup_parallel_workers.sh
#
# Tear down with:
#   sudo bash teardown_parallel_workers.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run with sudo (need NET_ADMIN to create namespaces and tun devices)" >&2
  exit 1
fi

NWORKERS=${NWORKERS:-4}

for w in $(seq 0 $((NWORKERS - 1))); do
  ns="cooja_w${w}"
  if ip netns list | awk '{print $1}' | grep -qx "$ns"; then
    echo "[setup] namespace ${ns} already exists, skipping"
    continue
  fi
  ip netns add "$ns"
  # Bring up loopback inside the namespace (needed for SerialSocket+tunslip6)
  ip netns exec "$ns" ip link set lo up
  # Pre-create /var/run dirs the keeper expects (some tooling needs them)
  mkdir -p "/var/run/netns" 2>/dev/null || true
  echo "[setup] ${ns} ready"
done

echo
echo "[setup] $NWORKERS namespaces ready. Verify with:"
echo "  ip netns list"
echo
echo "Next steps:"
echo "  1) In each terminal (or via tmux), keep tunslip6 running per worker:"
for w in $(seq 0 $((NWORKERS - 1))); do
  echo "       sudo bash tunslip6_keeper_ns.sh ${w}    # opens tun0 inside cooja_w${w}"
done
echo "  2) Run the dispatcher (non-sudo, it sudo's per worker as needed):"
echo "       bash dispatcher.sh"
