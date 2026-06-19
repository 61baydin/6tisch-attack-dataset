#!/usr/bin/env bash
# Reverses setup_parallel_workers.sh: kills any tunslip6 / cooja / udp_listener
# processes spawned inside the namespaces, then removes the namespaces.
#
# Run with sudo:
#   sudo bash teardown_parallel_workers.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "error: run with sudo" >&2; exit 1
fi

NWORKERS=${NWORKERS:-4}

for w in $(seq 0 $((NWORKERS - 1))); do
  ns="cooja_w${w}"
  if ! ip netns list | awk '{print $1}' | grep -qx "$ns"; then
    echo "[teardown] ${ns} not present, skipping"; continue
  fi
  echo "[teardown] killing processes in ${ns}..."
  # List PIDs running inside the namespace and kill them
  for pid in $(ip netns pids "$ns" 2>/dev/null || true); do
    kill -TERM "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in $(ip netns pids "$ns" 2>/dev/null || true); do
    kill -KILL "$pid" 2>/dev/null || true
  done
  echo "[teardown] removing namespace ${ns}"
  ip netns delete "$ns"
done

# Best-effort cleanup of leftover tun devices in host namespace
for i in $(seq 0 $((NWORKERS - 1))); do
  ip link delete "tun${i}" 2>/dev/null || true
done

echo "[teardown] done"
