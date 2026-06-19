#!/usr/bin/env bash
# Coklu-saldiri worker: ayni ag'da IKI farkli saldiri tipi es-zamanli.
# attackA dugumleri core havuzdan, attackB dugumleri edge havuzdan (uzamsal ayrim).
# Her tip 2 saldirgan (toplam 4). Cikti log+pcap KENDI-KENDINI ACIKLAYAN isimle.
#
# Calistirma (dispatcher namespace icine sudo'lar):
#   sudo ip netns exec cooja_w0 bash multirun_multiattack.sh 0 blackhole dis 42 31
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(pwd)"
export PATH="/opt/msp430/bin:${PATH:-/usr/sbin:/usr/bin:/sbin:/bin}"

WID="${1:?worker id}"
ATTACK_A="${2:?attackA name}"
ATTACK_B="${3:?attackB name}"
SEED="${4:?seed}"
SCALE="${5:-31}"
NPER=2   # tip basina saldirgan sayisi

# attack adi -> attack_type id (attacker-analyzer.h)
declare -A ATYPE=([blackhole]=1 [decrease]=2 [dis]=3 [flooding]=4 [shared-slot]=5 [slot-exhaustion]=6 [timekeep]=7)
TA="${ATYPE[$ATTACK_A]:?bilinmeyen attackA}"; TB="${ATYPE[$ATTACK_B]:?bilinmeyen attackB}"

case "$SCALE" in
  21) CORE="2 3 4 5 7 8"; EDGE="14 15 16 17 18 19 20 21"; CSC_VERSION="v3";    TOTAL_NODES=21 ;;
  30|31) CORE="2 3 4 5 6 7 8 9 10 11"; EDGE="22 23 24 25 26 27 28 29 30 31"; CSC_VERSION="v3-30"; TOTAL_NODES=31 ;;
  *) echo "scale 21|31"; exit 1 ;;
esac

# attackA core havuzdan, attackB edge havuzdan (deterministik, tohum+worker)
ASET=$(python3 -c "
import random; random.seed($SEED+1000*$WID)
print(','.join(str(x) for x in sorted(random.sample([$(echo $CORE|tr ' ' ,)], $NPER))))")
BSET=$(python3 -c "
import random; random.seed($SEED+1000*$WID+1)
print(','.join(str(x) for x in sorted(random.sample([$(echo $EDGE|tr ' ' ,)], $NPER))))")

BASE_A="examples/tsch/rpl-udp/rpl-border-${ATTACK_A}-${CSC_VERSION}.csc"
BASE_B="examples/tsch/rpl-udp/rpl-border-${ATTACK_B}-${CSC_VERSION}.csc"
[[ -f "$BASE_A" && -f "$BASE_B" ]] || { echo "base CSC eksik: $BASE_A / $BASE_B"; exit 1; }

STAMP="$(date +%Y-%m-%d_%H-%M-%S)"
TAG="multi-${ATTACK_A}+${ATTACK_B}-n${TOTAL_NODES}-s${SEED}-w${WID}"
COOJA_LOG="cooja_${STAMP}_${TAG}.log"
RUN_LOG="${STAMP}_${TAG}.log"
VARIANT_CSC="examples/tsch/rpl-udp/_multi-${ATTACK_A}-${ATTACK_B}-${CSC_VERSION}-w${WID}.csc"
mkdir -p pcaps
PCAP_PATH="$(pwd)/pcaps/${STAMP}_${TAG}.pcap"

echo "[w${WID}] === MULTI: ${ATTACK_A}(#3)=[$ASET] + ${ATTACK_B}(#4)=[$BSET] | n${TOTAL_NODES} seed${SEED} ==="

PCAP_PATH="$PCAP_PATH" python3 gen_multiattack_csc.py "$BASE_A" "$BASE_B" "$VARIANT_CSC" --a "$ASET" --b "$BSET" || {
  echo "[w${WID}] multi-CSC gen failed"; exit 1; }

WDIR="/tmp/cooja_w${WID}"; mkdir -p "$WDIR"
CSC_KEY="$(basename "$VARIANT_CSC")"
pkill -9 -f "$CSC_KEY" 2>/dev/null || true; sleep 1

( cd "$WDIR" && java -mx2048m -jar "$REPO/tools/cooja/dist/cooja.jar" \
    -nogui="$REPO/$VARIANT_CSC" -contiki="$REPO" > "$REPO/$COOJA_LOG" 2>&1 ) &
COOJA_PID=$!

port_up=0
for s in $(seq 1 120); do ss -tln 2>/dev/null | grep -q ':60001 ' && { port_up=1; break; }; sleep 1; done
[[ "$port_up" -ne 1 ]] && { echo "[w${WID}] port 60001 acilmadi"; kill "$COOJA_PID" 2>/dev/null||true; pkill -9 -f "$CSC_KEY" 2>/dev/null||true; exit 1; }

"$REPO/tools/tunslip6" -a 127.0.0.1 -p 60001 fd00::5/64 > "$REPO/tunslip_w${WID}.log" 2>&1 &
TUNSLIP_PID=$!
for s in $(seq 1 30); do ip link show tun0 >/dev/null 2>&1 && break; sleep 1; done
ip link show tun0 >/dev/null 2>&1 || { echo "[w${WID}] tun0 yok"; kill "$TUNSLIP_PID" "$COOJA_PID" 2>/dev/null||true; pkill -9 -f "$CSC_KEY" 2>/dev/null||true; exit 1; }

META="scenario=multiattack attackA=${ATTACK_A}(#3) attackB=${ATTACK_B}(#4) nodes=${TOTAL_NODES} seed=${SEED} worker=${WID} attackers_A=${ASET} attackers_B=${BSET}"
python3 -u udp_listener_ipv6.py "$REPO/$RUN_LOG" "$META" >/dev/null 2>&1 &
LISTENER_PID=$!

wait "$COOJA_PID" || true
pkill -9 -f "$CSC_KEY" 2>/dev/null || true
kill "$TUNSLIP_PID" "$LISTENER_PID" 2>/dev/null || true
sleep 2
rm -f "$VARIANT_CSC"

# Dogrulama: log dolu VE HER IKI saldiri tipi de etiketli satir uretmis olmali
if [[ -s "$REPO/$RUN_LOG" ]]; then
  okboth=$(python3 -c "
import re
RX=re.compile(r\"b'\s*([0-9,\-\s]+)\s*'\")
a=b=n=0
for ln in open('$REPO/$RUN_LOG'):
    m=RX.search(ln)
    if m:
        v=[int(x) for x in m.group(1).split(',') if x.strip()]
        if len(v)==20:
            n+=1
            if v[18]==1 and v[19]==$TA: a+=1
            if v[18]==1 and v[19]==$TB: b+=1
print('OK' if (n>2000 and a>0 and b>0) else f'BAD n={n} A={a} B={b}')
")
  echo "[w${WID}] $okboth -> $RUN_LOG"
  if [[ "$okboth" == OK ]]; then sleep 3; exit 0
  else echo "[w${WID}] validation FAILED (iki saldiri tipi de gerekli), siliniyor"; rm -f "$REPO/$RUN_LOG" "$PCAP_PATH"; sleep 3; exit 1; fi
else
  echo "[w${WID}] log bos"; rm -f "$REPO/$RUN_LOG" "$PCAP_PATH"; sleep 3; exit 1
fi
