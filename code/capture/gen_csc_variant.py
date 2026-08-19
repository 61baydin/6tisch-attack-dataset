#!/usr/bin/env python3
"""Generate a CSC variant with a specified attacker mote subset.

Usage:
    python3 gen_csc_variant.py <base.csc> <out.csc> <attacker_id_1> [...attacker_id_N]

Reads the base CSC and rewrites every per-mote motetype_identifier so that
the listed mote IDs use exp5438#3 (attack firmware) and all other client
motes (excluding the server, mote ID 1) use exp5438#2 (normal firmware).
The motetype-definition blocks at the top of the CSC are left untouched.

If the base CSC contains the placeholder __PCAP_PATH__, it is replaced with
a pcap file path derived from the output CSC stem (.../<stem>.pcap under a
'pcaps' subdirectory alongside the output CSC). Override the pcap path by
setting the PCAP_PATH environment variable before invoking this script.
"""
import os
import re
import sys


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 1

    base_path = sys.argv[1]
    out_path = sys.argv[2]
    attackers = {int(x) for x in sys.argv[3:]}
    # Empty attacker set is allowed and produces a baseline CSC where every
    # non-sink mote runs the normal client firmware (exp5438#2).

    with open(base_path) as f:
        content = f.read()

    pattern = re.compile(
        r'(<id>(\d+)</id>\s*</interface_config>\s*<motetype_identifier>)exp5438#\d+(</motetype_identifier>)'
    )

    def repl(match: 're.Match[str]') -> str:
        mote_id = int(match.group(2))
        if mote_id == 1:
            # Server stays on its own mote-type; we never touch it here.
            return match.group(0)
        new_type = '3' if mote_id in attackers else '2'
        return f'{match.group(1)}exp5438#{new_type}{match.group(3)}'

    new_content, n = pattern.subn(repl, content)

    # Sanity: at least the sink + 1 client. Real values are 21 (21-mote scale),
    # 31 (30-mote), 41 (40-mote), etc.
    if n < 2:
        sys.stderr.write(
            f"warning: only {n} mote blocks rewritten (need at least sink + 1 client)\n"
        )

    # --- Cooja radio seed: COOJA_RANDOMSEED overrides <randomseed> if set ---
    # A single radio seed makes every per-cell score a point estimate, so the
    # worker sets this variable per run to generate multi-seed replicas.
    radio_seed = os.environ.get('COOJA_RANDOMSEED')
    if radio_seed:
        new_content, ns = re.subn(r'<randomseed>\s*-?\d+\s*</randomseed>',
                                  f'<randomseed>{int(radio_seed)}</randomseed>',
                                  new_content)
        if ns != 1:
            sys.stderr.write(f"error: <randomseed> replaced {ns} times (expected 1)\n")
            return 1
        print(f'[csc] radio seed -> {radio_seed}')

    # --- pcap: her variant CSC bir RadioLogger+pcap_file iceriyor olsun ---
    pcap_path = os.environ.get('PCAP_PATH')
    if not pcap_path:
        stem = os.path.splitext(os.path.basename(out_path))[0]
        out_dir = os.path.dirname(os.path.abspath(out_path))
        pcap_dir = os.path.join(out_dir, 'pcaps')
        os.makedirs(pcap_dir, exist_ok=True)
        pcap_path = os.path.join(pcap_dir, stem + '.pcap')

    if '__PCAP_PATH__' in new_content:
        # Base CSC zaten yer-tutucu iceriyor: dogrudan degistir.
        new_content = new_content.replace('__PCAP_PATH__', pcap_path)
    else:
        # Yer-tutucu yok: mevcut RadioLogger plugin'ini (varsa) cikar ve
        # pcap yazan tek bir RadioLogger plugin'i </simconf> oncesine ekle.
        new_content = re.sub(
            r'[ \t]*<plugin>\s*org\.contikios\.cooja\.plugins\.RadioLogger.*?</plugin>\s*',
            '', new_content, flags=re.DOTALL)
        radiologger = (
            "  <plugin>\n"
            "    org.contikios.cooja.plugins.RadioLogger\n"
            "    <plugin_config>\n"
            "      <analyzers name=\"6lowpan-pcap\" />\n"
            f"      <pcap_file>{pcap_path}</pcap_file>\n"
            "    </plugin_config>\n"
            "  </plugin>\n"
        )
        new_content = new_content.replace('</simconf>', radiologger + '</simconf>')

    with open(out_path, 'w') as f:
        f.write(new_content)

    print(f"wrote {out_path} with attackers={sorted(attackers)} ({n} mote blocks rewritten)")
    return 0


if __name__ == '__main__':
    sys.exit(main())
