#!/usr/bin/env python3
"""Multi-attack CSC: merges two single-attack base CSCs.
The resulting CSC has 3 attack-related motetypes: normal(#2) + attackA(#3) + attackB(#4).
attackA nodes -> #3, attackB nodes -> #4, remaining clients -> #2, sink(#1) preserved.
A RadioLogger pcap is injected (PCAP_PATH env var, or derived from the stem).

Usage:
  python3 gen_multiattack_csc.py <baseA.csc> <baseB.csc> <out.csc> --a 7,9 --b 14,16
"""
import os, re, sys

def motetype_block(content, ident):
    """Return the <motetype>...</motetype> block containing exp5438#<ident> as (text, span)."""
    for m in re.finditer(r'<motetype>.*?</motetype>', content, re.DOTALL):
        if f'<identifier>{ident}</identifier>' in m.group(0):
            return m.group(0), m.span()
    return None, None

def main():
    if len(sys.argv) < 4:
        sys.stderr.write(__doc__); return 1
    baseA, baseB, out = sys.argv[1], sys.argv[2], sys.argv[3]
    rest = sys.argv[4:]
    aset = bset = ''
    for i, t in enumerate(rest):
        if t == '--a' and i+1 < len(rest): aset = rest[i+1]
        if t == '--b' and i+1 < len(rest): bset = rest[i+1]
    aids = {int(x) for x in aset.split(',') if x.strip()}
    bids = {int(x) for x in bset.split(',') if x.strip()}

    with open(baseA) as f: content = f.read()
    with open(baseB) as f: bcontent = f.read()

    # Take attackB's #3 motetype and renumber it as #4
    bblk, _ = motetype_block(bcontent, 'exp5438#3')
    if not bblk:
        sys.stderr.write("ERROR: attackB CSC has no exp5438#3 motetype\n"); return 1
    bblk4 = bblk.replace('exp5438#3', 'exp5438#4')

    # Insert the #4 block right after where attackA's #3 block ends
    ablk, span = motetype_block(content, 'exp5438#3')
    if not ablk:
        sys.stderr.write("ERROR: attackA CSC has no exp5438#3 motetype\n"); return 1
    content = content[:span[1]] + "\n" + bblk4 + content[span[1]:]

    # Mote assignment: sink(1)->#1 preserved; aids->#3, bids->#4, others->#2
    pat = re.compile(
        r'(<id>(\d+)</id>\s*</interface_config>\s*<motetype_identifier>)exp5438#\d+(</motetype_identifier>)')
    def repl(m):
        mid = int(m.group(2))
        if mid == 1: return m.group(0)
        t = '3' if mid in aids else ('4' if mid in bids else '2')
        return f'{m.group(1)}exp5438#{t}{m.group(3)}'
    content, n = pat.subn(repl, content)

    # pcap RadioLogger
    pcap_path = os.environ.get('PCAP_PATH')
    if not pcap_path:
        stem = os.path.splitext(os.path.basename(out))[0]
        d = os.path.join(os.path.dirname(os.path.abspath(out)), 'pcaps')
        os.makedirs(d, exist_ok=True); pcap_path = os.path.join(d, stem + '.pcap')
    if '__PCAP_PATH__' in content:
        content = content.replace('__PCAP_PATH__', pcap_path)
    else:
        content = re.sub(
            r'[ \t]*<plugin>\s*org\.contikios\.cooja\.plugins\.RadioLogger.*?</plugin>\s*',
            '', content, flags=re.DOTALL)
        rl = ("  <plugin>\n    org.contikios.cooja.plugins.RadioLogger\n"
              "    <plugin_config>\n      <analyzers name=\"6lowpan-pcap\" />\n"
              f"      <pcap_file>{pcap_path}</pcap_file>\n    </plugin_config>\n  </plugin>\n")
        content = content.replace('</simconf>', rl + '</simconf>')

    with open(out, 'w') as f: f.write(content)
    print(f"wrote {out}: A(#3)={sorted(aids)} B(#4)={sorted(bids)} ({n} motes assigned)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
