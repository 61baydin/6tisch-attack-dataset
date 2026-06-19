#!/usr/bin/env python3
"""Coklu-saldiri CSC: iki tek-saldiri base CSC'sini birlestirir.
Sonuc CSC'de 3 saldiri-ilgili motetype: normal(#2) + attackA(#3) + attackB(#4).
attackA dugumleri -> #3, attackB dugumleri -> #4, geri kalan client -> #2, sink(#1) korunur.
RadioLogger pcap enjekte edilir (PCAP_PATH env veya stem'den turetilir).

Kullanim:
  python3 gen_multiattack_csc.py <baseA.csc> <baseB.csc> <out.csc> --a 7,9 --b 14,16
"""
import os, re, sys

def motetype_block(content, ident):
    """exp5438#<ident> iceren <motetype>...</motetype> blogunu (metin, span) dondurur."""
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

    # attackB'nin #3 motetype'ini al, #4 olarak yeniden numarala
    bblk, _ = motetype_block(bcontent, 'exp5438#3')
    if not bblk:
        sys.stderr.write("HATA: attackB CSC'sinde exp5438#3 motetype yok\n"); return 1
    bblk4 = bblk.replace('exp5438#3', 'exp5438#4')

    # attackA CSC'sindeki #3 blogunun bittigi yere #4 blogunu ekle
    ablk, span = motetype_block(content, 'exp5438#3')
    if not ablk:
        sys.stderr.write("HATA: attackA CSC'sinde exp5438#3 motetype yok\n"); return 1
    content = content[:span[1]] + "\n" + bblk4 + content[span[1]:]

    # Mote atamasi: sink(1)->#1 korunur; aids->#3, bids->#4, digerleri->#2
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
    print(f"wrote {out}: A(#3)={sorted(aids)} B(#4)={sorted(bids)} ({n} mote atandi)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
