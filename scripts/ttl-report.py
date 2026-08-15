#!/usr/bin/env python3
"""TTL report over measurement captures (FF2 path characterisation).

Usage: ttl-report.py <pcap> [<pcap>...]

For every IPv4/UDP packet on the measurement ports (47101 data, 47102 reverse filter, 47103
canary) the report collects the IP header TTL, grouped per file into traffic classes: FRAG
fragments (UDP Length 8), normal datagrams, and canary packets. Egress captures (taken on the
sending host) show the TTL as sent; ingress captures (taken on the receiving host) show it after
the path, so the difference between the two is the number of IPv4 routers in between. The parser
is deliberately tiny and self-contained; it was cross-checked against the campaign evaluators.
"""

import struct
import sys
from collections import Counter
from pathlib import Path

LINK_HEADER_LEN = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}
PORTS = {47101, 47102, 47103}


def packets(path):
    data = path.read_bytes()
    if len(data) < 24:
        return
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    header_len = LINK_HEADER_LEN[linktype]
    offset = 24
    while offset + 16 <= len(data):
        _, _, incl, _ = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        packet = data[offset:offset + incl]
        offset += incl
        ip = packet[header_len:]
        if len(ip) < 28 or (ip[0] >> 4) != 4 or ip[9] != 17:
            continue
        if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:
            continue  # non-first IPv4 fragment
        ihl = (ip[0] & 0x0F) * 4
        udp = ip[ihl:]
        if len(udp) < 8:
            continue
        dst_port = struct.unpack("!H", udp[2:4])[0]
        if dst_port not in PORTS:
            continue
        udp_len = struct.unpack("!H", udp[4:6])[0]
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        if dst_port == 47103:
            kind = "canary"
        elif udp_len == 8:
            kind = "frag"
        else:
            kind = "normal"
        yield kind, ip[8], src, dst


def main():
    if len(sys.argv) < 2:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    print("| Datei | Klasse | Pakete | TTL (Anzahl) | Fluss |")
    print("|---|---|---|---|---|")
    for name in sys.argv[1:]:
        path = Path(name)
        ttls = {}
        flows = {}
        for kind, ttl, src, dst in packets(path):
            ttls.setdefault(kind, Counter())[ttl] += 1
            flows.setdefault(kind, set()).add(f"{src}->{dst}")
        if not ttls:
            print(f"| {path} | - | 0 | - | - |")
            continue
        for kind in sorted(ttls):
            counter = ttls[kind]
            dist = ", ".join(f"{ttl}: {n}" for ttl, n in sorted(counter.items()))
            flow = "; ".join(sorted(flows[kind]))
            print(f"| {path} | {kind} | {sum(counter.values())} | {dist} | {flow} |")
    return 0


if __name__ == "__main__":
    sys.exit(main())
