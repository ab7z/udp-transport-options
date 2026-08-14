#!/usr/bin/env python3
"""Offline evaluator for P0 campaign runs (scenarios s35/s31, driver scripts/p0-campaign.sh).

Joins the per-attempt send log and manifest against the receiver JSONL and both pcaps and prints
one markdown block per direction. Unlike eval-check.py, loss, duplication and reordering are
measurements here, not failures. Every loss is localised: sender error (exit code, e.g. EMSGSIZE),
lost before the egress capture, lost on the path (egress but no ingress), or lost after the
ingress capture (ingress but no delivery; only this class can implicate the implementation).

Usage: p0-eval.py <s35|s31> <direction-name> <direction-dir>
"""

import json
import re
import struct
import sys

DST_PORT = 47101
# Link-layer header sizes; venet0 captures as LINUX_SLL (113), eth0 as EN10MB (1).
_LINK = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}
_MAGICS = {b"\xa1\xb2\xc3\xd4": ">", b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">", b"\x4d\x3c\xb2\xa1": "<"}


def die(msg):
    print(f"p0-eval: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def pcap_seqs(path):
    """Returns [(seq, ip_total_len)] for UDP packets to DST_PORT carrying an 8-byte sequence.

    IPv4 fragments with a nonzero offset carry no UDP header and are skipped; a fragmented
    datagram is therefore counted once, through its first fragment.
    """
    with open(path, "rb") as capture:
        header = capture.read(24)
        if len(header) < 24:
            die(f"{path}: not a pcap file")
        endian = _MAGICS.get(header[:4])
        if endian is None:
            die(f"{path}: unknown pcap magic {header[:4].hex()}")
        linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
        if linktype not in _LINK:
            die(f"{path}: unhandled linktype {linktype}")
        out = []
        while True:
            record = capture.read(16)
            if not record:
                break
            _, _, caplen, origlen = struct.unpack(endian + "IIII", record)
            frame = capture.read(caplen)
            if caplen != origlen or len(frame) < caplen:
                die(f"{path}: truncated capture record")
            pkt = frame[_LINK[linktype]:]
            if len(pkt) < 28 or pkt[0] >> 4 != 4 or pkt[9] != 17:
                continue
            ihl = (pkt[0] & 0x0F) * 4
            total_len = (pkt[2] << 8) | pkt[3]
            frag_field = (pkt[6] << 8) | pkt[7]
            if frag_field & 0x1FFF:  # non-first IPv4 fragment: no UDP header
                continue
            udp = pkt[ihl:total_len]
            if len(udp) < 16 or (udp[2] << 8) | udp[3] != DST_PORT:
                continue
            out.append((int.from_bytes(udp[8:16], "big"), total_len))
    return out


def classify(scenario, seq):
    if scenario == "s35":
        return "typed" if seq >= 1000 else "baseline"
    return "typed" if seq % 3 == 1 else "baseline"


def inversions(seqs):
    return sum(1 for a, b in zip(seqs, seqs[1:]) if b < a)


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    scenario, name, d = sys.argv[1], sys.argv[2], sys.argv[3]

    attempts = []  # (class, seq, payload, rc)
    pattern = re.compile(r"^attempt class=(\w) seq=(\d+) payload=(\d+) rc=(\d+)$")
    with open(f"{d}/send.log") as log:
        for line in log:
            m = pattern.match(line.strip())
            if m:
                attempts.append((m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))))
    if not attempts:
        die("send.log contains no attempt lines")

    delivered = []  # (seq, class) in arrival order
    with open(f"{d}/recv.jsonl") as jsonl:
        for line in jsonl:
            row = json.loads(line)
            if row.get("delivery") != "payload" or len(row.get("payload_hex", "")) < 16:
                continue
            delivered.append((int(row["payload_hex"][:16], 16), "typed" if row["option_bearing"] else "baseline"))

    egress = pcap_seqs(f"{d}/egress.pcap")
    ingress = pcap_seqs(f"{d}/ingress.pcap")

    print(f"\n## {scenario} {name}\n")
    for cls in ("baseline", "typed"):
        att = [a for a in attempts if a[0] == cls[0]]
        ok = {a[1] for a in att if a[3] == 0}
        errs = {a[1]: a[3] for a in att if a[3] != 0}
        eg = [s for s, _ in egress if classify(scenario, s) == cls]
        ing = [s for s, _ in ingress if classify(scenario, s) == cls]
        dlv = [s for s, c in delivered if c == cls]
        lost_pre_egress = sorted(ok - set(eg))
        lost_on_path = sorted((set(eg) & ok) - set(ing))
        lost_post_capture = sorted((set(ing) & ok) - set(dlv))
        dup_wire = len(ing) - len(set(ing))
        dup_dlv = len(dlv) - len(set(dlv))
        print(
            f"- **{cls}**: attempts {len(att)}, sent ok {len(ok)}, sender errors {len(errs)}, "
            f"egress {len(eg)}, ingress {len(ing)}, delivered {len(dlv)}"
        )
        print(
            f"  lost pre-egress {lost_pre_egress or 0}, on path {lost_on_path or 0}, "
            f"post-capture {lost_post_capture or 0}; wire dups {dup_wire}, delivered dups {dup_dlv}, "
            f"reorder inversions {inversions(dlv)}"
        )
        if errs:
            codes = {}
            for seq, rc in errs.items():
                codes.setdefault(rc, []).append(seq)
            for rc, seqs in sorted(codes.items()):
                print(f"  sender rc={rc}: {len(seqs)} attempts (seq {min(seqs)}..{max(seqs)})")

    if scenario == "s35":
        print("\n| IPv4 total | baseline ok/att | typed ok/att | baseline delivered | typed delivered |")
        print("|---|---|---|---|---|")
        dlv_set = {s for s, _ in delivered}
        for idx in range(16):
            total = 1460 + 4 * idx
            row = []
            for cls, base in (("b", 0), ("t", 1000)):
                seqs = [base + idx * 10 + k for k in range(3)]
                att = [a for a in attempts if a[1] in seqs]
                okc = sum(1 for a in att if a[3] == 0)
                row.append((okc, len(att), sum(1 for s in seqs if s in dlv_set)))
            print(
                f"| {total} | {row[0][0]}/{row[0][1]} | {row[1][0]}/{row[1][1]} "
                f"| {row[0][2]} | {row[1][2]} |"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
