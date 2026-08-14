#!/usr/bin/env python3
"""Offline evaluator for P0 campaign runs (driver scripts/p0-campaign.sh).

Joins the per-attempt send log and manifest against the receiver JSONL and both pcaps and prints
one markdown block per direction. Unlike eval-check.py, loss, duplication and reordering are
measurements here, not failures. Every loss of an unfragmented datagram is localised: sender error
(exit code, e.g. EMSGSIZE or a refused split), lost before the egress capture, lost on the path
(egress but no ingress), or lost after the ingress capture (only this class can implicate the
implementation). RFC 9868 fragments carry UDP Length 8 and their data in the surplus area, so
they expose no sequence number on the wire; fragment wire datagrams are counted separately and
fragmented classes are judged by their delivered reassemblies.

Usage: p0-eval.py <scenario> <direction-name> <direction-dir>
"""

import json
import re
import struct
import sys

DST_PORT = 47101
S36_PORTS = (47101, 47102, 47103)
# Link-layer header sizes; venet0 captures as LINUX_SLL (113), eth0 as EN10MB (1).
_LINK = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}
_MAGICS = {b"\xa1\xb2\xc3\xd4": ">", b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">", b"\x4d\x3c\xb2\xa1": "<"}

SOPT_CLASSES = {
    100: "S-02 even start + REQ",
    200: "S-03 odd start (pad) + REQ",
    300: "S-12 APC payload 0",
    320: "S-12 APC payload 1",
    340: "S-12 APC payload 9",
    360: "S-12 APC payload 64",
    380: "S-12 APC payload 1462",
    400: "S-15 unsolicited RES",
    500: "S-16a MDS announce",
    600: "S-16b plain 1400 after MDS",
    700: "S-17 MRDS 6000/4 announce",
    900: "baseline",
}
SFRAG_CLASSES = {
    100: "S-17a 2900 default limits",
    200: "S-17b 3100 refusal expected",
    300: "S-17c 5000 peer 6008/4",
    400: "S-18 2000 two fragments",
    500: "S-46 reuse first send",
    520: "S-46 reuse after 7s",
    900: "baseline",
}
S36_FRAG_RANGES = {47101: range(0, 10), 47102: range(100, 110), 47103: range(200, 210)}
S36_BASE_RANGES = {47101: range(300, 310), 47102: range(400, 410), 47103: range(500, 510)}

_ATTEMPT = re.compile(r"^attempt class=(\w) seq=(\d+) payload=(\d+)(?: port=(\d+))? rc=(\d+)$")


def die(msg):
    print(f"p0-eval: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def mask_crc(text):
    return re.sub(r"APC:[0-9a-f]{8}", "APC:<crc>", text)


def pcap_packets(path, ports=(DST_PORT,)):
    """Returns [(seq_or_None, ip_total_len, udp_len, dst_port)] for UDP packets to the ports.

    A packet with UDP Length 8 is an RFC 9868 fragment (or empty datagram) and exposes no
    sequence number; IPv4 fragments with a nonzero offset carry no UDP header and are skipped.
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
            if ((pkt[6] << 8) | pkt[7]) & 0x1FFF:  # non-first IPv4 fragment: no UDP header
                continue
            udp = pkt[ihl:total_len]
            if len(udp) < 8:
                continue
            dport = (udp[2] << 8) | udp[3]
            if dport not in ports:
                continue
            udp_len = (udp[4] << 8) | udp[5]
            seq = int.from_bytes(udp[8:16], "big") if udp_len >= 16 else None
            out.append((seq, total_len, udp_len, dport))
    return out


def inversions(seqs):
    return sum(1 for a, b in zip(seqs, seqs[1:]) if b < a)


def load_attempts(path):
    attempts = []  # (class, seq, payload, rc, port_or_None) in send order
    with open(path) as log:
        for line in log:
            m = _ATTEMPT.match(line.strip())
            if m:
                attempts.append(
                    (m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(5)),
                     int(m.group(4)) if m.group(4) else None)
                )
    if not attempts:
        die(f"{path} contains no attempt lines")
    return attempts


def load_rows(path):
    rows = []  # receiver JSONL rows in arrival order, seq added where extractable
    with open(path) as jsonl:
        for line in jsonl:
            row = json.loads(line)
            row["seq"] = int(row["payload_hex"][:16], 16) if len(row.get("payload_hex", "")) >= 16 else None
            rows.append(row)
    return rows


def eval_s14(name, d):
    print(f"\n## s14 {name}\n")
    token = open(f"{d}/token.txt").read().strip()
    p1 = [r for r in load_rows(f"{d}/p1-recv.jsonl") if r.get("delivery") == "payload"]
    p2 = [r for r in load_rows(f"{d}/p2-recv.jsonl") if r.get("delivery") == "payload"]
    reflector = int(open(f"{d}/p1-reflector-count.txt").read().strip() or 0)
    req_opts = sorted({r.get("options", "") for r in p1})
    res_opts = sorted({r.get("options", "") for r in p2})
    res_ok = all(f"RES:{token}" in o for o in res_opts) and bool(res_opts)
    print(f"- Phase 1 (REQ): delivered {len(p1)}/6, options {req_opts}")
    print(f"- Reflektor-Pruefung: {reflector} automatische Antwortpakete im 3s-Fenster (0 erwartet)")
    print(f"- Anwendungsschritt: Token aus JSONL uebernommen: {token}")
    print(f"- Phase 2 (RES): delivered {len(p2)}/6, options {res_opts}, Token-Echo korrekt: {'JA' if res_ok else 'NEIN'}")


def eval_s36(name, d):
    print(f"\n## s36 {name}\n")
    attempts = load_attempts(f"{d}/send.log")
    egress = pcap_packets(f"{d}/egress.pcap", S36_PORTS)
    ingress = pcap_packets(f"{d}/ingress.pcap", S36_PORTS)
    all_ranges = list(S36_FRAG_RANGES.values()) + list(S36_BASE_RANGES.values())
    clean = True
    print("| Port | frag att | frag delivered | baseline delivered | frag wire eg/in | Fremd-Sequenzen |")
    print("|---|---|---|---|---|---|")
    for port in S36_PORTS:
        rows = [r for r in load_rows(f"{d}/recv-{port}.jsonl") if r.get("delivery") == "payload"]
        seqs = [r["seq"] for r in rows if r["seq"] is not None]
        frag_dlv = sum(1 for s in seqs if s in S36_FRAG_RANGES[port])
        base_dlv = sum(1 for s in seqs if s in S36_BASE_RANGES[port])
        own = set(S36_FRAG_RANGES[port]) | set(S36_BASE_RANGES[port])
        foreign = sorted({s for s in seqs if s not in own and any(s in r for r in all_ranges)})
        att = sum(1 for a in attempts if a[4] == port and a[0] == "t")
        frag_eg = sum(1 for s, _, u, p in egress if u == 8 and p == port)
        frag_in = sum(1 for s, _, u, p in ingress if u == 8 and p == port)
        if foreign or frag_dlv != 10 or base_dlv != 10:
            clean = False
        print(f"| {port} | {att} | {frag_dlv}/10 | {base_dlv}/10 | {frag_eg}/{frag_in} | {foreign or 0} |")
    print(
        f"- geteilte Identification 0xAAAA auf allen drei Ports, Trennung ueber das 4-Tupel: "
        f"{'JA, keine Kreuzkontamination' if clean else 'NEIN, siehe Fremd-Sequenzen'}"
    )


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    scenario, name, d = sys.argv[1], sys.argv[2], sys.argv[3]
    if scenario == "s14":
        eval_s14(name, d)
        return 0
    if scenario == "s36":
        eval_s36(name, d)
        return 0

    attempts = load_attempts(f"{d}/send.log")
    rows = load_rows(f"{d}/recv.jsonl")
    egress = pcap_packets(f"{d}/egress.pcap")
    ingress = pcap_packets(f"{d}/ingress.pcap")
    seqmap = {a[1]: a[0] for a in attempts}
    delivered = [r for r in rows if r.get("delivery") == "payload"]

    print(f"\n## {scenario} {name}\n")
    kinds = {}
    for r in rows:
        kinds[r.get("delivery")] = kinds.get(r.get("delivery"), 0) + 1
    print(f"- receiver rows by delivery: {sorted(kinds.items())}")
    frag_eg = sum(1 for s, _, u, _p in egress if u == 8)
    frag_in = sum(1 for s, _, u, _p in ingress if u == 8)
    if frag_eg or frag_in:
        print(f"- fragment wire datagrams (UDP Length 8): egress {frag_eg}, ingress {frag_in}")

    for cls in ("b", "t"):
        att = [a for a in attempts if a[0] == cls]
        if not att:
            continue
        ok = {a[1] for a in att if a[3] == 0}
        errs = {a[1]: a[3] for a in att if a[3] != 0}
        eg = [s for s, _, u, _p in egress if u >= 16 and seqmap.get(s) == cls]
        ing = [s for s, _, u, _p in ingress if u >= 16 and seqmap.get(s) == cls]
        dlv = [r["seq"] for r in delivered if r["seq"] in seqmap and seqmap[r["seq"]] == cls]
        label = {"b": "baseline", "t": "typed"}[cls]
        print(
            f"- **{label}**: attempts {len(att)}, sent ok {len(ok)}, sender errors {len(errs)}, "
            f"egress {len(eg)}, ingress {len(ing)}, delivered {len(dlv)} (seq-bearing wire view; "
            f"fragmented sends appear only in the fragment counter and in delivered)"
        )
        lost_pre = sorted((ok - set(eg)) - {a[1] for a in att if a[2] >= 1000 and scenario in ("sfrag", "s48")})
        print(
            f"  on-path loss {sorted((set(eg) & ok) - set(ing)) or 0}, "
            f"post-capture loss {sorted((set(ing) & ok) - {s for s in dlv}) or 0}, "
            f"pre-egress gap {lost_pre or 0}; wire dups {len(ing) - len(set(ing))}, "
            f"delivered dups {len(dlv) - len(set(dlv))}, reorder inversions {inversions(dlv)}"
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
        dlv_set = {r["seq"] for r in delivered}
        for idx in range(16):
            total = 1460 + 4 * idx
            cells = []
            for base in (0, 1000):
                seqs = [base + idx * 10 + k for k in range(3)]
                att = [a for a in attempts if a[1] in seqs]
                cells.append((sum(1 for a in att if a[3] == 0), len(att), sum(1 for s in seqs if s in dlv_set)))
            print(
                f"| {total} | {cells[0][0]}/{cells[0][1]} | {cells[1][0]}/{cells[1][1]} "
                f"| {cells[0][2]} | {cells[1][2]} |"
            )

    if scenario in ("sopt", "sfrag"):
        classes = SOPT_CLASSES if scenario == "sopt" else SFRAG_CLASSES
        print("\n| Klasse | att | ok | delivered | options | reports | ocs | surplus_len |")
        print("|---|---|---|---|---|---|---|---|")
        for base in sorted(classes):
            span = range(base, base + 20)
            att = [a for a in attempts if a[1] in span]
            ok = sum(1 for a in att if a[3] == 0)
            if scenario == "sopt" and base in (300, 320):
                # payloads 0 and 1 carry no seq: match delivered rows by payload length instead
                pay = 0 if base == 300 else 1
                sel = [r for r in delivered if r["seq"] is None and r["payload_len"] == pay]
            else:
                sel = [r for r in delivered if r["seq"] in span]
            opts = sorted({mask_crc(r.get("options", "")) for r in sel})
            reps = sorted({r.get("reports", "") for r in sel})
            ocs = sorted({r.get("ocs_reports", "") for r in sel})
            slen = sorted({r.get("surplus_len") for r in sel})
            print(
                f"| {classes[base]} | {len(att)} | {ok} | {len(sel)} | {'; '.join(opts)} "
                f"| {'; '.join(reps)} | {'; '.join(ocs)} | {slen} |"
            )

    if scenario == "s30":
        def profile_class(seq):
            return seq % 6 if seq < 100 else (seq - 100 + 3) % 6

        views = {}
        for r in delivered:
            if r["seq"] is None:
                continue
            run = 1 if r["seq"] < 100 else 2
            key = (mask_crc(r.get("options", "")), r.get("reports", ""))
            views.setdefault((run, profile_class(r["seq"])), set()).add(key)
        same = all(views.get((1, c), set()) == views.get((2, c), set()) for c in range(6))
        print(f"- rotation runs behave identically per class: {'JA' if same else 'NEIN'}")
        for c in range(6):
            print(f"  class {c}: {sorted(views.get((1, c), set()))}")

    if scenario == "s47":
        typed = [r["seq"] for r in delivered if r["seq"] is not None and r["seq"] < 100]
        print(f"- duplicate check: 20 doubled sends -> delivered copies {len(typed)} (expected 40, no dedup)")

    if scenario == "s48":
        sent_order = [a[1] for a in attempts if a[0] == "t" and a[1] < 100]
        dlv_order = [r["seq"] for r in delivered if r["seq"] is not None and r["seq"] < 100]
        print(
            f"- shuffle check: sender inversions {inversions(sent_order)}, "
            f"delivered inversions {inversions(dlv_order)} (equal = path preserved the order)"
        )
        for seq in (100, 101):
            sel = [r.get("options", "") for r in delivered if r["seq"] == seq]
            print(f"  MRDS announce seq {seq}: {sel}")
        frag_dlv = [r["seq"] for r in delivered if r["seq"] is not None and 110 <= r["seq"] < 120]
        print(f"  fragmented sends after swapped announces delivered: {sorted(frag_dlv)}")

    if scenario == "s53":
        lens = {}
        for r in delivered:
            if r["seq"] is None:
                continue
            cls = seqmap.get(r["seq"])
            lens.setdefault(cls, set()).add(r["payload_len"])
        print(
            f"- legacy view: payload lengths baseline {sorted(lens.get('b', set()))}, "
            f"typed {sorted(lens.get('t', set()))} (74/64 erwartet: der Altempfaenger sieht nur die "
            f"user data, die surplus area bleibt unsichtbar)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
