#!/usr/bin/env python3
"""Offline evaluator for the P1 negative campaign.

Usage: p1-eval.py <scenario> <direction> <run-dir>

Reads the sender's per-attempt log, both packet captures and the receiver's JSONL, and reports one
row per scenario class: how far each class travelled (sender, egress, ingress, delivered) and
whether the receiver's verdict matches what RFC 9868 requires. Loss and duplicates are measurements
here, never errors; a class that never reaches the wire is reported as a sender refusal, and a class
that reaches the wire but not the ingress capture is reported as path loss.
"""

import json
import re
import struct
import sys
from pathlib import Path

ATTEMPT = re.compile(r"^attempt class=(\w) seq=(\d+) payload=(\d+) rc=(\d+)$")

LINK_HEADER_LEN = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}

# One entry per class: label, and the receiver verdict RFC 9868 requires.
#   options  - the option list the receiver must report
#   ocs      - the OCS disposition the receiver must report
#   reports  - substrings that must appear in the per-option report list
#   paylen   - the user-data length the receiver must deliver
P1OPT_CLASSES = {
    "a": dict(base=100, label="Kontrolle gerade (REQ, OCS gueltig)",
              options="REQ:deadbeef", ocs="valid:datagram", reports=["REQ:success"], paylen=64),
    "b": dict(base=150, label="Kontrolle ungerade (Pad 00)",
              options="REQ:deadbeef", ocs="valid:datagram", reports=["REQ:success"], paylen=17),
    "c": dict(base=200, label="S-04 Pad ungleich null (OCS kompensiert)",
              options="", ocs="failed:datagram", reports=[], paylen=17),
    "d": dict(base=250, label="S-05 ungueltige OCS (UDP-Pruefsumme 0)",
              options="", ocs="failed:datagram", reports=[], paylen=64),
    "e": dict(base=300, label="S-06 OCS 0 bei lebender Pruefsumme",
              options="", ocs="invalid-zero:datagram", reports=[], paylen=64),
    "f": dict(base=350, label="S-06 OCS 0 bei Pruefsumme 0 (unused)",
              options="REQ:deadbeef", ocs="unused:datagram", reports=["REQ:success"], paylen=64),
    "g": dict(base=400, label="S-06 OCS gueltig bei Pruefsumme 0",
              options="REQ:deadbeef", ocs="valid:datagram", reports=["REQ:success"], paylen=64),
    "h": dict(base=450, label="S-08 Bytes nach EOL",
              options="REQ:deadbeef", ocs="valid:datagram", reports=["REQ:success"], paylen=64),
    "i": dict(base=500, label="S-10 unbekannte SAFE-Option (Kind 20)",
              options="REQ:deadbeef", ocs="valid:datagram",
              reports=["0x14:ignored", "REQ:success"], paylen=64),
    "j": dict(base=550, label="S-11a Laengen-Unterlauf",
              options="", ocs="valid:datagram", reports=[], paylen=64),
    "k": dict(base=600, label="S-11b Laengen-Ueberlauf nach gueltigem REQ",
              options="", ocs="valid:datagram", reports=[], paylen=64),
    "l": dict(base=650, label="S-13 APC mit falscher Pruefsumme",
              options="", ocs="valid:datagram", reports=["APC:failed"], paylen=64),
    "m": dict(base=700, label="S-20 UNSAFE-Option bei vorhandenen Nutzdaten",
              options="", ocs="valid:datagram", reports=["0xc0:failed"], paylen=0),
    "n": dict(base=750, label="S-21 NOP-Flut ueber der DoS-Schwelle",
              options="REQ:deadbeef", ocs="valid:datagram", reports=["REQ:success"], paylen=64),
    "o": dict(base=900, label="Baseline ohne Optionen",
              options="", ocs="absent:datagram", reports=[], paylen=74),
}

# Fragment classes: `delivered` is how many of the six logical sends must be reassembled.
P1FRAG_CLASSES = {
    "a": dict(base=100, label="Kontrolle: beide Fragmente in Reihenfolge", delivered=6),
    "b": dict(base=200, label="S-41 Fragmentverlust (Terminalfragment fehlt)", delivered=0),
    "c": dict(base=300, label="S-43 Fragmentduplikat (erstes Fragment doppelt)", delivered=6),
    "d": dict(base=400, label="S-44 Fragmentumordnung (Terminal zuerst)", delivered=6),
    "e": dict(base=500, label="S-42 Reassembly-Timeout (8s Luecke)", delivered=0),
    "f": dict(base=600, label="S-42 Kontrolle (1s Luecke)", delivered=6),
}


def read_attempts(path):
    """Returns [(class, seq, payload_len, rc)] in send order."""
    out = []
    for line in path.read_text().splitlines():
        match = ATTEMPT.match(line.strip())
        if match:
            out.append((match[1], int(match[2]), int(match[3]), int(match[4])))
    return out


def pcap_packets(path, ports):
    """Yields (seq, udp_len, dst_port) for every captured IPv4/UDP packet on the given ports."""
    data = path.read_bytes()
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
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:  # non-first IPv4 fragment
            continue
        udp = ip[(ip[0] & 0x0F) * 4:]
        if len(udp) < 8:
            continue
        dst_port = struct.unpack("!H", udp[2:4])[0]
        if dst_port not in ports:
            continue
        udp_len = struct.unpack("!H", udp[4:6])[0]
        body = udp[8:]
        seq = struct.unpack("!Q", body[:8])[0] if udp_len >= 16 and len(body) >= 8 else None
        yield seq, udp_len, dst_port


def read_rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def row_seq(row):
    payload_hex = row.get("payload_hex", "")
    return int(payload_hex[:16], 16) if len(payload_hex) >= 16 else None


def verdict_of(row):
    return (row.get("options", ""), row.get("ocs_reports", ""), row.get("reports", ""))


def eval_p1opt(out, attempts, egress, ingress, rows):
    egress_seqs = [seq for seq, _, _ in egress if seq is not None]
    ingress_seqs = [seq for seq, _, _ in ingress if seq is not None]
    delivered = [row for row in rows if row.get("delivery") == "payload"]

    # S-20 delivers empty user data, so its rows carry no sequence and are matched by their report.
    by_seq = {}
    unmatched = []
    for row in delivered:
        seq = row_seq(row)
        if seq is None:
            unmatched.append(row)
        else:
            by_seq.setdefault(seq, []).append(row)

    print(f"\n## {out.name}\n")
    print("| Klasse | Versuche | Senderfehler | Egress | Ingress | Zugestellt | Urteil |")
    print("|---|---|---|---|---|---|---|")
    findings = []
    for cls, spec in P1OPT_CLASSES.items():
        seqs = [seq for klass, seq, _, _ in attempts if klass == cls]
        errors = sum(1 for klass, _, _, rc in attempts if klass == cls and rc != 0)
        eg = sum(1 for seq in egress_seqs if seq in seqs)
        ing = sum(1 for seq in ingress_seqs if seq in seqs)
        if spec["paylen"] == 0:
            got = [row for row in unmatched if any(r in row.get("reports", "") for r in spec["reports"])]
        else:
            got = [row for seq in seqs for row in by_seq.get(seq, [])]

        problems = []
        if got:
            options, ocs, reports = verdict_of(got[0])
            if options != spec["options"]:
                problems.append(f"options='{options}' statt '{spec['options']}'")
            if ocs != spec["ocs"]:
                problems.append(f"ocs='{ocs}' statt '{spec['ocs']}'")
            for needle in spec["reports"]:
                if needle not in reports:
                    problems.append(f"report '{needle}' fehlt (ist '{reports}')")
            if got[0].get("payload_len") != spec["paylen"]:
                problems.append(f"payload_len={got[0].get('payload_len')} statt {spec['paylen']}")
            verdict = "konform" if not problems else "ABWEICHUNG: " + "; ".join(problems)
        elif ing == 0 and eg > 0:
            verdict = "auf dem Pfad verloren (nicht zustellbar, siehe Befund P1-A)"
        elif eg == 0:
            verdict = "Sender hat nichts ausgesendet"
        else:
            verdict = "ABWEICHUNG: angekommen, aber nicht zugestellt"
        if verdict.startswith("ABWEICHUNG"):
            findings.append(f"{spec['label']}: {verdict}")
        print(f"| {spec['label']} | {len(seqs)} | {errors} | {eg} | {ing} | {len(got)} | {verdict} |")

    print()
    print(f"- Summen: Versuche {len(attempts)}, Egress {len(egress_seqs)}, Ingress {len(ingress_seqs)}, "
          f"zugestellte Zeilen {len(delivered)}")
    print(f"- Abweichungen gegenueber der RFC-Erwartung: {len(findings)}")
    for finding in findings:
        print(f"  - {finding}")


def eval_p1frag(out, attempts, egress, ingress, rows):
    # Fragments carry UDP Length 8 and no sequence; count them separately from seq-bearing packets.
    egress_frags = sum(1 for _, udp_len, _ in egress if udp_len == 8)
    ingress_frags = sum(1 for _, udp_len, _ in ingress if udp_len == 8)
    delivered = [row for row in rows if row.get("delivery") == "payload"]
    buffered = [row for row in rows if row.get("delivery") == "buffered"]
    dropped = [row for row in rows if row.get("delivery") == "dropped"]
    by_seq = {}
    for row in delivered:
        seq = row_seq(row)
        if seq is not None:
            by_seq.setdefault(seq, []).append(row)

    print(f"\n## {out.name}\n")
    print("| Klasse | logische Sends | Senderfehler | zugestellt | erwartet | Urteil |")
    print("|---|---|---|---|---|---|")
    findings = []
    for cls, spec in P1FRAG_CLASSES.items():
        seqs = sorted({seq for klass, seq, _, _ in attempts if klass == cls})
        errors = sum(1 for klass, _, _, rc in attempts if klass == cls and rc != 0)
        got = sum(len(by_seq.get(seq, [])) for seq in seqs)
        if got == spec["delivered"]:
            verdict = "konform"
        else:
            verdict = f"ABWEICHUNG: {got} statt {spec['delivered']}"
            findings.append(f"{spec['label']}: {verdict}")
        print(f"| {spec['label']} | {len(seqs)} | {errors} | {got} | {spec['delivered']} | {verdict} |")

    print()
    print(f"- Fragmente auf dem Draht: Egress {egress_frags}, Ingress {ingress_frags} "
          f"(Differenz = Pfadverlust)")
    print(f"- Empfaengerzeilen: payload {len(delivered)}, buffered {len(buffered)}, dropped {len(dropped)}")
    print(f"- Abweichungen gegenueber der RFC-Erwartung: {len(findings)}")
    for finding in findings:
        print(f"  - {finding}")


def main():
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    scenario, _direction, run_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])

    attempts = read_attempts(run_dir / "send.log")
    ports = {47101}
    egress = list(pcap_packets(run_dir / "egress.pcap", ports))
    ingress = list(pcap_packets(run_dir / "ingress.pcap", ports))
    rows = read_rows(run_dir / "recv.jsonl")

    if scenario == "p1opt":
        eval_p1opt(run_dir, attempts, egress, ingress, rows)
    elif scenario == "p1frag":
        eval_p1frag(run_dir, attempts, egress, ingress, rows)
    else:
        print(f"unknown scenario: {scenario}", file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main())
