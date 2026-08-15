#!/usr/bin/env python3
"""Offline evaluator for the P2 campaign (plan v2).

Usage: p2-eval.py <scenario> <direction> <run-dir>

Expectations come exclusively from scripts/p2-cellplan.json (pre-registered before the runs; the
calibration only fixed receiver string formats). The evaluator is fail-closed: missing or empty
evidence makes the run invalid instead of shrinking the denominator. Beyond the P1 evaluator it
keeps capture timestamps, decodes the FRAG option (identification, offsets, RDOS) straight from
the surplus area of captured fragments, and re-checks per packet that it would pass the path's
legacy checksum gate (finding P1-A): pass iff the UDP checksum field is zero or the one's
complement sum over pseudo header (IP-derived length) plus the entire IP payload folds to 0xffff.
"""

import json
import re
import struct
import sys
from pathlib import Path

ATTEMPT = re.compile(r"^attempt class=(\w+) seq=(\d+) payload=(\d+) rc=(\d+)$")
LINK_HEADER_LEN = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}
CELLPLAN = Path(__file__).with_name("p2-cellplan.json")


def fail(msg):
    print(f"UNGUELTIGER LAUF: {msg}", file=sys.stderr)
    sys.exit(64)


def ones_complement_ok(chunks):
    """True iff the 16-bit one's complement sum over all byte chunks folds to 0xffff."""
    total = 0
    for chunk in chunks:
        if len(chunk) % 2:
            chunk = chunk + b"\x00"
        for i in range(0, len(chunk), 2):
            total += (chunk[i] << 8) | chunk[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def parse_frag_tlv(surplus, payload_len):
    """Returns the FRAG option decoded from a surplus area, or None."""
    at = (payload_len % 2) + 2  # optional alignment pad byte, then the 2-byte OCS
    while at < len(surplus):
        kind = surplus[at]
        if kind == 0:
            return None
        if kind == 1:
            at += 1
            continue
        if at + 2 > len(surplus):
            return None
        length = surplus[at + 1]
        if kind == 3 and length in (10, 12) and at + length <= len(surplus):
            start, ident, offset = struct.unpack("!HIH", surplus[at + 2:at + 10])
            rdos = struct.unpack("!H", surplus[at + 10:at + 12])[0] if length == 12 else None
            return dict(start=start, id=ident, offset=offset, rdos=rdos, terminal=length == 12)
        if length == 255 or length < 2:
            return None  # extended or malformed: nothing past here is FRAG in our traffic
        at += length
    return None


def pcap_packets(path, ports):
    """Yields one dict per captured IPv4/UDP packet on the given destination ports."""
    if not path.exists() or path.stat().st_size < 24:
        fail(f"Capture fehlt oder leer: {path}")
    data = path.read_bytes()
    endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    header_len = LINK_HEADER_LEN[linktype]
    offset = 24
    while offset + 16 <= len(data):
        ts_sec, ts_sub, incl, orig = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        packet = data[offset:offset + incl]
        offset += incl
        if incl != orig:
            fail(f"abgeschnittener Frame in {path.name} (incl {incl} != orig {orig})")
        ip = packet[header_len:]
        if len(ip) < 20 or (ip[0] >> 4) != 4:
            continue
        if struct.unpack("!H", ip[6:8])[0] & 0x1FFF:
            continue  # non-first IPv4 fragment
        ihl = (ip[0] & 0x0F) * 4
        ip_total = struct.unpack("!H", ip[2:4])[0]
        ip_payload = ip[ihl:ip_total]
        udp = ip_payload
        if len(udp) < 8:
            continue
        dst_port = struct.unpack("!H", udp[2:4])[0]
        if dst_port not in ports:
            continue
        udp_len = struct.unpack("!H", udp[4:6])[0]
        udp_cksum = struct.unpack("!H", udp[6:8])[0]
        body = udp[8:udp_len]
        seq = struct.unpack("!Q", body[:8])[0] if udp_len >= 16 and len(body) >= 8 else None
        surplus = ip_payload[udp_len:]
        frag = parse_frag_tlv(surplus, udp_len - 8) if udp_len == 8 and surplus else None
        pseudo = ip[12:20] + bytes([0, 17]) + struct.pack("!H", len(ip_payload))
        gate = udp_cksum == 0 or ones_complement_ok([pseudo, ip_payload])
        yield dict(ts=ts_sec + ts_sub / 1e6, seq=seq, udp_len=udp_len, frag=frag,
                   gate=gate, surplus_len=len(surplus))


def read_attempts(path):
    if not path.exists():
        fail(f"send.log fehlt: {path}")
    out = []
    for line in path.read_text().splitlines():
        match = ATTEMPT.match(line.strip())
        if match:
            out.append((match[1], int(match[2]), int(match[3]), int(match[4])))
    if not out:
        fail(f"send.log ohne attempt-Zeilen: {path}")
    return out


def read_rows(path):
    if not path.exists():
        fail(f"JSONL fehlt: {path}")
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def row_seq(row):
    payload_hex = row.get("payload_hex", "")
    return int(payload_hex[:16], 16) if len(payload_hex) >= 16 else None


def fill_of(row):
    """The fill byte as two hex digits if the payload repeats one byte, else None."""
    payload_hex = row.get("payload_hex", "")
    if len(payload_hex) >= 4 and payload_hex == payload_hex[:2] * (len(payload_hex) // 2):
        return payload_hex[:2]
    return None


def gate_summary(packets, seqs=None, frag_ids=None):
    """(count, gate_failures) over packets matched by seq set or FRAG id set."""
    hits = [p for p in packets
            if (seqs is not None and p["seq"] in seqs)
            or (frag_ids is not None and p["frag"] and p["frag"]["id"] in frag_ids)]
    return len(hits), sum(1 for p in hits if not p["gate"])


def load_cellplan(scenario):
    plan = json.loads(CELLPLAN.read_text())
    if scenario not in plan:
        fail(f"Zellplan ohne Szenario {scenario}")
    return plan[scenario]


# --- p2opt ---------------------------------------------------------------------------------------

def eval_p2opt(out, attempts, egress, ingress, rows):
    plan = load_cellplan("p2opt")["classes"]
    delivered = [row for row in rows if row.get("delivery") == "payload"]
    by_seq = {}
    for row in delivered:
        seq = row_seq(row)
        if seq is not None:
            by_seq.setdefault(seq, []).append(row)

    print(f"\n## {out.name}\n")
    print("| Klasse | Etikett | Versuche | Egress (Gate-Fehler) | Ingress | Zugestellt | Urteil |")
    print("|---|---|---|---|---|---|---|")
    findings = []
    for cls, spec in plan.items():
        seqs = {seq for klass, seq, _, _ in attempts if klass == cls}
        errors = sum(1 for klass, _, _, rc in attempts if klass == cls and rc != 0)
        eg, eg_gate = gate_summary(egress, seqs=seqs)
        ing, _ = gate_summary(ingress, seqs=seqs)
        got = [row for seq in sorted(seqs) for row in by_seq.get(seq, [])]

        problems = []
        if errors:
            problems.append(f"{errors} Senderfehler")
        if eg == 0:
            problems.append("keine Egress-Evidenz")
        if eg_gate:
            problems.append(f"{eg_gate} Pakete wuerden am Pfad-Gate scheitern")
        if len(got) != spec["n"]:
            problems.append(f"{len(got)} statt {spec['n']} zugestellt")
        if got:
            row = got[0]
            options, ocs, reports = row.get("options", ""), row.get("ocs_reports", ""), row.get("reports", "")
            if "options" in spec and options != spec["options"]:
                problems.append(f"options='{options}' statt '{spec['options']}'")
            for needle in spec.get("options_contains", []):
                if needle not in options:
                    problems.append(f"options ohne '{needle}'")
            if ocs != spec["ocs"]:
                problems.append(f"ocs='{ocs}' statt '{spec['ocs']}'")
            for needle in spec["reports"]:
                if needle not in reports:
                    problems.append(f"report '{needle}' fehlt (ist '{reports}')")
            if not spec["reports"] and reports:
                problems.append(f"unerwartete reports '{reports}'")
            for needle in spec.get("absent_reports", []):
                if needle in reports:
                    problems.append(f"unerwarteter report '{needle}'")
            if row.get("payload_len") != spec["paylen"]:
                problems.append(f"payload_len={row.get('payload_len')} statt {spec['paylen']}")
        verdict = "konform" if not problems else "ABWEICHUNG: " + "; ".join(problems)
        if problems:
            findings.append(f"{spec['label']}: {verdict}")
        print(f"| {spec['label']} | {spec['etikett']} | {len(seqs)} | {eg} ({eg_gate}) | {ing} "
              f"| {len(got)} | {verdict} |")

    print()
    print(f"- Summen: Versuche {len(attempts)}, zugestellte Zeilen {len(delivered)}")
    print(f"- Abweichungen gegenueber dem Zellplan: {len(findings)}")
    for finding in findings:
        print(f"  - {finding}")


# --- p2frag --------------------------------------------------------------------------------------

def eval_p2frag(out, attempts, egress, ingress, rows):
    plan = load_cellplan("p2frag")
    delivered = [row for row in rows if row.get("delivery") == "payload"]
    buffered = sum(1 for row in rows if row.get("delivery") == "buffered")
    dropped = sum(1 for row in rows if row.get("delivery") == "dropped")
    by_seq = {}
    for row in delivered:
        seq = row_seq(row)
        if seq is not None:
            by_seq.setdefault(seq, []).append(row)

    print(f"\n## {out.name}\n")
    print("| Zelle | Etikett | Egress (Gate-Fehler) | Ingress | zugestellt | erwartet | Urteil |")
    print("|---|---|---|---|---|---|---|")
    findings = []

    def report(label, etikett, eg, eg_gate, ing, got, want, problems):
        verdict = "konform" if not problems else "ABWEICHUNG: " + "; ".join(problems)
        if problems:
            findings.append(f"{label}: {verdict}")
        print(f"| {label} | {etikett} | {eg} ({eg_gate}) | {ing} | {got} | {want} | {verdict} |")

    # S-19: six atomic terminal fragments, delivered byte-intact.
    spec = plan["s19"]
    seqs = set(range(spec["seq"], spec["seq"] + spec["n"]))
    ids = set(range(spec["ids"][0], spec["ids"][1] + 1))
    eg, eg_gate = gate_summary(egress, frag_ids=ids)
    ing, _ = gate_summary(ingress, frag_ids=ids)
    got = [row for seq in sorted(seqs) for row in by_seq.get(seq, [])]
    problems = []
    if eg != spec["n"] or eg_gate:
        problems.append(f"Egress {eg} (Gate-Fehler {eg_gate}) statt {spec['n']}")
    if len(got) != spec["delivered"]:
        problems.append(f"{len(got)} statt {spec['delivered']} zugestellt")
    for row in got:
        if row.get("payload_len") != spec["paylen"]:
            problems.append(f"payload_len={row.get('payload_len')}")
        if spec["ocs_contains"] not in row.get("ocs_reports", ""):
            problems.append(f"ocs='{row.get('ocs_reports')}' ohne '{spec['ocs_contains']}'")
    for packet in egress:
        if packet["frag"] and packet["frag"]["id"] in ids:
            frag = packet["frag"]
            if not (frag["terminal"] and frag["offset"] == 8 and frag["rdos"] == 8 + spec["paylen"]):
                problems.append(f"Fragmentform abweichend: {frag}")
    report(spec["label"], spec["etikett"], eg, eg_gate, ing, len(got), spec["delivered"], problems)

    # S-34: ten undisturbed sends between first fragment and terminal, per group.
    spec = plan["s34"]
    frag_seqs = list(range(spec["frag_seq"], spec["frag_seq"] + spec["groups"]))
    control_rows = {}
    for k in range(spec["groups"]):
        for seq in range(spec["control_seq"] + 10 * k, spec["control_seq"] + 10 * k + spec["controls_per_group"]):
            control_rows[seq] = k
    got_frag = [row for seq in frag_seqs for row in by_seq.get(seq, [])]
    got_ctl = [row for seq in control_rows for row in by_seq.get(seq, [])]
    problems = []
    if len(got_frag) != spec["frag_delivered"]:
        problems.append(f"{len(got_frag)} statt {spec['frag_delivered']} Saetze")
    if len(got_ctl) != spec["control_delivered"]:
        problems.append(f"{len(got_ctl)} statt {spec['control_delivered']} Kontrollen")
    for k, seq in enumerate(frag_seqs):
        frag_row = by_seq.get(seq, [])
        if frag_row:
            frag_index = frag_row[0].get("index", 0)
            late = [s for s, grp in control_rows.items() if grp == k
                    for row in by_seq.get(s, []) if row.get("index", 0) > frag_index]
            if late:
                problems.append(f"Gruppe {k}: {len(late)} Kontrollen NACH dem Satz zugestellt")
    eg, eg_gate = gate_summary(egress, seqs=set(control_rows))
    ing, _ = gate_summary(ingress, seqs=set(control_rows))
    report(spec["label"], spec["etikett"], eg, eg_gate, ing,
           f"{len(got_frag)}+{len(got_ctl)}", f"{spec['frag_delivered']}+{spec['control_delivered']}", problems)

    # S-45: overlap cells, attributed via FRAG ids on the wire and fill bytes in delivered rows.
    fills_delivered = {}
    for row in delivered:
        fill = fill_of(row)
        if fill and row.get("payload_len") == 2000:
            fills_delivered.setdefault(fill, []).append(row)
    for cell, spec in plan["s45"].items():
        ids = set(range(spec["ids"][0], spec["ids"][1] + 1))
        eg, eg_gate = gate_summary(egress, frag_ids=ids)
        ing, _ = gate_summary(ingress, frag_ids=ids)
        fills = [spec["fill"]] if "fill" in spec else [spec["fill_a"], spec["fill_b"]]
        got = [row for fill in fills for row in fills_delivered.get(fill, [])]
        problems = []
        if eg != spec["egress_frags"] or eg_gate:
            problems.append(f"Egress {eg} (Gate-Fehler {eg_gate}) statt {spec['egress_frags']}")
        if ing != eg:
            problems.append(f"Pfadverlust: Ingress {ing} statt {eg}")
        if len(got) != spec["delivered"]:
            problems.append(f"{len(got)} statt {spec['delivered']} zugestellt")
        report(spec["label"], spec["etikett"], eg, eg_gate, ing, len(got), spec["delivered"], problems)

    print()
    print(f"- Empfaengerzeilen: payload {len(delivered)}, buffered {buffered}, dropped {dropped}")
    print(f"- Abweichungen gegenueber dem Zellplan: {len(findings)}")
    for finding in findings:
        print(f"  - {finding}")


# --- p2s50 ---------------------------------------------------------------------------------------

def eval_p2s50(out, direction, egress, ingress, run_dir):
    plan = load_cellplan("p2s50")
    dirbase = 0 if direction.startswith("a") else plan["runs_per_direction"]
    sets_n, limit = plan["sets_per_run"], plan["cache_limit"]

    print(f"\n## {out.name}\n")
    print("| Lauf | Reihenfolge | zugestellte Sets | Vorhersage exakt | Ueberlauf zugestellt "
          "| Kontrollen | Probe (voller Cache) | Terminale < 30 s |")
    print("|---|---|---|---|---|---|---|---|")
    findings = []
    for g in range(plan["runs_per_direction"]):
        r = dirbase + g
        order = "vorwaerts" if g < 3 else "rueckwaerts"
        ids = list(range(plan["id_base"] + plan["id_stride"] * r,
                         plan["id_base"] + plan["id_stride"] * r + sets_n))
        seq0 = plan["seq_base"] + plan["seq_stride"] * r
        control_seqs = set(range(seq0 + sets_n, seq0 + sets_n + plan["controls_per_run"]))
        probe_seq = plan["probe_seq_base"] + r
        rows = read_rows(run_dir / f"recv-r{g}.jsonl")
        delivered = [row for row in rows if row.get("delivery") == "payload"]
        by_seq = {}
        for row in delivered:
            seq = row_seq(row)
            if seq is not None:
                by_seq.setdefault(seq, []).append(row)

        firsts, terminals = {}, {}
        for packet in ingress:
            frag = packet["frag"]
            if not frag or frag["id"] not in set(ids):
                continue
            store = terminals if frag["terminal"] else firsts
            store.setdefault(frag["id"], packet["ts"])
        if len(firsts) != sets_n:
            fail(f"Lauf {r}: {len(firsts)} statt {sets_n} Erstfragmente in der Ingress-Capture")
        predicted = {ident for ident, _ in sorted(firsts.items(), key=lambda kv: kv[1])[:limit]}
        id_of = {seq0 + k: ids[k] for k in range(sets_n)}
        got_ids = {id_of[seq] for seq in by_seq if seq in id_of}
        overflow_got = got_ids - predicted
        controls_got = sum(len(by_seq.get(seq, [])) for seq in control_seqs)
        probe_got = len(by_seq.get(probe_seq, []))
        timing_ok = all(terminals.get(i, 1e18) - firsts[i] < 30 for i in predicted)

        problems = []
        if got_ids != predicted:
            problems.append(f"Zustellmenge != Ingress-Vorhersage ({len(got_ids)} vs {limit})")
        if overflow_got:
            problems.append(f"{len(overflow_got)} Ueberlauf-Sets zugestellt")
        if controls_got != plan["controls_per_run"]:
            problems.append(f"Kontrollen {controls_got}/{plan['controls_per_run']}")
        if probe_got != 1:
            problems.append(f"Probe {probe_got}/1")
        if not timing_ok:
            problems.append("Terminal ausserhalb 30 s")
        if problems:
            findings.append(f"Lauf {r} ({order}): " + "; ".join(problems))
        print(f"| {r} | {order} | {len(got_ids)}/{limit} | {'ja' if got_ids == predicted else 'NEIN'} "
              f"| {len(overflow_got)} | {controls_got}/{plan['controls_per_run']} | {probe_got}/1 "
              f"| {'ja' if timing_ok else 'NEIN'} |")

    egress_frags = sum(1 for p in egress if p["frag"])
    ingress_frags = sum(1 for p in ingress if p["frag"])
    gate_bad = sum(1 for p in egress if not p["gate"])
    print()
    print(f"- Fragmente auf dem Draht: Egress {egress_frags}, Ingress {ingress_frags}; "
          f"Gate-Fehler im Egress: {gate_bad}")
    print(f"- Etikett: {plan['etikett']}; Erwartung: {plan['erwartung']}")
    print(f"- Abweichungen gegenueber dem Zellplan: {len(findings)}")
    for finding in findings:
        print(f"  - {finding}")


def main():
    if len(sys.argv) != 4:
        print(__doc__.strip(), file=sys.stderr)
        return 64
    scenario, direction, run_dir = sys.argv[1], sys.argv[2], Path(sys.argv[3])
    ports = {47101}
    egress = list(pcap_packets(run_dir / "egress.pcap", ports))
    ingress = list(pcap_packets(run_dir / "ingress.pcap", ports))
    if scenario == "p2opt":
        eval_p2opt(run_dir, read_attempts(run_dir / "send.log"), egress, ingress,
                   read_rows(run_dir / "recv.jsonl"))
    elif scenario == "p2frag":
        eval_p2frag(run_dir, read_attempts(run_dir / "send.log"), egress, ingress,
                    read_rows(run_dir / "recv.jsonl"))
    elif scenario == "p2s50":
        eval_p2s50(run_dir, direction, egress, ingress, run_dir)
    else:
        print(f"unknown scenario: {scenario}", file=sys.stderr)
        return 64
    return 0


if __name__ == "__main__":
    sys.exit(main())
