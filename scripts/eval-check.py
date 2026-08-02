#!/usr/bin/env python3
"""Validate and classify the Step 17 FF2/P2 evaluation artifacts."""

from __future__ import annotations

import argparse
import json
import struct
import sys
from collections import Counter, defaultdict
from pathlib import Path

CANARY_PORT = 40999
SCENARIOS = ("baseline", "typed", "pad", "near-mtu", "frag")
NAT_RECEIVER_SOURCE = "10.9.2.254"

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
    b"\x4d\x3c\xb2\xa1": "<",
}

FIXED_TOTAL_LENGTHS = {
    2: {6},
    3: {10, 12},
    4: {4},
    5: {5},
    6: {6},
    7: {6},
}
CANONICAL_RANK = {3: 0, 2: 1, 4: 2, 5: 3, 6: 4, 7: 5}
SCENARIO_OPTIONS: dict[str, list[tuple[int, bytes | None]]] = {
    "typed": [
        (2, None),
        (4, (1472).to_bytes(2, "big")),
        (5, (2926).to_bytes(2, "big") + b"\x02"),
        (6, bytes.fromhex("deadbeef")),
    ],
    "pad": [(6, bytes.fromhex("c0ffee01"))],
    "near-mtu": [(2, None), (4, (1472).to_bytes(2, "big"))],
    "frag": [(3, None)],
}
SCENARIO_PAYLOADS: dict[str, bytes | int] = {
    "baseline": b"plain",
    "typed": b"wire",
    "pad": b"odd",
    "near-mtu": 1392,
    "frag": b"",
}


class CheckError(Exception):
    """An evaluation artifact is malformed or semantically invalid."""


class NotIpv4Udp(Exception):
    """A capture record is not an IPv4 UDP packet."""


def fold16(data: bytes, *extra_words: int) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum((data[index] << 8) | data[index + 1] for index in range(0, len(data), 2))
    total += sum(extra_words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def crc32c(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


def _declared_ipv4(payload: bytes) -> bytes:
    if not payload:
        raise CheckError("missing IPv4 payload after capture link header")
    if payload[0] >> 4 != 4:
        raise CheckError("bad IPv4 version after IPv4 capture link header")
    return payload


def _ipv4_from_frame(frame: bytes, linktype: int) -> bytes | None:
    if linktype == 101:
        if not frame:
            raise CheckError("empty raw-IP capture record")
        return frame if frame[0] >> 4 == 4 else None
    if linktype == 0:
        if len(frame) < 4:
            raise CheckError("truncated DLT_NULL header")
        family_le = int.from_bytes(frame[:4], "little")
        family_be = int.from_bytes(frame[:4], "big")
        return _declared_ipv4(frame[4:]) if 2 in {family_le, family_be} else None
    if linktype == 1:
        if len(frame) < 14:
            raise CheckError("truncated Ethernet header")
        return _declared_ipv4(frame[14:]) if frame[12:14] == b"\x08\x00" else None
    if linktype == 113:
        if len(frame) < 16:
            raise CheckError("truncated Linux cooked-v1 header")
        return _declared_ipv4(frame[16:]) if frame[14:16] == b"\x08\x00" else None
    if linktype == 276:
        if len(frame) < 20:
            raise CheckError("truncated Linux cooked-v2 header")
        return _declared_ipv4(frame[20:]) if frame[:2] == b"\x08\x00" else None
    raise CheckError(f"unsupported pcap linktype {linktype}")


class Packet:
    def __init__(self, raw: bytes):
        if not raw or raw[0] >> 4 != 4:
            raise NotIpv4Udp
        if len(raw) < 20:
            raise CheckError("truncated IPv4 header")
        self.ihl = (raw[0] & 0x0F) * 4
        if self.ihl < 20 or self.ihl > len(raw):
            raise CheckError("bad IPv4 header length")
        self.total_len = int.from_bytes(raw[2:4], "big")
        if self.total_len < self.ihl or self.total_len > len(raw):
            raise CheckError("bad IPv4 total length")
        self.raw = raw[: self.total_len]
        if fold16(self.raw[: self.ihl]) != 0xFFFF:
            raise CheckError("bad IPv4 header checksum")
        if self.raw[9] != 17:
            raise NotIpv4Udp
        if self.total_len < self.ihl + 8:
            raise CheckError("truncated UDP header")
        fragment = int.from_bytes(self.raw[6:8], "big")
        if fragment & 0x3FFF:
            raise CheckError("IPv4 fragments are not supported by this checker")

        udp = self.raw[self.ihl :]
        self.src = ".".join(str(byte) for byte in self.raw[12:16])
        self.dst = ".".join(str(byte) for byte in self.raw[16:20])
        self.src_port = int.from_bytes(udp[:2], "big")
        self.dst_port = int.from_bytes(udp[2:4], "big")
        self.udp_len = int.from_bytes(udp[4:6], "big")
        self.udp_checksum = int.from_bytes(udp[6:8], "big")
        if not 8 <= self.udp_len <= len(udp):
            raise CheckError("bad UDP length")
        if self.udp_checksum:
            pseudo = self.raw[12:20] + b"\x00\x11" + self.udp_len.to_bytes(2, "big")
            if fold16(pseudo + udp[: self.udp_len]) != 0xFFFF:
                raise CheckError("bad UDP checksum")
        self.user_data = udp[8 : self.udp_len]
        self.surplus = udp[self.udp_len :]


def read_pcap(path: str | Path) -> list[Packet]:
    path = str(path)
    try:
        capture = open(path, "rb")
    except OSError as error:
        raise CheckError(f"{path}: {error}") from error
    with capture:
        header = capture.read(24)
        if len(header) < 24:
            raise CheckError(f"{path}: short pcap header")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise CheckError(f"{path}: pcapng is not supported; use tcpdump -w classic pcap")
        endian = PCAP_MAGICS.get(header[:4])
        if endian is None:
            raise CheckError(f"{path}: unknown pcap magic {header[:4].hex()}")
        linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
        if linktype not in {0, 1, 101, 113, 276}:
            raise CheckError(f"{path}: unsupported pcap linktype {linktype}")

        packets: list[Packet] = []
        record_number = 0
        while True:
            record = capture.read(16)
            if not record:
                break
            record_number += 1
            if len(record) < 16:
                raise CheckError(f"{path}: truncated pcap record {record_number}")
            _, _, caplen, origlen = struct.unpack(endian + "IIII", record)
            frame = capture.read(caplen)
            if len(frame) < caplen:
                raise CheckError(f"{path}: truncated pcap packet {record_number}")
            if caplen != origlen:
                raise CheckError(f"{path}: snaplen truncated packet {record_number}: {caplen} < {origlen}")
            try:
                ipv4 = _ipv4_from_frame(frame, linktype)
                if ipv4 is None:
                    continue
                packets.append(Packet(ipv4))
            except NotIpv4Udp:
                continue
            except CheckError as error:
                raise CheckError(f"{path}: packet {record_number}: {error}") from error
        return packets


def by_port(packets: list[Packet], lo: int, hi: int) -> dict[int, list[Packet]]:
    grouped: dict[int, list[Packet]] = defaultdict(list)
    for packet in packets:
        if packet.dst_port == CANARY_PORT:
            continue
        if lo <= packet.dst_port <= hi:
            grouped[packet.dst_port].append(packet)
    return grouped


def _parse_option(region: bytes, offset: int, limit: int) -> tuple[int, int, bytes]:
    kind = region[offset]
    if kind in {0, 1}:
        return kind, 1, b""
    if offset + 2 > limit:
        raise CheckError("truncated TLV header")
    if region[offset + 1] == 255:
        if offset + 4 > limit:
            raise CheckError("truncated extended TLV header")
        total_len = int.from_bytes(region[offset + 2 : offset + 4], "big")
        header_len = 4
        if total_len < 255:
            raise CheckError("non-canonical extended TLV length")
    else:
        total_len = region[offset + 1]
        header_len = 2
        if total_len < 2:
            raise CheckError("invalid TLV length")
    if offset + total_len > limit:
        raise CheckError("TLV overruns option area")
    return kind, total_len, region[offset + header_len : offset + total_len]


def _validate_surplus(packet: Packet) -> tuple[list[tuple[int, int, bytes]], dict[str, object] | None]:
    surplus = packet.surplus
    pad_len = 1 if (packet.ihl + packet.udp_len) % 2 else 0
    if len(surplus) < pad_len + 2:
        raise CheckError("surplus too short for aligned OCS")
    if pad_len and surplus[0] != 0:
        raise CheckError("non-zero odd-start pad")

    body = surplus[pad_len:]
    stored_ocs = int.from_bytes(body[:2], "big")
    if stored_ocs == 0:
        if packet.udp_checksum != 0:
            raise CheckError("zero OCS with a non-zero UDP checksum")
    else:
        derived = (~fold16(b"\x00\x00" + body[2:], len(surplus))) & 0xFFFF
        expected = 0xFFFF if derived == 0 else derived
        if stored_ocs != expected:
            raise CheckError("bad OCS")

    region = body[2:]
    if not region:
        return [], None
    limit = len(region)
    offset = 0
    eol_end: int | None = None
    options: list[tuple[int, int, bytes]] = []
    frag: dict[str, object] | None = None
    consecutive_nops = 0
    while offset < limit:
        kind, total_len, value = _parse_option(region, offset, limit)
        if kind == 0:
            eol_end = offset + 1
            break
        if kind == 1:
            consecutive_nops += 1
            if consecutive_nops > 7:
                raise CheckError("more than seven consecutive NOPs")
        else:
            consecutive_nops = 0
            if kind in FIXED_TOTAL_LENGTHS and total_len not in FIXED_TOTAL_LENGTHS[kind]:
                raise CheckError(f"option kind {kind} has invalid total length {total_len}")
            options.append((kind, total_len, value))
            if kind == 3:
                if frag is not None:
                    raise CheckError("multiple FRAG options in one datagram")
                frag_start = int.from_bytes(value[:2], "big")
                data_start = frag_start - packet.udp_len - pad_len - 2
                option_end = offset + total_len
                if data_start < option_end or data_start > len(region):
                    raise CheckError("FRAG start does not point behind its option area")
                limit = data_start
                frag = {
                    "identification": int.from_bytes(value[2:6], "big"),
                    "offset": int.from_bytes(value[6:8], "big"),
                    "rdos": int.from_bytes(value[8:10], "big") if total_len == 12 else None,
                    "data_start": data_start,
                }
        offset += total_len

    if eol_end is None:
        if offset != limit:
            raise CheckError("unterminated option area")
        eol_end = limit
    if any(region[eol_end:limit]):
        raise CheckError("non-zero bytes after EOL")

    substantive = [kind for kind, _, _ in options]
    ranks = [CANONICAL_RANK.get(kind, 6 + kind) for kind in substantive]
    if ranks != sorted(ranks):
        raise CheckError("options are not in canonical sender order")
    for kind in FIXED_TOTAL_LENGTHS:
        if substantive.count(kind) > 1:
            raise CheckError(f"duplicate must-support option kind {kind}")

    for kind, _, value in options:
        if kind == 2 and int.from_bytes(value, "big") != crc32c(packet.user_data):
            raise CheckError("APC does not match UDP user data")

    if frag is None:
        return options, None
    if packet.udp_len != 8 or packet.user_data:
        raise CheckError("FRAG used with non-empty UDP user data")
    if not substantive or substantive[0] != 3:
        raise CheckError("FRAG is not the first substantive option")
    data_start = int(frag["data_start"])
    data = region[data_start:]
    frag["data"] = data
    return options, frag


def _validate_scenario_contract(
    port: int,
    scenario: str,
    packets: list[Packet],
    parsed: list[tuple[list[tuple[int, int, bytes]], dict[str, object] | None]],
) -> None:
    expected_payload = SCENARIO_PAYLOADS[scenario]
    for index, packet in enumerate(packets, 1):
        payload_matches = (
            len(packet.user_data) == expected_payload
            if isinstance(expected_payload, int)
            else packet.user_data == expected_payload
        )
        if not payload_matches:
            raise CheckError(f"sender port {port}, packet {index}: payload does not match {scenario} scenario")

    if scenario == "baseline":
        if any(packet.surplus for packet in packets):
            raise CheckError(f"sender port {port}: baseline scenario unexpectedly carries surplus bytes")
        return
    if any(not packet.surplus for packet in packets):
        raise CheckError(f"sender port {port}: {scenario} scenario is missing its surplus area")

    expected_options = SCENARIO_OPTIONS[scenario]
    for index, (options, _) in enumerate(parsed, 1):
        kinds = [kind for kind, _, _ in options]
        expected_kinds = [kind for kind, _ in expected_options]
        if kinds != expected_kinds:
            raise CheckError(
                f"sender port {port}, packet {index}: {scenario} option kinds {kinds} != {expected_kinds}"
            )
        for (kind, _, value), (_, expected_value) in zip(options, expected_options):
            if expected_value is not None and value != expected_value:
                raise CheckError(f"sender port {port}, packet {index}: option kind {kind} has the wrong value")


def validate_sender_groups(
    grouped: dict[int, list[Packet]],
    expect_surplus_ports: set[int],
    scenario_by_port: dict[int, str] | None = None,
) -> dict[int, int]:
    scenario_by_port = scenario_by_port or {}
    fragment_identifications: dict[int, int] = {}
    for port, packets in grouped.items():
        parsed: list[tuple[list[tuple[int, int, bytes]], dict[str, object] | None]] = []
        fragments: list[dict[str, object]] = []
        for index, packet in enumerate(packets, 1):
            if packet.surplus:
                try:
                    options, fragment = _validate_surplus(packet)
                except CheckError as error:
                    raise CheckError(f"sender port {port}, packet {index}: {error}") from error
                parsed.append((options, fragment))
                if fragment is not None:
                    fragments.append(fragment)
            else:
                parsed.append(([], None))
        scenario = scenario_by_port.get(port)
        if scenario is not None:
            _validate_scenario_contract(port, scenario, packets, parsed)
        if port in expect_surplus_ports and packets and any(not packet.surplus for packet in packets):
            continue
        if not fragments:
            continue
        if len(fragments) != len(packets):
            raise CheckError(f"sender port {port}: FRAG and non-FRAG packets are mixed")
        identifiers = {int(fragment["identification"]) for fragment in fragments}
        if len(identifiers) != 1:
            raise CheckError(f"sender port {port}: FRAG Identification changed within one sequence")
        fragment_identifications[port] = next(iter(identifiers))
        ordered = sorted(fragments, key=lambda fragment: int(fragment["offset"]))
        terminals = [fragment for fragment in ordered if fragment["rdos"] is not None]
        if len(terminals) != 1 or terminals[0] is not ordered[-1]:
            raise CheckError(f"sender port {port}: FRAG sequence needs one final terminal fragment")
        if len(ordered) > 1:
            cursor = 8
            for fragment in ordered:
                offset = int(fragment["offset"])
                if offset != cursor:
                    raise CheckError(f"sender port {port}: FRAG sequence has a gap or overlap at offset {offset}")
                cursor += len(bytes(fragment["data"]))
            if int(ordered[-1]["rdos"]) != cursor:
                raise CheckError(f"sender port {port}: terminal FRAG RDOS does not match reconstructed size")
        else:
            only = ordered[0]
            expected_rdos = 8 + len(bytes(only["data"]))
            if int(only["offset"]) != 0 or int(only["rdos"]) != expected_rdos:
                raise CheckError(f"sender port {port}: invalid atomic FRAG geometry")
    return fragment_identifications


def validate_nat_observation(receiver: dict[int, list[Packet]]) -> None:
    packets = [packet for copies in receiver.values() for packet in copies]
    if packets and any(packet.src != NAT_RECEIVER_SOURCE for packet in packets):
        sources = sorted({packet.src for packet in packets})
        raise CheckError(
            f"NAT receiver packets did not use masquerade source {NAT_RECEIVER_SOURCE}: observed {sources}"
        )


def classify(sender: list[Packet], receiver: list[Packet], expect_sender_surplus: bool) -> str:
    if not sender:
        return "never-captured"
    if expect_sender_surplus and any(not packet.surplus for packet in sender):
        return "sender-surplus-missing"
    if not receiver:
        return "dropped"
    sender_surplus = Counter(packet.surplus for packet in sender)
    receiver_surplus = Counter(packet.surplus for packet in receiver)
    if sender_surplus == receiver_surplus:
        return "intact"
    if len(sender) != len(receiver):
        return "packet-count-mismatch"
    if (
        any(packet.surplus for packet in sender)
        and all(not packet.surplus for packet in receiver)
        and all(packet.total_len == packet.ihl + packet.udp_len for packet in receiver)
    ):
        return "surplus-stripped"
    return "modified"


def _reject_json_constant(value: str) -> None:
    raise ValueError(value)


def _read_jsonl(path: Path, *, allow_empty: bool) -> list[dict[str, object]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise CheckError(f"{path}: {error}") from error
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            raise CheckError(f"{path}:{line_number}: blank JSONL record")
        try:
            record = json.loads(line, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError) as error:
            message = error.msg if isinstance(error, json.JSONDecodeError) else str(error)
            raise CheckError(f"{path}:{line_number}: invalid JSON: {message}") from error
        if not isinstance(record, dict):
            raise CheckError(f"{path}:{line_number}: JSONL record is not an object")
        records.append(record)
    if not records and not allow_empty:
        raise CheckError(f"{path}: expected at least one JSONL record")
    return records


def _uint(record: dict[str, object], field: str, *, maximum: int = 0xFFFFFFFF) -> int:
    value = record.get(field)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise CheckError(f"field {field!r} is not an unsigned integer")
    return value


def validate_artifact_pair(
    manifest_path: Path,
    receiver_path: Path,
    *,
    require_delivery: bool,
    forbid_receiver_records: bool = False,
    scenario: str | None = None,
    expected_identification: int | None = None,
    expected_datagrams: int | None = None,
) -> dict[str, int]:
    manifests = _read_jsonl(manifest_path, allow_empty=False)
    if scenario is not None and len(manifests) != 1:
        raise CheckError(f"{manifest_path}: {scenario} scenario requires exactly one manifest record")
    expected: Counter[tuple[int, int]] = Counter()
    for record_number, record in enumerate(manifests, 1):
        try:
            key = (_uint(record, "payload_len"), _uint(record, "payload_crc32c"))
            if scenario == "frag":
                identification = _uint(record, "identification")
                if expected_identification is None or identification != expected_identification:
                    raise CheckError("manifest Identification does not match the captured FRAG sequence")
            elif scenario is not None and ("identification" not in record or record["identification"] is not None):
                raise CheckError("unfragmented manifest Identification must be null")
            if scenario is not None:
                datagrams = _uint(record, "datagrams", maximum=0xFFFF)
                if expected_datagrams is None or datagrams != expected_datagrams:
                    raise CheckError("manifest datagram count does not match the sender capture")
        except CheckError as error:
            raise CheckError(f"{manifest_path}:{record_number}: {error}") from error
        expected[key] += 1

    receiver = _read_jsonl(receiver_path, allow_empty=not require_delivery)
    if forbid_receiver_records and receiver:
        raise CheckError(f"{receiver_path}: filter path was not a total drop")
    delivered: Counter[tuple[int, int]] = Counter()
    for record_number, record in enumerate(receiver, 1):
        delivery = record.get("delivery")
        if delivery not in {"payload", "buffered", "dropped", "error"}:
            raise CheckError(f"{receiver_path}:{record_number}: invalid delivery value {delivery!r}")
        if delivery == "error":
            raise CheckError(f"{receiver_path}:{record_number}: receiver reported an error")
        if delivery != "payload":
            continue
        try:
            payload_len = _uint(record, "payload_len")
            payload_crc = _uint(record, "payload_crc32c")
            payload_hex = record.get("payload_hex")
            if not isinstance(payload_hex, str):
                raise CheckError("field 'payload_hex' is not a string")
            if len(payload_hex) != payload_len * 2:
                raise CheckError("payload_hex is not the canonical encoded payload length")
            try:
                payload = bytes.fromhex(payload_hex)
            except ValueError as error:
                raise CheckError("field 'payload_hex' is not valid hexadecimal") from error
            if len(payload) != payload_len:
                raise CheckError("payload_len does not match payload_hex")
            if crc32c(payload) != payload_crc:
                raise CheckError("payload_crc32c does not match payload_hex")
        except CheckError as error:
            raise CheckError(f"{receiver_path}:{record_number}: {error}") from error
        delivered[(payload_len, payload_crc)] += 1

    unexpected = delivered - expected
    if unexpected:
        raise CheckError(f"{receiver_path}: delivered payload is absent from sender manifest")
    if require_delivery:
        missing = expected - delivered
        if missing:
            raise CheckError(f"{receiver_path}: sender payload was not delivered with matching length and CRC")
        if not delivered:
            raise CheckError(f"{receiver_path}: no payload delivery was proven")
    return {
        "manifest_records": len(manifests),
        "receiver_records": len(receiver),
        "payload_records": sum(delivered.values()),
    }


def validate_run_artifacts(
    run_dir: Path,
    topology: str,
    fragment_identifications: dict[int, int],
    sender_packet_counts: dict[int, int],
    port_base: int,
) -> list[dict[str, object]]:
    require_delivery = topology in {"veth", "router"}
    summaries: list[dict[str, object]] = []
    for index, scenario in enumerate(SCENARIOS):
        summary = validate_artifact_pair(
            run_dir / f"send-{scenario}.jsonl",
            run_dir / f"recv-{scenario}.jsonl",
            require_delivery=require_delivery,
            forbid_receiver_records=topology == "filter",
            scenario=scenario,
            expected_identification=fragment_identifications.get(port_base + index),
            expected_datagrams=sender_packet_counts.get(port_base + index),
        )
        summaries.append({"record_type": "artifact", "scenario": scenario, **summary})
    return summaries


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sender-pcap", required=True)
    parser.add_argument("--receiver-pcap", required=True)
    parser.add_argument("--port-base", type=int, default=41000)
    parser.add_argument("--port-count", type=int, default=5)
    parser.add_argument("--expect-surplus-port", type=int, action="append", default=[])
    verdict_requirement = parser.add_mutually_exclusive_group()
    verdict_requirement.add_argument("--require-intact", action="store_true")
    verdict_requirement.add_argument("--require-dropped", action="store_true")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--topology", choices=("veth", "router", "nat", "filter"))
    args = parser.parse_args()
    if (args.run_dir is None) != (args.topology is None):
        parser.error("--run-dir and --topology must be supplied together")

    try:
        sender = by_port(read_pcap(args.sender_pcap), args.port_base, args.port_base + args.port_count - 1)
        receiver = by_port(read_pcap(args.receiver_pcap), args.port_base, args.port_base + args.port_count - 1)
        expect_surplus_ports = set(args.expect_surplus_port)
        scenario_by_port = {
            args.port_base + index: scenario
            for index, scenario in enumerate(SCENARIOS[: args.port_count])
        }
        fragment_identifications = validate_sender_groups(sender, expect_surplus_ports, scenario_by_port)
        if args.topology == "nat":
            validate_nat_observation(receiver)
        failed = False
        for port in range(args.port_base, args.port_base + args.port_count):
            verdict = classify(sender.get(port, []), receiver.get(port, []), port in expect_surplus_ports)
            sent_surplus = sum(len(packet.surplus) for packet in sender.get(port, []))
            received_surplus = sum(len(packet.surplus) for packet in receiver.get(port, []))
            print(
                json.dumps(
                    {
                        "port": port,
                        "verdict": verdict,
                        "sender_packets": len(sender.get(port, [])),
                        "receiver_packets": len(receiver.get(port, [])),
                        "sender_surplus": sent_surplus,
                        "receiver_surplus": received_surplus,
                    },
                    separators=(",", ":"),
                )
            )
            failed = failed or verdict in {"never-captured", "sender-surplus-missing"}
            failed = failed or (args.require_intact and verdict != "intact")
            failed = failed or (args.require_dropped and verdict != "dropped")
        if args.run_dir is not None:
            for summary in validate_run_artifacts(
                args.run_dir,
                args.topology,
                fragment_identifications,
                {port: len(packets) for port, packets in sender.items()},
                args.port_base,
            ):
                print(json.dumps(summary, separators=(",", ":")))
        return 1 if failed else 0
    except CheckError as error:
        print(f"eval-check: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
