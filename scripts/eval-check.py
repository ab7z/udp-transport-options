#!/usr/bin/env python3
"""Classify FF2/P2 sender/receiver pcaps by comparing UDP surplus bytes per destination port."""

from __future__ import annotations

import argparse
import struct
import sys
from collections import Counter, defaultdict

CANARY_PORT = 40999

PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
    b"\x4d\x3c\xb2\xa1": "<",
}
LINK_HEADER_LEN = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}


class FragmentedIpv4Error(Exception):
    pass


class Packet:
    def __init__(self, raw: bytes):
        if len(raw) < 28 or raw[0] >> 4 != 4:
            raise ValueError("not an IPv4 UDP packet")
        self.ihl = (raw[0] & 0x0F) * 4
        self.total_len = (raw[2] << 8) | raw[3]
        if raw[9] != 17:
            raise ValueError("not UDP")
        if self.total_len > len(raw) or self.total_len < self.ihl + 8:
            raise ValueError("bad IPv4 total length")
        fragment = (raw[6] << 8) | raw[7]
        if fragment & 0x3FFF:
            raise FragmentedIpv4Error("IPv4 fragments are not supported by this checker")
        self.raw = raw[: self.total_len]
        udp = self.raw[self.ihl :]
        self.src = ".".join(str(b) for b in self.raw[12:16])
        self.dst = ".".join(str(b) for b in self.raw[16:20])
        self.src_port = (udp[0] << 8) | udp[1]
        self.dst_port = (udp[2] << 8) | udp[3]
        self.udp_len = (udp[4] << 8) | udp[5]
        if not 8 <= self.udp_len <= len(udp):
            raise ValueError("bad UDP length")
        self.user_data = udp[8 : self.udp_len]
        self.surplus = udp[self.udp_len :]


def read_pcap(path: str) -> list[Packet]:
    with open(path, "rb") as capture:
        header = capture.read(24)
        if len(header) < 24:
            raise SystemExit(f"{path}: short pcap header")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            raise SystemExit(f"{path}: pcapng is not supported; use tcpdump -w classic pcap")
        endian = PCAP_MAGICS.get(header[:4])
        if endian is None:
            raise SystemExit(f"{path}: unknown pcap magic {header[:4].hex()}")
        linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF
        if linktype not in LINK_HEADER_LEN:
            raise SystemExit(f"{path}: unsupported pcap linktype {linktype}")
        link_len = LINK_HEADER_LEN[linktype]
        packets: list[Packet] = []
        while True:
            record = capture.read(16)
            if not record:
                break
            if len(record) < 16:
                raise SystemExit(f"{path}: truncated pcap record")
            _, _, caplen, origlen = struct.unpack(endian + "IIII", record)
            frame = capture.read(caplen)
            if len(frame) < caplen:
                raise SystemExit(f"{path}: truncated pcap packet")
            if caplen != origlen:
                raise SystemExit(f"{path}: snaplen truncated packet {caplen} < {origlen}")
            if len(frame) <= link_len:
                continue
            try:
                packets.append(Packet(frame[link_len:]))
            except FragmentedIpv4Error as error:
                raise SystemExit(f"{path}: {error}") from error
            except ValueError:
                continue
        return packets


def by_port(packets: list[Packet], lo: int, hi: int) -> dict[int, list[Packet]]:
    grouped: dict[int, list[Packet]] = defaultdict(list)
    for packet in packets:
        if packet.dst_port == CANARY_PORT:
            continue
        if lo <= packet.dst_port <= hi:
            grouped[packet.dst_port].append(packet)
    return grouped


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


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sender-pcap", required=True)
    parser.add_argument("--receiver-pcap", required=True)
    parser.add_argument("--port-base", type=int, default=41000)
    parser.add_argument("--port-count", type=int, default=5)
    parser.add_argument("--expect-surplus-port", type=int, action="append", default=[])
    parser.add_argument("--require-intact", action="store_true")
    args = parser.parse_args()

    sender = by_port(read_pcap(args.sender_pcap), args.port_base, args.port_base + args.port_count - 1)
    receiver = by_port(read_pcap(args.receiver_pcap), args.port_base, args.port_base + args.port_count - 1)
    expect_surplus_ports = set(args.expect_surplus_port)
    failed = False
    for port in range(args.port_base, args.port_base + args.port_count):
        verdict = classify(sender.get(port, []), receiver.get(port, []), port in expect_surplus_ports)
        sent_surplus = sum(len(packet.surplus) for packet in sender.get(port, []))
        received_surplus = sum(len(packet.surplus) for packet in receiver.get(port, []))
        print(
            f'{{"port":{port},"verdict":"{verdict}",'
            f'"sender_packets":{len(sender.get(port, []))},"receiver_packets":{len(receiver.get(port, []))},'
            f'"sender_surplus":{sent_surplus},"receiver_surplus":{received_surplus}}}'
        )
        failed = failed or verdict in {"never-captured", "sender-surplus-missing"}
        failed = failed or (args.require_intact and verdict != "intact")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
