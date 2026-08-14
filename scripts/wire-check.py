#!/usr/bin/env python3
"""Independent wire checker for the Step 10.5 verification lane (see scripts/wire-check.sh).

Reads the tcpdump capture of the examples/wire_probe.rs scenario set and verifies the post-kernel
bytes with logic that deliberately shares nothing with the Rust implementation: its own pcap
reader, its own RFC 1071 one's-complement fold, its own CRC32C (Castagnoli) table, and its own
IPv4/UDP/TLV/OCS decoding. Golden bytes below are derived from docs/wire-format.md (section
references in the comments), never from a hexdump of a probe run; computed fields (OCS, APC CRC)
are always re-derived, never taken as goldens.

Usage: wire-check.py <capture.pcap> [tshark.csv]

The optional tshark CSV (one row per packet, fields ip.hdr_len, ip.len, ip.checksum.status,
udp.srcport, udp.dstport, udp.length, udp.checksum, udp.checksum.status) is cross-checked field by
field against this script's own decoding, so two independent decoders must agree.

Python 3 standard library only (achim carries no extra packages).
"""

import os
import struct
import sys

# WIRE_SRC_ADDR/WIRE_DST_ADDR mirror the examples/wire_probe.rs overrides for a real-path capture;
# the default is the loopback lane.
SRC_IP = os.environ.get("WIRE_SRC_ADDR", "127.0.0.1")
DST_IP = os.environ.get("WIRE_DST_ADDR", "127.0.0.1")
# Keep in sync with examples/wire_probe.rs and scripts/wire-check.sh.
SRC_PORT = 0x9A00
PORT_BASE = 0x9A68
# wire-check.sh proves the capture is live by sending warm-up datagrams to this port before the
# probe runs; they are dropped from both views (own decode and tshark rows) before any check.
CANARY_PORT = 0x9A67

UDP_HEADER_LEN = 8
SPLIT_FRAG_ID = 0xA1B2C3D4
SPLIT_PAYLOAD_LEN = 90
SPLIT_FRAGMENT_SURPLUS_LEN = 36
SPLIT_FRAGMENT_COUNT = 5

# --- Independent primitives ------------------------------------------------------------------


def fold16(data, *extra):
    """RFC 1071 one's-complement sum over big-endian 16-bit words plus extra 16-bit addends."""
    if len(data) % 2:
        data = data + b"\x00"
    total = sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2)) + sum(extra)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total


def _crc32c_table():
    table = []
    for index in range(256):
        crc = index
        for _ in range(8):
            crc = (crc >> 1) ^ 0x82F63B78 if crc & 1 else crc >> 1
        table.append(crc)
    return table


_CRC32C_TABLE = _crc32c_table()


def crc32c(data):
    """CRC32C (Castagnoli, reflected 0x82F63B78) -- zlib.crc32 is CRC-32/IEEE, not this."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = _CRC32C_TABLE[(crc ^ byte) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def pattern(length):
    """The deterministic fill wire_probe uses for extended-length values and fragment data."""
    return bytes(i % 256 for i in range(length))


# --- pcap reading ----------------------------------------------------------------------------

_PCAP_MAGICS = {
    b"\xa1\xb2\xc3\xd4": ">",
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",  # nanosecond variant
    b"\x4d\x3c\xb2\xa1": "<",
}

# Link-layer header sizes. Linux `lo` captures as EN10MB (1) with a fake Ethernet header; the
# others cover DLT_NULL, RAW, and the cooked captures an `-i any` fallback would produce.
_LINK_HEADER_LEN = {0: 4, 1: 14, 101: 0, 113: 16, 276: 20}


def read_pcap(path):
    """Returns (linktype, [frame bytes])."""
    with open(path, "rb") as capture:
        header = capture.read(24)
        if len(header) < 24:
            die(f"{path}: not a pcap file (short global header)")
        if header[:4] == b"\x0a\x0d\x0d\x0a":
            die(f"{path}: pcapng is not supported; capture with tcpdump -w (classic pcap)")
        endian = _PCAP_MAGICS.get(header[:4])
        if endian is None:
            die(f"{path}: unknown pcap magic {header[:4].hex()}")
        linktype = struct.unpack(endian + "I", header[20:24])[0] & 0x0FFFFFFF

        frames = []
        while True:
            record = capture.read(16)
            if not record:
                break
            if len(record) < 16:
                die(f"{path}: truncated record header")
            _, _, caplen, origlen = struct.unpack(endian + "IIII", record)
            data = capture.read(caplen)
            if len(data) < caplen:
                die(f"{path}: truncated record body")
            if caplen != origlen:
                die(f"{path}: truncated capture (caplen {caplen} < packet {origlen}; snaplen too small?)")
            frames.append(data)
    return linktype, frames


def strip_link(linktype, frame):
    if linktype not in _LINK_HEADER_LEN:
        die(f"unhandled pcap linktype {linktype}")
    if linktype == 1:
        ethertype = (frame[12] << 8) | frame[13]
        if ethertype != 0x0800:
            die(f"EN10MB frame is not IPv4 (EtherType 0x{ethertype:04x})")
    elif linktype == 0:
        family = int.from_bytes(frame[:4], "little")
        if family not in (2, 0x02000000):  # AF_INET, either byte order
            die(f"DLT_NULL frame is not AF_INET (family field 0x{family:08x})")
    elif linktype == 113 and (frame[14] << 8) | frame[15] != 0x0800:
        die("SLL frame is not IPv4")
    elif linktype == 276 and (frame[0] << 8) | frame[1] != 0x0800:
        die("SLL2 frame is not IPv4")
    packet = frame[_LINK_HEADER_LEN[linktype] :]
    if not packet or packet[0] >> 4 != 4:
        die("link-layer strip did not land on an IPv4 header")
    return packet


# --- Independent IPv4/UDP decoding -----------------------------------------------------------


class Packet:
    """One decoded datagram: independent IPv4 + UDP parse of the captured bytes."""

    def __init__(self, raw):
        if len(raw) < 20:
            die("IPv4 header truncated")
        self.ihl = (raw[0] & 0x0F) * 4
        self.total_len = (raw[2] << 8) | raw[3]
        if raw[9] != 17:
            die(f"IP protocol {raw[9]} is not UDP")
        if fold16(raw[: self.ihl]) != 0xFFFF:
            die("IPv4 header checksum does not fold to one's-complement zero")
        if self.total_len > len(raw):
            die(f"IP Total Length {self.total_len} exceeds the captured frame")
        self.raw = raw[: self.total_len]  # drop any capture padding past IP Total Length
        self.src = ".".join(str(b) for b in self.raw[12:16])
        self.dst = ".".join(str(b) for b in self.raw[16:20])

        udp = self.raw[self.ihl :]
        if len(udp) < UDP_HEADER_LEN:
            die("UDP header truncated")
        self.src_port = (udp[0] << 8) | udp[1]
        self.dst_port = (udp[2] << 8) | udp[3]
        self.udp_len = (udp[4] << 8) | udp[5]
        self.udp_checksum = (udp[6] << 8) | udp[7]
        if not UDP_HEADER_LEN <= self.udp_len <= len(udp):
            die(f"UDP Length {self.udp_len} out of bounds")
        self.user_data = udp[UDP_HEADER_LEN : self.udp_len]
        # RFC 9868 Sec. 7: the surplus area runs from the end of the UDP datagram to the end of
        # the IP transport payload.
        self.surplus = udp[self.udp_len :]
        # RFC 9868 Sec. 8: pad iff the natural start (relative to the IP datagram) is odd.
        self.needs_pad = (self.ihl + self.udp_len) % 2 == 1

    def udp_checksum_folds(self):
        """Verifies the stored UDP checksum over pseudo-header + UDP header + user data ONLY.

        The surplus area never enters this sum (RFC 9868 Sec. 17 bounds the UDP checksum by the
        UDP Length field) -- summing the wire bytes exactly as captured proves that scope.
        """
        pseudo = bytes(int(b) for b in self.src.split(".")) + bytes(int(b) for b in self.dst.split("."))
        udp_bytes = self.raw[self.ihl : self.ihl + self.udp_len]
        return fold16(pseudo + udp_bytes, 17, self.udp_len) == 0xFFFF


def walk_tlvs(region):
    """Independent TLV walk (docs/wire-format.md Sec. 4): returns (options, end_offset).

    `options` is a list of (kind, value bytes); `end_offset` points just past the terminating EOL.
    Raises ValueError on any framing violation.
    """
    options = []
    offset = 0
    while True:
        if offset >= len(region):
            raise ValueError("options ran past the surplus area without an EOL")
        kind = region[offset]
        if kind == 0:  # EOL, Sec. 4.2
            return options, offset + 1
        if kind == 1:  # NOP, Sec. 4.2
            options.append((1, b""))
            offset += 1
            continue
        if offset + 2 > len(region):
            raise ValueError(f"TLV header truncated at offset {offset}")
        length = region[offset + 1]
        if length == 255:  # Extended Length, Sec. 4.1
            if offset + 4 > len(region):
                raise ValueError(f"extended length truncated at offset {offset}")
            length = (region[offset + 2] << 8) | region[offset + 3]
            # The default form carries total lengths through 254; every total length from 255
            # onward therefore uses the extended form (RFC 9868 Sec. 10).
            if length < 255:
                raise ValueError(f"non-minimal extended length {length} at offset {offset}")
            value = region[offset + 4 : offset + length]
        else:
            if length < 2:
                raise ValueError(f"TLV length {length} below minimum at offset {offset}")
            value = region[offset + 2 : offset + length]
        if offset + length > len(region):
            raise ValueError(f"option (kind {kind}) overruns the surplus area at offset {offset}")
        options.append((kind, value))
        offset += length


# Fixed TLV value lengths for the must-support options (docs/wire-format.md Sec. 6-10).
_FIXED_VALUE_LENS = {2: {4}, 3: {8, 10}, 4: {2}, 5: {3}, 6: {4}, 7: {4}}


def canonical_rank(kind):
    """The builder's canonical transmit order (docs/wire-format.md Sec. 4)."""
    return {3: 0, 2: 1, 4: 2, 5: 3, 6: 4, 7: 5}.get(kind, 1000 + kind)


# --- Single-datagram scenario table (mirror of examples/wire_probe.rs) -------------------------

REQ_TLV = bytes.fromhex("0606deadbeef")  # REQ, Sec. 10
# The pad-odd scenario uses its own token: the deadbeef REQ body folds to 0xA3A3, a byte
# palindrome whose byte-swap equals itself, which would mask word-alignment regressions in the
# odd-start OCS. c0ffee01 folds to a non-palindromic sum.
PAD_REQ_TLV = bytes.fromhex("0606c0ffee01")
RES_TLV = bytes.fromhex("0706feedface")  # RES, Sec. 10
EOL_FILL = bytes.fromhex("0000")  # EOL (Sec. 4.2) + zero-fill to even length (Sec. 4)


def canon_even_tlv(user):
    return (
        bytes.fromhex("0206")  # APC, Sec. 6 ...
        + crc32c(user).to_bytes(4, "big")  # ... with the checker's own CRC32C of the user data
        + bytes.fromhex("040405dc")  # MDS 1500, Sec. 8
        + bytes.fromhex("05050b6e02")  # MRDS 2926 / 2 segments, Sec. 9
        + bytes.fromhex("01")  # NOP aligning the next TLV to an even offset, Sec. 4.2
        + REQ_TLV
        + RES_TLV
        + EOL_FILL
    )


# Each entry: user data, OCS mode ("normal" | "zero" | "forced-ffff"), expected TLV region (bytes,
# a callable over the user data, or None for structural-only checks), expected parsed options
# ((kind, value-or-None), NOP excluded) when there is no golden, and the expected FRAG data length.
SCENARIOS = [
    {"name": "baseline", "user": b"plain", "no_surplus": True},
    {"name": "canon-even", "user": b"wire", "ocs": "normal", "tlv": canon_even_tlv},
    {"name": "pad-odd", "user": b"odd", "ocs": "normal", "tlv": PAD_REQ_TLV + EOL_FILL},
    {
        "name": "frag-nonterm",
        "user": b"",
        "ocs": "normal",
        # FRAG non-terminal, Sec. 7: Length 10, Frag.Start 0x0016 = 8 + 14-byte body (end of the
        # datagram: zero fragment data), Identification, Frag.Offset 8.
        "tlv": bytes.fromhex("030a0016112233440008") + EOL_FILL,
        "frag_data_len": 0,
    },
    {
        "name": "frag-term",
        "user": b"",
        "ocs": "normal",
        # FRAG terminal, Sec. 7: Length 12, Frag.Start 0x0018 = 8 + 16-byte body, RDOS 0x001c.
        "tlv": bytes.fromhex("030c0018112233440010001c") + EOL_FILL,
        "frag_data_len": 0,
    },
    {
        "name": "ocs-forced-ffff",
        "user": b"",
        "ocs": "forced-ffff",
        # The 2-byte filler is brute-forced by the probe, so only the frame is pinned here.
        "opts": [(77, None)],
    },
    {
        "name": "ext-len",
        "user": b"",
        "ocs": "normal",
        # Extended Length, Sec. 4.1: marker 255, 16-bit total length 0x0130 = 304 = 300 + 4.
        "tlv": bytes.fromhex("0bff0130") + pattern(300) + EOL_FILL,
    },
    {
        # RFC 9868 Sec. 9: a zero OCS is legal only when the UDP checksum is also zero.
        "name": "cksum0-ocs0",
        "user": b"nochksum",
        "ocs": "zero",
        "tlv": REQ_TLV + EOL_FILL,
    },
    {
        "name": "frag-data-nonterm",
        "user": b"",
        "ocs": "normal",
        # Frag.Start 0x001c = 8 + 20-byte body; 64 bytes of fragment data follow the options.
        # Frag.Offset 8: the first fragment's data belongs right after the original UDP header
        # (both offsets are measured from the original UDP header start, Sec. 7), covering [8, 72).
        "tlv": bytes.fromhex("030a001c112233440008") + REQ_TLV + EOL_FILL + pattern(64),
        "frag_data_len": 64,
    },
    {
        "name": "frag-data-term",
        "user": b"",
        "ocs": "normal",
        # Frag.Start 0x001e = 8 + 22-byte body; the coherent terminal half of the pair above:
        # Frag.Offset 0x0048 = 72 covers [72, 136), and RDOS 0x0088 = 136 points right past the
        # reassembled data to the per-datagram option start.
        "tlv": bytes.fromhex("030c001e112233440048" + "0088") + REQ_TLV + EOL_FILL + pattern(64),
        "frag_data_len": 64,
    },
]

# The production-split scenario follows these ports and carries five datagrams on one shared port;
# check_production_split handles it separately because a single-packet golden cannot prove reassembly.


# --- Checks ----------------------------------------------------------------------------------


def check_scenario(spec, pkt, err):
    if pkt.src != SRC_IP or pkt.dst != DST_IP:
        err(f"addresses {pkt.src} -> {pkt.dst} do not match the expected {SRC_IP} -> {DST_IP}")
    if pkt.src_port != SRC_PORT:
        err(f"source port {pkt.src_port} != {SRC_PORT}")
    if pkt.ihl != 20:
        err(f"IHL {pkt.ihl} != 20 (the probe writes option-free IPv4 headers)")
    if pkt.user_data != spec["user"]:
        err(f"user data {pkt.user_data.hex()} != expected {spec['user'].hex()}")

    if spec.get("ocs") == "zero":
        if pkt.udp_checksum != 0:
            err(f"UDP checksum field 0x{pkt.udp_checksum:04x} should be zero")
    elif pkt.udp_checksum == 0:
        err("UDP checksum field is zero outside the cksum0 scenario")
    elif not pkt.udp_checksum_folds():
        err("UDP checksum does not verify over pseudo-header + header + user data")

    if spec.get("no_surplus"):
        if pkt.surplus:
            err(f"unexpected {len(pkt.surplus)}-byte surplus area")
        return
    if len(pkt.surplus) < pkt.needs_pad + 2:
        err(f"surplus area too short for pad + OCS ({len(pkt.surplus)} bytes)")
        return

    # Pad rule (Sec. 8): present iff the natural start is odd, and then zero.
    pad = int(pkt.needs_pad)
    if pad and pkt.surplus[0] != 0:
        err(f"pad byte 0x{pkt.surplus[0]:02x} is not zero")

    # OCS re-derivation (Sec. 9): the RFC 1071 word grouping starts at the OCS -- Sec. 8 aligns
    # the OCS to a 2-byte boundary precisely so the sum is word-aligned. Prepending the (zero)
    # pad byte would shift the grouping by one and byte-swap the sum; the pad is checked above
    # and enters the sum only through the full surplus length.
    stored_ocs = (pkt.surplus[pad] << 8) | pkt.surplus[pad + 1]
    zeroed = b"\x00\x00" + pkt.surplus[pad + 2 :]
    derived = ~fold16(zeroed, len(pkt.surplus)) & 0xFFFF
    mode = spec.get("ocs", "normal")
    if mode == "zero":
        if stored_ocs != 0:
            err(f"OCS 0x{stored_ocs:04x} should be zero (unused, UDP checksum is zero)")
    elif mode == "forced-ffff":
        if derived != 0:
            err(f"scenario should sum to a computed OCS of 0x0000, derived 0x{derived:04x}")
        if stored_ocs != 0xFFFF:
            err(f"computed 0x0000 must be transmitted as 0xFFFF, stored 0x{stored_ocs:04x}")
    else:
        expected = derived if derived != 0 else 0xFFFF
        if stored_ocs != expected:
            err(f"OCS 0x{stored_ocs:04x} != re-derived 0x{expected:04x}")

    region = pkt.surplus[pad + 2 :]
    golden = spec.get("tlv")
    if callable(golden):
        golden = golden(spec["user"])
    if golden is not None and region != golden:
        err(f"TLV region mismatch:\n    wire   {region.hex()}\n    golden {golden.hex()}")

    try:
        options, end = walk_tlvs(region)
    except ValueError as exc:
        err(f"TLV walk failed: {exc}")
        return
    check_tlv_grammar(spec, region, options, end, err)


def check_tlv_grammar(spec, region, options, end, err):
    substantive = [(kind, value) for kind, value in options if kind != 1]
    for kind, value in substantive:
        allowed = _FIXED_VALUE_LENS.get(kind)
        if allowed is not None and len(value) not in allowed:
            err(f"option kind {kind} has value length {len(value)}, allowed {sorted(allowed)}")
    ranks = [canonical_rank(kind) for kind, _ in substantive]
    if ranks != sorted(ranks):
        err(f"options are not in canonical order (kinds {[k for k, _ in substantive]})")

    expected_opts = spec.get("opts")
    if expected_opts is not None:
        got = [(kind, value) for kind, value in substantive]
        if len(got) != len(expected_opts) or any(
            kind != want_kind or (want_value is not None and value != want_value)
            for (kind, value), (want_kind, want_value) in zip(got, expected_opts)
        ):
            err(f"parsed options {[(k, v.hex()) for k, v in got]} != expected {expected_opts}")

    frags = [value for kind, value in substantive if kind == 3]
    data_start = len(region)
    if frags:
        # Independent Frag.Start invariant (Sec. 7): the fragment data begins at Frag.Start bytes
        # from the UDP header, i.e. right after the options body; anything between the EOL and the
        # data start can only be the builder's even-length zero-fill.
        frag_start = (frags[0][0] << 8) | frags[0][1]
        data_start = frag_start - UDP_HEADER_LEN - 2  # region starts after the 2-byte OCS
        if not end <= data_start <= len(region):
            err(f"Frag.Start {frag_start} points outside [options end, surplus end]")
            return
        data = region[data_start:]
        expected_len = spec.get("frag_data_len")
        if expected_len is not None and len(data) != expected_len:
            err(f"fragment data length {len(data)} != expected {expected_len}")
        if data != pattern(len(data)):
            err("fragment data does not match the probe pattern")
    trailer = region[end:data_start]
    if any(trailer):
        err(f"non-zero bytes after EOL: {trailer.hex()}")


def decode_production_fragment(pkt, err):
    """Independently decodes one fragment emitted by Rust's production splitter."""
    if pkt.src != SRC_IP or pkt.dst != DST_IP:
        err(f"addresses {pkt.src} -> {pkt.dst} do not match the expected {SRC_IP} -> {DST_IP}")
    if pkt.src_port != SRC_PORT:
        err(f"source port {pkt.src_port} != {SRC_PORT}")
    if pkt.ihl != 20:
        err(f"IHL {pkt.ihl} != 20")
    if pkt.udp_len != UDP_HEADER_LEN or pkt.user_data:
        err(f"FRAG must carry UDP Length 8 and empty user data, got {pkt.udp_len} / {pkt.user_data.hex()}")
    if pkt.udp_checksum == 0 or not pkt.udp_checksum_folds():
        err("UDP checksum is zero or invalid")
    if pkt.needs_pad:
        err("UDP Length 8 with a 20-byte IPv4 header must not need a surplus pad")
        return None
    if len(pkt.surplus) > SPLIT_FRAGMENT_SURPLUS_LEN:
        err(f"surplus length {len(pkt.surplus)} exceeds split budget {SPLIT_FRAGMENT_SURPLUS_LEN}")
    if len(pkt.surplus) < 12:
        err("surplus is too short for OCS plus non-terminal FRAG")
        return None

    stored_ocs = (pkt.surplus[0] << 8) | pkt.surplus[1]
    zeroed = b"\x00\x00" + pkt.surplus[2:]
    derived = ~fold16(zeroed, len(pkt.surplus)) & 0xFFFF
    expected_ocs = derived if derived != 0 else 0xFFFF
    if stored_ocs != expected_ocs:
        err(f"OCS 0x{stored_ocs:04x} != re-derived 0x{expected_ocs:04x}")

    region = pkt.surplus[2:]
    if region[0] != 3:
        err(f"first option kind {region[0]} is not FRAG")
        return None
    option_len = region[1]
    if option_len not in (10, 12) or option_len > len(region):
        err(f"FRAG length {option_len} is not a complete 10/12-byte option")
        return None
    value = region[2:option_len]
    frag_start = int.from_bytes(value[0:2], "big")
    identification = int.from_bytes(value[2:6], "big")
    frag_offset = int.from_bytes(value[6:8], "big")
    rdos = int.from_bytes(value[8:10], "big") if option_len == 12 else None
    data_start = frag_start - UDP_HEADER_LEN - 2  # region starts after the two-byte OCS
    if data_start != option_len:
        err(f"Frag.Start {frag_start} maps to region offset {data_start}, expected {option_len}")
        return None

    return {
        "identification": identification,
        "offset": frag_offset,
        "rdos": rdos,
        "terminal": option_len == 12,
        "data": region[data_start:],
        "frag_start": frag_start,
        "surplus_len": len(pkt.surplus),
    }


def check_production_split(copies, err):
    """Checks fragment wire invariants and independently reconstructs payload plus options."""
    unique = {}
    for pkt in copies:
        unique.setdefault(pkt.raw, pkt)
    if len(unique) != SPLIT_FRAGMENT_COUNT:
        err(f"captured {len(unique)} unique fragments, expected {SPLIT_FRAGMENT_COUNT}")

    fragments = []
    for pkt in unique.values():
        fragment = decode_production_fragment(pkt, err)
        if fragment is not None:
            fragments.append(fragment)
    if len(fragments) != SPLIT_FRAGMENT_COUNT:
        return
    if any(fragment["identification"] != SPLIT_FRAG_ID for fragment in fragments):
        err("fragments do not all carry the production-split Identification 0xa1b2c3d4")

    fragments.sort(key=lambda fragment: fragment["offset"])
    expected_offsets = [8, 32, 56, 80, 92]
    expected_surplus_lengths = [36, 36, 36, 24, 36]
    expected_lengths = [24, 24, 24, 12, 22]
    if [fragment["offset"] for fragment in fragments] != expected_offsets:
        err(f"fragment offsets {[fragment['offset'] for fragment in fragments]} != {expected_offsets}")
    if [len(fragment["data"]) for fragment in fragments] != expected_lengths:
        err(f"fragment data lengths {[len(fragment['data']) for fragment in fragments]} != {expected_lengths}")
    if [fragment["surplus_len"] for fragment in fragments] != expected_surplus_lengths:
        err(
            f"fragment surplus lengths {[fragment['surplus_len'] for fragment in fragments]} "
            f"!= {expected_surplus_lengths}"
        )
    if [fragment["frag_start"] for fragment in fragments] != [20, 20, 20, 20, 22]:
        err(f"unexpected Frag.Start sequence {[fragment['frag_start'] for fragment in fragments]}")

    terminal = [fragment for fragment in fragments if fragment["terminal"]]
    expected_rdos = UDP_HEADER_LEN + SPLIT_PAYLOAD_LEN
    if len(terminal) != 1 or terminal[0] is not fragments[-1] or terminal[0]["rdos"] != expected_rdos:
        err(
            f"terminal FRAG/RDOS mismatch: terminals {len(terminal)}, "
            f"RDOS {[fragment['rdos'] for fragment in terminal]}, expected {expected_rdos}"
        )
        return
    if any(fragment["rdos"] is not None for fragment in fragments[:-1]):
        err("a non-terminal fragment carries RDOS")

    cursor = UDP_HEADER_LEN
    reassembled_tail = bytearray()
    for fragment in fragments:
        if fragment["offset"] != cursor:
            err(f"gap or overlap at offset {cursor}: next fragment starts at {fragment['offset']}")
        reassembled_tail.extend(fragment["data"])
        cursor = fragment["offset"] + len(fragment["data"])

    payload_len = terminal[0]["rdos"] - UDP_HEADER_LEN
    payload = bytes(reassembled_tail[:payload_len])
    options_body = bytes(reassembled_tail[payload_len:])
    if payload != pattern(SPLIT_PAYLOAD_LEN):
        err("independently reassembled payload does not match the production-split input")
    expected_options = (
        b"\x00\x00"
        + bytes.fromhex("0206")
        + crc32c(payload).to_bytes(4, "big")
        + RES_TLV
        + EOL_FILL
    )
    if options_body != expected_options:
        err(f"reassembled options {options_body.hex()} != expected {expected_options.hex()}")
        return

    # The reconstructed virtual UDP header has checksum zero, so the zero per-datagram OCS is the
    # RFC 9868 "unused" form. Still parse its TLVs independently and prove the APC over the payload.
    try:
        options, end = walk_tlvs(options_body[2:])
    except ValueError as exc:
        err(f"reassembled TLV walk failed: {exc}")
        return
    if options != [(2, crc32c(payload).to_bytes(4, "big")), (7, bytes.fromhex("feedface"))]:
        err(f"reassembled parsed options are unexpected: {[(kind, value.hex()) for kind, value in options]}")
    if any(options_body[2 + end :]):
        err(f"non-zero reassembled bytes after EOL: {options_body[2 + end :].hex()}")


# --- tshark cross-check ------------------------------------------------------------------------


def parse_int(cell):
    return int(cell, 16) if cell.lower().startswith("0x") else int(cell)


def cross_check_tshark(path, packets, err):
    """Field-by-field agreement between tshark's decode and this script's own (same file order)."""
    with open(path, encoding="ascii") as csv:
        rows = [line.rstrip("\n").split(",") for line in csv if line.strip()]
    rows = [row for row in rows if len(row) < 5 or row[4] != str(CANARY_PORT)]
    if len(rows) != len(packets):
        err(f"tshark saw {len(rows)} packets, this checker {len(packets)}")
        return
    for index, (row, pkt) in enumerate(zip(rows, packets)):
        if len(row) != 8:
            err(f"tshark row {index} has {len(row)} fields, expected 8")
            continue
        hdr_len, ip_len, ip_status, sport, dport, udp_len, udp_cksum, udp_status = row
        actual = (pkt.ihl, pkt.total_len, pkt.src_port, pkt.dst_port, pkt.udp_len, pkt.udp_checksum)
        reported = tuple(parse_int(cell) for cell in (hdr_len, ip_len, sport, dport, udp_len, udp_cksum))
        if reported != actual:
            err(f"tshark row {index} {reported} disagrees with own decode {actual}")
        if ip_status != "1":
            err(f"tshark row {index}: IP checksum status {ip_status!r} is not good")
        # Status 1 is "good"; a zero checksum is the RFC 768 "no checksum" case and is asserted
        # via the field value above, so its status code is left to tshark.
        if pkt.udp_checksum != 0 and udp_status != "1":
            err(f"tshark row {index}: UDP checksum status {udp_status!r} is not good")


# --- Main --------------------------------------------------------------------------------------


def die(message):
    print(f"wire-check: FAIL: {message}", file=sys.stderr)
    sys.exit(1)


def main(argv):
    if len(argv) not in (2, 3):
        print("usage: wire-check.py <capture.pcap> [tshark.csv]", file=sys.stderr)
        return 2
    linktype, frames = read_pcap(argv[1])
    if not frames:
        die("no packets captured -- tcpdump readiness race or the probe did not run?")
    packets = [Packet(strip_link(linktype, frame)) for frame in frames]
    packets = [pkt for pkt in packets if pkt.dst_port != CANARY_PORT]
    if not packets:
        die("only warm-up canaries captured -- the probe traffic is missing")

    failures = []
    if len(argv) == 3:
        cross_check_tshark(argv[2], packets, lambda msg: failures.append(f"tshark: {msg}"))
    else:
        print("wire-check: note: no tshark CSV given, cross-check skipped")

    groups = {}
    for pkt in packets:
        groups.setdefault(pkt.dst_port, []).append(pkt)
    scenario_count = len(SCENARIOS) + 1
    split_port = PORT_BASE + len(SCENARIOS)
    expected_ports = {PORT_BASE + index for index in range(scenario_count)}
    for port in sorted(set(groups) - expected_ports):
        failures.append(f"unexpected traffic to port {port}")

    passed = 0
    for index, spec in enumerate(SCENARIOS):
        port = PORT_BASE + index
        copies = groups.get(port)
        if not copies:
            failures.append(f"{spec['name']}: no packet captured on port {port}")
            continue
        errors = []
        if any(pkt.raw != copies[0].raw for pkt in copies[1:]):
            errors.append("loopback copies of the same datagram differ")
        check_scenario(spec, copies[0], errors.append)
        if errors:
            failures.extend(f"{spec['name']}: {message}" for message in errors)
        else:
            passed += 1
            print(f"PASS {spec['name']:<18} port {port}  {len(copies[0].surplus):>3}-byte surplus")

    split_copies = groups.get(split_port)
    if not split_copies:
        failures.append(f"production-split: no packets captured on port {split_port}")
    else:
        errors = []
        check_production_split(split_copies, errors.append)
        if errors:
            failures.extend(f"production-split: {message}" for message in errors)
        else:
            passed += 1
            print(
                f"PASS {'production-split':<18} port {split_port}  "
                f"{SPLIT_FRAGMENT_COUNT} independently reassembled fragments"
            )

    if failures:
        for failure in failures:
            print(f"FAIL {failure}", file=sys.stderr)
        print(f"wire-check: FAIL ({passed}/{scenario_count} scenarios, {len(failures)} failures)", file=sys.stderr)
        return 1
    print(f"wire-check: PASS ({passed}/{scenario_count} scenarios)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
