#!/usr/bin/env python3
"""Root-free tests for scripts/eval-check.py."""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("eval_check", ROOT / "scripts" / "eval-check.py")
assert SPEC is not None and SPEC.loader is not None
eval_check = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = eval_check
SPEC.loader.exec_module(eval_check)


def checksum(data: bytes) -> int:
    value = (~eval_check.fold16(data)) & 0xFFFF
    return 0xFFFF if value == 0 else value


def make_surplus(region: bytes, udp_len: int, *, ihl: int = 20) -> bytes:
    pad = b"\x00" if (ihl + udp_len) % 2 else b""
    surplus_len = len(pad) + 2 + len(region)
    derived = (~eval_check.fold16(b"\x00\x00" + region, surplus_len)) & 0xFFFF
    ocs = 0xFFFF if derived == 0 else derived
    return pad + ocs.to_bytes(2, "big") + region


def make_datagram(
    user_data: bytes,
    *,
    surplus: bytes = b"",
    dst_port: int = 41001,
    udp_checksum_zero: bool = False,
) -> bytes:
    src = bytes((10, 9, 1, 1))
    dst = bytes((10, 9, 1, 2))
    udp_len = 8 + len(user_data)
    udp = bytearray(struct.pack("!HHHH", 40000, dst_port, udp_len, 0) + user_data)
    if not udp_checksum_zero:
        pseudo = src + dst + b"\x00\x11" + udp_len.to_bytes(2, "big")
        udp[6:8] = checksum(pseudo + udp).to_bytes(2, "big")

    total_len = 20 + len(udp) + len(surplus)
    ipv4 = bytearray(20)
    ipv4[0] = 0x45
    ipv4[2:4] = total_len.to_bytes(2, "big")
    ipv4[4:6] = b"\x12\x34"
    ipv4[6:8] = b"\x40\x00"
    ipv4[8] = 64
    ipv4[9] = 17
    ipv4[12:16] = src
    ipv4[16:20] = dst
    ipv4[10:12] = checksum(ipv4).to_bytes(2, "big")
    return bytes(ipv4 + udp + surplus)


def write_raw_pcap(path: Path, packets: list[bytes]) -> None:
    with path.open("wb") as capture:
        capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        for packet in packets:
            capture.write(struct.pack("<IIII", 0, 0, len(packet), len(packet)))
            capture.write(packet)


def frag_region(identification: int, offset: int, data: bytes, rdos: int | None = None) -> bytes:
    total_len = 12 if rdos is not None else 10
    frag_start = 8 + 2 + total_len
    value = frag_start.to_bytes(2, "big") + identification.to_bytes(4, "big") + offset.to_bytes(2, "big")
    if rdos is not None:
        value += rdos.to_bytes(2, "big")
    return bytes((3, total_len)) + value + data


class PacketValidationTests(unittest.TestCase):
    def test_ipv4_and_udp_checksums_are_independent(self) -> None:
        raw = make_datagram(b"wire")
        packet = eval_check.Packet(raw)
        self.assertEqual(packet.user_data, b"wire")

        bad_ipv4 = bytearray(raw)
        bad_ipv4[8] ^= 1
        with self.assertRaisesRegex(eval_check.CheckError, "IPv4 header checksum"):
            eval_check.Packet(bytes(bad_ipv4))

        bad_udp = bytearray(raw)
        bad_udp[28] ^= 1
        with self.assertRaisesRegex(eval_check.CheckError, "UDP checksum"):
            eval_check.Packet(bytes(bad_udp))

    def test_malformed_udp_in_pcap_is_not_silently_skipped(self) -> None:
        malformed = bytearray(make_datagram(b"wire"))
        malformed[24:26] = (7).to_bytes(2, "big")
        with tempfile.TemporaryDirectory() as directory:
            pcap = Path(directory) / "malformed.pcap"
            write_raw_pcap(pcap, [bytes(malformed)])
            with self.assertRaisesRegex(eval_check.CheckError, "packet 1: bad UDP length"):
                eval_check.read_pcap(pcap)

    def test_malformed_link_declared_ipv4_is_not_treated_as_non_ip(self) -> None:
        frame = b"\x00" * 12 + b"\x08\x00" + b"\x60" + b"\x00" * 19
        with self.assertRaisesRegex(eval_check.CheckError, "bad IPv4 version"):
            eval_check._ipv4_from_frame(frame, 1)


class SenderWireValidationTests(unittest.TestCase):
    def test_fixed_scenario_payloads_options_and_values_are_accepted(self) -> None:
        typed_payload = b"wire"
        typed_region = (
            bytes((2, 6))
            + eval_check.crc32c(typed_payload).to_bytes(4, "big")
            + bytes.fromhex("040405c0")
            + bytes.fromhex("05050b6e02")
            + b"\x01"
            + bytes.fromhex("0606deadbeef")
            + b"\x00\x00"
        )
        pad_payload = b"odd"
        pad_region = bytes.fromhex("0606c0ffee01") + b"\x00\x00"
        near_payload = bytes(1392)
        near_region = (
            bytes((2, 6))
            + eval_check.crc32c(near_payload).to_bytes(4, "big")
            + bytes.fromhex("040405c0")
            + b"\x00\x00"
        )
        packets = {
            41000: [eval_check.Packet(make_datagram(b"plain", dst_port=41000))],
            41001: [
                eval_check.Packet(
                    make_datagram(
                        typed_payload,
                        surplus=make_surplus(typed_region, 8 + len(typed_payload)),
                        dst_port=41001,
                    )
                )
            ],
            41002: [
                eval_check.Packet(
                    make_datagram(
                        pad_payload,
                        surplus=make_surplus(pad_region, 8 + len(pad_payload)),
                        dst_port=41002,
                    )
                )
            ],
            41003: [
                eval_check.Packet(
                    make_datagram(
                        near_payload,
                        surplus=make_surplus(near_region, 8 + len(near_payload)),
                        dst_port=41003,
                    )
                )
            ],
        }
        contracts = {41000: "baseline", 41001: "typed", 41002: "pad", 41003: "near-mtu"}
        eval_check.validate_sender_groups(packets, {41001, 41002, 41003}, contracts)

    def test_ocs_can_fill_the_entire_surplus_area(self) -> None:
        raw = make_datagram(b"", surplus=make_surplus(b"", 8))
        eval_check.validate_sender_groups({41001: [eval_check.Packet(raw)]}, {41001})

    def test_pad_ocs_tlv_and_apc_are_validated(self) -> None:
        payload = b"odd"
        apc = bytes((2, 6)) + eval_check.crc32c(payload).to_bytes(4, "big")
        req = bytes.fromhex("0606c0ffee01")
        region = apc + req + b"\x00\x00"
        udp_len = 8 + len(payload)
        raw = make_datagram(payload, surplus=make_surplus(region, udp_len), dst_port=41002)
        packet = eval_check.Packet(raw)
        eval_check.validate_sender_groups({41002: [packet]}, {41002})

        bad_pad = bytearray(raw)
        bad_pad[20 + udp_len] = 1
        with self.assertRaisesRegex(eval_check.CheckError, "odd-start pad"):
            eval_check.validate_sender_groups({41002: [eval_check.Packet(bytes(bad_pad))]}, {41002})

        bad_ocs = bytearray(raw)
        bad_ocs[20 + udp_len + 1] ^= 1
        with self.assertRaisesRegex(eval_check.CheckError, "bad OCS"):
            eval_check.validate_sender_groups({41002: [eval_check.Packet(bytes(bad_ocs))]}, {41002})

    def test_tlv_overrun_is_rejected(self) -> None:
        region = bytes.fromhex("060a0102")
        raw = make_datagram(b"", surplus=make_surplus(region, 8))
        with self.assertRaisesRegex(eval_check.CheckError, "TLV overruns"):
            eval_check.validate_sender_groups({41001: [eval_check.Packet(raw)]}, {41001})

    def test_production_style_frag_sequence_is_validated(self) -> None:
        identification = 0x11223344
        first_region = frag_region(identification, 8, b"abcd")
        final_region = frag_region(identification, 12, b"efgh", rdos=16)
        first = eval_check.Packet(make_datagram(b"", surplus=make_surplus(first_region, 8), dst_port=41004))
        final = eval_check.Packet(make_datagram(b"", surplus=make_surplus(final_region, 8), dst_port=41004))
        eval_check.validate_sender_groups({41004: [first, final]}, {41004}, {41004: "frag"})

        gap_region = frag_region(identification, 13, b"efgh", rdos=17)
        gap = eval_check.Packet(make_datagram(b"", surplus=make_surplus(gap_region, 8), dst_port=41004))
        with self.assertRaisesRegex(eval_check.CheckError, "gap or overlap"):
            eval_check.validate_sender_groups({41004: [first, gap]}, {41004}, {41004: "frag"})

    def test_atomic_frag_requires_offset_zero_and_coherent_rdos(self) -> None:
        identification = 0x11223344
        valid_region = frag_region(identification, 0, b"data", rdos=12)
        valid = eval_check.Packet(make_datagram(b"", surplus=make_surplus(valid_region, 8), dst_port=41004))
        eval_check.validate_sender_groups({41004: [valid]}, {41004}, {41004: "frag"})

        invalid_region = frag_region(identification, 8, b"data", rdos=12)
        invalid = eval_check.Packet(make_datagram(b"", surplus=make_surplus(invalid_region, 8), dst_port=41004))
        with self.assertRaisesRegex(eval_check.CheckError, "invalid atomic FRAG geometry"):
            eval_check.validate_sender_groups({41004: [invalid]}, {41004}, {41004: "frag"})

    def test_scenario_contract_requires_frag_and_typed_options(self) -> None:
        no_options = eval_check.Packet(make_datagram(b"", surplus=make_surplus(b"\x00\x00", 8), dst_port=41004))
        with self.assertRaisesRegex(eval_check.CheckError, "frag option kinds"):
            eval_check.validate_sender_groups({41004: [no_options]}, {41004}, {41004: "frag"})

        payload = b"wire"
        apc_region = bytes((2, 6)) + eval_check.crc32c(payload).to_bytes(4, "big") + b"\x00\x00"
        only_apc = eval_check.Packet(
            make_datagram(payload, surplus=make_surplus(apc_region, 8 + len(payload)), dst_port=41001)
        )
        with self.assertRaisesRegex(eval_check.CheckError, "typed option kinds"):
            eval_check.validate_sender_groups({41001: [only_apc]}, {41001}, {41001: "typed"})

    def test_nat_checks_observed_masquerade_but_allows_total_drop(self) -> None:
        eval_check.validate_nat_observation({41000: []})
        eval_check.validate_nat_observation({41000: [SimpleNamespace(src=eval_check.NAT_RECEIVER_SOURCE)]})
        with self.assertRaisesRegex(eval_check.CheckError, "did not use masquerade source"):
            eval_check.validate_nat_observation({41000: [SimpleNamespace(src="10.9.1.1")]})


class ArtifactValidationTests(unittest.TestCase):
    def test_crc32c_reference_vector(self) -> None:
        self.assertEqual(eval_check.crc32c(b"123456789"), 0xE3069283)

    def test_payload_is_proven_against_manifest(self) -> None:
        payload = b"wire"
        payload_crc = eval_check.crc32c(payload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "send.jsonl"
            receiver = root / "recv.jsonl"
            manifest.write_text(
                json.dumps({"payload_len": len(payload), "payload_crc32c": payload_crc}) + "\n",
                encoding="utf-8",
            )
            receiver.write_text(
                json.dumps(
                    {
                        "delivery": "payload",
                        "payload_len": len(payload),
                        "payload_crc32c": payload_crc,
                        "payload_hex": payload.hex(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            summary = eval_check.validate_artifact_pair(manifest, receiver, require_delivery=True)
            self.assertEqual(summary["payload_records"], 1)

            receiver.write_text("{not-json}\n", encoding="utf-8")
            with self.assertRaisesRegex(eval_check.CheckError, "invalid JSON"):
                eval_check.validate_artifact_pair(manifest, receiver, require_delivery=True)

    def test_self_consistent_unexpected_payload_is_rejected(self) -> None:
        expected = b"wire"
        delivered = b"other"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "send.jsonl"
            receiver = root / "recv.jsonl"
            manifest.write_text(
                json.dumps(
                    {"payload_len": len(expected), "payload_crc32c": eval_check.crc32c(expected)}
                )
                + "\n",
                encoding="utf-8",
            )
            receiver.write_text(
                json.dumps(
                    {
                        "delivery": "payload",
                        "payload_len": len(delivered),
                        "payload_crc32c": eval_check.crc32c(delivered),
                        "payload_hex": delivered.hex(),
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(eval_check.CheckError, "absent from sender manifest"):
                eval_check.validate_artifact_pair(manifest, receiver, require_delivery=False)

    def test_filter_allows_only_an_empty_receiver_artifact(self) -> None:
        payload = b"wire"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "send.jsonl"
            receiver = root / "recv.jsonl"
            manifest.write_text(
                json.dumps({"payload_len": len(payload), "payload_crc32c": eval_check.crc32c(payload)}) + "\n",
                encoding="utf-8",
            )
            receiver.write_text("", encoding="utf-8")
            summary = eval_check.validate_artifact_pair(
                manifest,
                receiver,
                require_delivery=False,
                forbid_receiver_records=True,
            )
            self.assertEqual(summary["receiver_records"], 0)

            receiver.write_text(json.dumps({"delivery": "dropped"}) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(eval_check.CheckError, "not a total drop"):
                eval_check.validate_artifact_pair(
                    manifest,
                    receiver,
                    require_delivery=False,
                    forbid_receiver_records=True,
                )

    def test_manifest_identification_matches_fragmentation_state(self) -> None:
        payload = b"wire"
        record = {
            "identification": None,
            "payload_len": len(payload),
            "payload_crc32c": eval_check.crc32c(payload),
            "datagrams": 1,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "send.jsonl"
            receiver = root / "recv.jsonl"
            receiver.write_text("", encoding="utf-8")
            manifest.write_text(json.dumps(record) + "\n", encoding="utf-8")
            eval_check.validate_artifact_pair(
                manifest,
                receiver,
                require_delivery=False,
                scenario="baseline",
                expected_datagrams=1,
            )

            record["identification"] = 0x11223344
            manifest.write_text(json.dumps(record) + "\n", encoding="utf-8")
            eval_check.validate_artifact_pair(
                manifest,
                receiver,
                require_delivery=False,
                scenario="frag",
                expected_identification=0x11223344,
                expected_datagrams=1,
            )
            with self.assertRaisesRegex(eval_check.CheckError, "does not match"):
                eval_check.validate_artifact_pair(
                    manifest,
                    receiver,
                    require_delivery=False,
                    scenario="frag",
                    expected_identification=0x55667788,
                    expected_datagrams=1,
                )


if __name__ == "__main__":
    unittest.main()
