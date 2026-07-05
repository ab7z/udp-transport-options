# Step 10.5: Wire-verification lane (tcpdump + independent checker + tshark)

Status: done; verified on `achim` (wire lane exit 0, 10/10 scenarios; mutation check red, rc=1)

## Goal

Break the self-reference of the in-process test pyramid. Every other lane -- unit tests, property
tests, fuzzing, loopback round-trips -- verifies the implementation against itself: sender and
receiver share the same hand-rolled serializer, parser, and OCS code, so a self-consistent-but-wrong
bug (the same endianness, offset, or checksum-scope mistake on both sides) passes every round-trip.
This lane checks the **post-kernel wire bytes** with three instances that share nothing with the
Rust implementation:

1. **tcpdump** captures the probe's datagrams on `lo` (with `IP_HDRINCL` the kernel rewrites IP
   Total Length and the IP header checksum -- Step 0.5 Finding A -- so only a capture shows the
   true wire bytes).
2. **`scripts/wire-check.py`** (python3 stdlib only) re-decodes everything independently: its own
   pcap reader, its own RFC 1071 fold, its own CRC32C (Castagnoli) table, its own IPv4/UDP/TLV/OCS
   logic, and golden surplus bytes typed from `docs/wire-format.md` (section references annotate
   each golden). Computed fields (OCS, APC CRC) are always re-derived, never taken as goldens.
3. **tshark** (Wireshark's dissector engine, third-party code) reads the same capture offline; the
   checker asserts field-by-field agreement with its own decode of the L3/L4 layer, including UDP
   checksum validation -- if the UDP checksum ever covered the surplus area, tshark would flag it.

The hand-roll rule in `CLAUDE.md` applies to production code only; the python second oracle is a
test harness and deliberately re-implements the checksums.

## Scenarios

`examples/wire_probe.rs` sends one datagram per scenario to `127.0.0.1`, source port `0x9a00`
(39424), destination `0x9a68` (39528) + index -- above the spike marker range, so stale spike
traffic can never collide. The checker owns the mirrored table and fails on any port-set or byte
mismatch.

| # | Name | Shape | Pins on the wire |
|---|------|-------|------------------|
| 0 | `baseline` | hand-built, no surplus | negative control: `Total Length - 20 == UDP Length` |
| 1 | `canon-even` | APC+MDS+MRDS+REQ+RES, 4-byte user data | canonical must-support order, NOP alignment, EOL + zero-fill, OCS |
| 2 | `pad-odd` | REQ, 3-byte user data | the single zero pad byte before the OCS (odd natural start) |
| 3 | `frag-nonterm` | FRAG length 10, empty user data | FRAG TLV layout; patched Frag.Start = end of options |
| 4 | `frag-term` | FRAG length 12 (RDOS) | terminal FRAG layout |
| 5 | `ocs-forced-ffff` | Other(77) with a brute-forced 2-byte filler | computed OCS 0x0000 transmitted as 0xFFFF (Sec. 9) |
| 6 | `ext-len` | Other(11), 300-byte value | Length=255 marker + 16-bit Extended Length |
| 7 | `cksum0-ocs0` | hand-built: UDP checksum 0, OCS left 0 | the legal "OCS unused" pairing (Sec. 9); kernel leaves the zero UDP checksum untouched |
| 8 | `frag-data-nonterm` | FRAG + REQ + 64 bytes fragment data | Frag.Start points exactly at the fragment data; OCS covers options + data |
| 9 | `frag-data-term` | as 8, terminal (RDOS = 8 + 128) | terminal fragment with data |

Scenarios 0 and 7 are hand-built (via `IpRepr::write`/`UdpHeader::write`) because
`assemble_datagram` cannot emit them: it asserts an OCS-led body and always computes a real UDP
checksum and OCS. Scenario 5 brute-forces the filler through the production `ocs::compute`
(deterministic ascending scan, at most 65536 folds). Scenarios 8/9 append the fragment data to the
`OptionsBuilder::finish` body; `patch_frag_start` then points exactly at the data start, which the
checker re-derives from the captured layout instead of trusting the golden.

## Findings

- **tshark 4.6.4 has no RFC 9868 dissector.** `tshark -G fields` lists no `udp.options*` fields;
  the dissection shows only the UDP-Length-bounded payload and silently ignores the surplus area
  (no trailer item, no expert-info warning). Wireshark cannot currently serve as an options-level
  oracle; the L3/L4 fields remain the hard cross-check and the byte-level gate is the own checker.
- **`tcpdump -Q out` captures nothing on `lo`** (20 packets received by filter, 0 captured):
  loopback tap copies do not carry the `PACKET_OUTGOING` type libpcap's direction filter expects.
  The lane records both tap copies instead and the checker asserts they are byte-identical.
- **"received by filter" does not mean "written".** Without `--immediate-mode`, libpcap's
  TPACKET block batching kept matched packets in a kernel block past the SIGINT (observed under
  load: 34 received by filter, 6 written, 0 "dropped by kernel"); `-U` only flushes the dump
  file, not the kernel delivery. The pcap file header alone also does not prove the capture path
  is live -- under load the probe outran the filter attach. Hence: immediate mode, canary
  handshake before the probe, and stop-only-when-quiet.
- **Ubuntu confines tshark with an owner-based AppArmor profile.** Ubuntu's tcpdump drops
  privileges and chowns the pcap to `tcpdump:tcpdump`; tshark (even as root) is then denied the
  read. `tcpdump -Z root` keeps the capture root-owned so the offline dissection works.
- **The kernel leaves the UDP checksum field alone on the `IP_HDRINCL` path** (scenario 7 arrives
  with checksum 0x0000 on the wire), consistent with Step 0.5 Finding A: only IP Total Length and
  the IP header checksum are rewritten.
- Linux `lo` captures as `LINKTYPE_EN10MB` with a fake all-zero Ethernet header (not `DLT_NULL`).
- **A byte-palindrome checksum can mask an alignment bug.** The checker's first odd-pad OCS
  re-derivation grouped the RFC 1071 words one byte off (pad byte prepended) -- a one-byte shift
  byte-swaps a one's-complement sum. The scenario still passed because the `deadbeef` REQ body
  folds to exactly `0xA3A3`, whose byte-swap equals itself. Caught by cross-model review; the
  grouping now starts at the OCS (which is what the Sec. 8 alignment rule exists for) and the
  pad-odd token is chosen non-palindromic (`c0ffee01`), so a sender-side shift regression is
  detectable too.

## Lean verification

Not applicable: this is an empirical second oracle over socket/kernel behavior, exactly the layer
the Lean track excludes (like Steps 0.5 and 15). See `LEAN_RFC9868_VALIDATION.md`.

## Components

- `examples/wire_probe.rs` -- the traffic generator (scenario table above; permanent, unlike the
  Step 0.5 spike examples).
- `scripts/wire-check.py` -- the independent checker; also consumes the tshark CSV for the L3/L4
  field agreement check.
- `scripts/wire-check.sh` -- the orchestrator (spike.sh pattern: build before sudo, self-elevate):
  tcpdump capture (`--immediate-mode`, `-U`, `-Z root`) with a two-stage readiness handshake
  (pcap-header poll, then warm-up canaries on the dedicated port 39527 until one is visibly
  recorded), probe run, a stop-when-quiet poll on the dump file before the SIGINT, kernel-drop
  assertion, tshark CSV/verbose/expert artifacts, checker as the exit gate. Artifacts persist
  under `/tmp/udpopt-wire`.
- `scripts/vm-ubuntu-server.sh wire` -- cross-build + sync + remote run; `bootstrap` now also
  checks `tcpdump`/`tshark`/`python3` on achim.
- `scripts/pre-pr.sh` -- carries the lane after "achim verify" (the pre-PR gate therefore needs
  passwordless sudo on achim).

One-time prerequisite on achim: `sudo apt-get install -y tshark` (tcpdump and python3 ship with
Ubuntu Server; tshark 4.6.4 was installed and recorded here).

## Explicitly out of scope (other steps, not deferrals of this lane)

- Receiver dispositions (the Step 10 matrix) are not wire-observable; they stay with the pure
  pipeline tests and the Step 15 loopback suite.
- FRAG split/reassembly *logic* is Steps 11/12 -- the wire image of data-carrying fragments is
  already pinned here, and the lane should gain split-produced scenarios once `frag::split`
  exists.
- CLI end-to-end waits for Steps 14/15; real paths, middleboxes, and offloads are Step 17 / FF2.
- The UDP-checksum-zero case pins the *sender* wire image only; the receive-side disposition
  matrix around it is Step 10's.

## Tasks

- [x] `examples/wire_probe.rs`: 10 scenarios, hand-built shapes for 0/7, brute-forced OCS filler.
- [x] `scripts/wire-check.py`: independent pcap/IPv4/UDP/TLV/OCS/CRC32C checker + goldens + tshark
      cross-check.
- [x] `scripts/wire-check.sh`: capture orchestration, artifacts, exit gate.
- [x] `scripts/vm-ubuntu-server.sh`: `wire` command, sync of probe + checker, bootstrap tool checks.
- [x] `scripts/pre-pr.sh`: wire lane after "achim verify".
- [x] tshark installed on achim; version + dissector findings recorded above.

## Definition of Done

- `scripts/vm-ubuntu-server.sh wire` exits 0 and prints `wire-check: PASS (10/10 scenarios)`.
  (Verified on achim: tcpdump 4.99.6, tshark 4.6.4, python3 3.14.)
- Mutation proof: flipping a single surplus byte in the captured pcap makes the checker fail.
  (Verified: `b[-3] ^= 1` on the capture -> OCS re-derivation mismatch + golden TLV mismatch +
  fragment-pattern mismatch, exit 1; the clean capture re-checks to exit 0.)
- Host and cross `fmt`/`clippy -D warnings` stay green with the example present.
