# Step 2: Wire model (IpRepr, IP/UDP headers, surplus)

Status: done

## Goal

Provide the IP-version-generic header representation, IPv4/IPv6 and UDP header parse/build, the UDP
pseudo-header checksum, and the surplus-area location computation.

## Requirements

- `IpRepr` (V4 and V6) with `transport_payload_len()` and a pseudo-header seed for the UDP checksum.
- IPv4 header parse/build (IHL, Total Length, protocol, header checksum) and IPv6 header parse/build
  (Payload Length, Next Header, extension-header length accounting).
- `UdpHeader` parse/build and the UDP checksum over pseudo-header + UDP header + user data only.
- `locate_surplus(ip, transport_payload) -> Option<SurplusLayout>`: even start offset, the odd-start
  pad flag, and the surplus length. Surplus = transport payload length minus UDP Length.
- IP-version-agnostic where possible; only the address family differs.

## Plan

1. Implement `IpRepr::transport_payload_len()` (V4: `total_len - ihl*4`; V6: `payload_len -
   ext_hdr_len`) and a pseudo-header contribution (addresses, protocol 17, UDP length) that feeds the
   Step 1 accumulator.
2. IPv4 parse/build: read and emit IHL, Total Length, protocol, addresses, and the header checksum
   (20-byte header, no IP options). IPv6 parse/build: the fixed 40-byte header plus minimal
   extension-header length accounting for the in-scope cases.
3. `UdpHeader::parse`/`write` and `udp_checksum(ip, header, payload)` over pseudo-header + header +
   data, applying the IPv4 zero -> 0xFFFF rule.
4. `locate_surplus(ip, transport_payload)`: surplus = transport payload length - UDP length; derive
   the even start offset and the odd-start pad flag; return `None` when there is no surplus.
5. Test against a captured datagram and both even and odd surplus starts.

## Tasks

- [x] `IpRepr` methods (transport payload length, pseudo-header seed) for V4 and V6.
- [x] IPv4 + IPv6 header parse/build with round-trip tests.
- [x] `UdpHeader` parse/build + UDP checksum.
- [x] `locate_surplus` with even/odd cases.

## Definition of Done

- Round-trip parse->build equality for IPv4, IPv6, and UDP headers; the UDP checksum matches a
  known-good captured datagram; `locate_surplus` returns the correct offset and pad flag for even and
  odd starts.

## Outcome

- `IpRepr::{parse, write, header_len, transport_payload_len, pseudo_header_sum, src_addr, dst_addr}`
  in `src/wire/ip.rs`; `UdpHeader::{parse, write, compute_checksum}` plus `HEADER_LEN` in
  `src/wire/udp.rs`; `locate_surplus` in `src/wire/surplus.rs`.
- Two deviations from the plan sketch, both reflected in `docs/architecture.md`:
  `pseudo_header_sum` returns the Step-1 `Checksum` accumulator instead of a raw `u32` (every
  pseudo-header field flows through the existing `add_slice`/`add_u16` API, keeping `Checksum`
  closed), and header-level failures got their own datagram-drop error enum `HeaderError` in
  `src/error.rs` instead of reusing `ParseError`, whose contract is "options discarded, payload
  still delivered".
- Parse rules: IPv4 accepts IHL 5..=15 (options skipped undecoded) and verifies the header checksum;
  IPv6 skips Hop-by-Hop (legal only directly after the base header, RFC 8200 Sec. 4.1) and
  Destination Options by length and rejects Routing (its final-destination pseudo-header semantics,
  RFC 8200 Sec. 8.1, are out of scope), Fragment, AH, and ESP chains; `write` emits only the
  20-/40-byte base headers (building IP options or extension headers is out of scope).
  `locate_surplus` additionally returns `None` when the surplus cannot hold the aligned OCS plus any
  required pad byte (RFC 9868 Sec. 8 "enough space for the aligned OCS"); the FR-49 UDP-Length drop
  check stays a pipeline (Step 10) responsibility, `locate_surplus` is only defensive there.
- 23 unit tests over hand-verified vectors (a 33-byte IPv4 and a 53-byte IPv6 "hello" datagram whose
  checksums were independently computed and receiver-side verified, a computed-zero -> 0xFFFF
  vector, even/odd/minimal/no-room surplus layouts including IHL-6 and extension-header shifts, and
  a corrupt-input matrix covering every `HeaderError` variant plus misplaced/unsupported IPv6
  extension headers). An adversarial RFC review (second model) drove the Routing-header rejection,
  the Hop-by-Hop placement rule, and the minimal-surplus tests.
- Verified on the host and cross-compiled on `achim` (`scripts/vm-ubuntu-server.sh verify`).
