# Step 2: Wire model (IpRepr, IP/UDP headers, surplus)

Status: pending

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

To be detailed when the step starts (reuse the Step 1 checksum accumulator for the pseudo-header).

## Tasks

- [ ] `IpRepr` methods (transport payload length, pseudo-header seed) for V4 and V6.
- [ ] IPv4 + IPv6 header parse/build with round-trip tests.
- [ ] `UdpHeader` parse/build + UDP checksum.
- [ ] `locate_surplus` with even/odd cases.

## Definition of Done

- Round-trip parse->build equality for IPv4, IPv6, and UDP headers; the UDP checksum matches a
  known-good captured datagram; `locate_surplus` returns the correct offset and pad flag for even and
  odd starts.
