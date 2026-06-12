# Step 8: Raw send path (IP_HDRINCL)

Status: pending (Linux, requires CAP_NET_RAW)

## Goal

Send a datagram with a surplus area over a raw socket, building all headers and checksums by hand.

## Requirements

- An `AF_INET` `SOCK_RAW` socket with `IP_HDRINCL` set (via `socket2`).
- Build the IP header, the UDP header with UDP Length < IP Total Length (creating the surplus area),
  and the surplus area from Steps 5/6.
- Compute the UDP checksum and the OCS in userspace (the kernel does not for raw sockets).
- Set the IP Total Length explicitly and handle the kernel's `IP_HDRINCL` field-fill behavior.
- A typed `PermissionError` when the process lacks `CAP_NET_RAW`.

## Lean verification

Not applicable for the socket path: socket I/O, `IP_HDRINCL` kernel behavior (Step 0.5 Findings
A/B), and capabilities are system effects, covered by the root-gated achim tests. No new Lean
obligations: the wire postconditions of the assembled buffer (IP Total Length = buffer length,
UDP Length < IP Total Length opening the surplus, UDP checksum and OCS per spec) are already the
Steps 2/5/6 scope. Only if this step adds pure packet-assembly helpers beyond those pieces may
their postconditions optionally be specced, per the `socket/*` section of
`LEAN_RFC9868_VALIDATION.md`.

## Plan

1. Create an AF_INET SOCK_RAW socket via `socket2`, set `IP_HDRINCL`, and map `EPERM` to
   `RecvError::PermissionDenied`.
2. Assemble the IP header (explicit Total Length), the UDP header (UDP Length < Total Length to open
   the surplus area), and the surplus (Steps 5 and 6); compute the UDP checksum and the OCS.
3. `sendto` the destination and assert the on-wire Total Length equals the buffer length (Step 0.5
   Finding A: with `IP_HDRINCL` the kernel forces Total Length to the buffer length and recomputes
   the IP checksum, so the explicit value must match the buffer for nothing to change on the wire).
4. Root-gated loopback test asserting the assembled bytes and that UDP Length < IP Total Length on
   the wire.

## Tasks

- [ ] Socket creation + `IP_HDRINCL`.
- [ ] Packet assembly (IP + UDP + surplus) and checksums.
- [ ] Privilege preflight + error mapping.
- [ ] Root-gated loopback test asserting the on-wire bytes.

## Definition of Done

- Under a root-gated loopback test, the bytes handed to the socket equal the serializer output and
  the datagram on the wire has UDP Length < IP Total Length (true on-wire capture added in Step 9).
