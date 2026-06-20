# Step 8: Raw socket send/recv path

Status: pending (Linux, requires CAP_NET_RAW)

## Goal

Send and receive datagrams with a surplus area over Linux raw sockets, proving the kernel-facing
premise in one root-gated round trip.

## Requirements

- Send: an `AF_INET` `SOCK_RAW` socket with `IP_HDRINCL` set (via `socket2`).
- Send: build the IP header, the UDP header with UDP Length < IP Total Length (creating the surplus
  area), and the surplus area from Steps 5/6.
- Send: compute the UDP checksum and the OCS in userspace (the kernel does not for raw sockets).
- Send: set the IP Total Length explicitly and handle the kernel's `IP_HDRINCL` field-fill behavior.
- Receive: an `AF_INET` `SOCK_RAW` `IPPROTO_UDP` socket that receives full incoming IP datagrams,
  including the surplus area.
- Receive: filter by destination port in userspace (optionally via an attached BPF program).
- Receive: mitigate raw-socket noise by skipping own-source copies and binding a dummy
  `SOCK_DGRAM` to absorb ICMP port-unreachable when no normal UDP socket is bound.
- A typed `PermissionError` when the process lacks `CAP_NET_RAW`.

## Lean verification

Not applicable for the socket path: socket I/O, `IP_HDRINCL` kernel behavior (Step 0.5 Findings
A/B), raw-socket delivery, port filtering, ICMP noise, and capabilities are system effects, covered
by the root-gated achim tests and Step 17. No new Lean obligations: the pure wire postconditions of
the assembled buffer (IP Total Length = buffer length, UDP Length < IP Total Length opening the
surplus, UDP checksum and OCS per spec) are already the Steps 2/5/6 scope. Only if this step adds
pure packet-assembly helpers beyond those pieces may their postconditions optionally be specced, per
the `socket/*` section of `LEAN_RFC9868_VALIDATION.md`.

## Plan

1. Create an AF_INET SOCK_RAW socket via `socket2`, set `IP_HDRINCL`, and map `EPERM` to
   `RecvError::PermissionDenied`.
2. Assemble the IP header (explicit Total Length), the UDP header (UDP Length < Total Length to open
   the surplus area), and the surplus (Steps 5 and 6); compute the UDP checksum and the OCS.
3. `sendto` the destination and assert the on-wire Total Length equals the buffer length (Step 0.5
   Finding A: with `IP_HDRINCL` the kernel forces Total Length to the buffer length and recomputes
   the IP checksum, so the explicit value must match the buffer for nothing to change on the wire).
4. Create an AF_INET SOCK_RAW IPPROTO_UDP receive socket; attach a BPF destination-port filter, or
   filter by port in userspace.
5. Bind a dummy SOCK_DGRAM on the port to absorb ICMP port-unreachable; skip own-source datagrams.
6. Receive full IP datagrams and hand the bytes to the pipeline (Step 10).
7. Root-gated loopback round trip asserting the assembled bytes, UDP Length < IP Total Length, and
   that the surplus area arrives intact.

## Tasks

- [ ] Socket creation + `IP_HDRINCL`.
- [ ] Packet assembly (IP + UDP + surplus) and checksums.
- [ ] Receive socket creation + receive loop.
- [ ] Port filtering + noise mitigation.
- [ ] Privilege preflight + error mapping.
- [ ] Root-gated loopback test: send then receive; assert the on-wire bytes and surviving surplus.

## Definition of Done

- Under a root-gated loopback test, the bytes handed to the send socket equal the serializer output,
  the datagram on the wire has UDP Length < IP Total Length, the surplus bytes arrive intact at the
  raw receive socket, non-matching ports are filtered, and no spurious ICMP is observed.
