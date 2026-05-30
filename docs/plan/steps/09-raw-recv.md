# Step 9: Raw recv socket

Status: pending (Linux, requires CAP_NET_RAW)

## Goal

Receive full IP datagrams with the surplus area intact and hand them to the receive pipeline.

## Requirements

- An `AF_INET` `SOCK_RAW` `IPPROTO_UDP` socket that receives a copy of incoming UDP datagrams,
  including the surplus area.
- Filter by destination port in userspace (optionally via an attached BPF program).
- Mitigate raw-socket noise: own-source copies and ICMP port-unreachable when no normal UDP socket is
  bound (bind a dummy `SOCK_DGRAM` to absorb ICMP).
- This step proves the project's core premise: the surplus area arrives intact.

## Plan

1. Create an AF_INET SOCK_RAW IPPROTO_UDP socket; attach a BPF destination-port filter, or filter by
   port in userspace.
2. Bind a dummy SOCK_DGRAM on the port to absorb ICMP port-unreachable; skip own-source datagrams.
3. Receive full IP datagrams and hand the bytes to the pipeline (Step 10).
4. Root-gated loopback round-trip (with Step 8) asserting the surplus area arrives intact.

## Tasks

- [ ] Socket creation + receive loop.
- [ ] Port filtering + noise mitigation.
- [ ] Root-gated loopback test: send (Step 8) then receive; assert the surplus survives.

## Definition of Done

- A root-gated loopback round-trip shows the surplus bytes arriving intact; non-matching ports are
  filtered; no spurious ICMP is observed.
