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

## Plan

To be detailed when the step starts.

## Tasks

- [ ] Socket creation + `IP_HDRINCL`.
- [ ] Packet assembly (IP + UDP + surplus) and checksums.
- [ ] Privilege preflight + error mapping.
- [ ] Root-gated loopback test asserting the on-wire bytes.

## Definition of Done

- Under a root-gated loopback test, the bytes handed to the socket equal the serializer output and
  the datagram on the wire has UDP Length < IP Total Length (true on-wire capture added in Step 9).
