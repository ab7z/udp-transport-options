# Step 0.5: Loopback spike (throwaway)

Status: pending (Linux, requires CAP_NET_RAW to run)

## Goal

De-risk the project's core premise *before* building any RFC 9868 machinery: confirm that a UDP
datagram whose `UDP Length` is smaller than the IP `Total Length` -- i.e. one carrying trailing
**surplus area** bytes -- survives a raw send -> raw recv round-trip over `127.0.0.1` inside the
single Linux `dev` service.

This is a **walking skeleton**, not a conformance step. It sends **arbitrary** surplus bytes: no OCS,
no TLV options, no FRAG, no IPv6, no library wiring. If the local kernel or loopback stripped or
dropped the surplus area, we want to learn that here -- not at Step 9. Its findings fold into the real
Steps 8-9 (`src/socket/{send,recv}.rs`), after which the spike can be deleted.

## Requirements

- A single self-contained Cargo example, `examples/loopback_spike.rs` (one process, loopback only).
- Send side: an `AF_INET` `SOCK_RAW` socket with `IP_HDRINCL`; build the IPv4 + UDP headers by hand
  with `UDP Length == 8` (empty user data) and `IP Total Length = 20 + 8 + N`, so `N` arbitrary bytes
  form a genuine surplus area; compute a valid UDP checksum (over the pseudo-header + UDP header only,
  not the surplus) and the IPv4 header checksum.
- Receive side: an `AF_INET` `SOCK_RAW` `IPPROTO_UDP` socket that receives the full IP datagram; a
  read timeout; filter to the marker destination port in userspace; ignore non-matching datagrams.
- Assert the trailing surplus bytes arrive byte-for-byte intact; print a hexdump and a clear
  PASS/FAIL line; exit non-zero on mismatch, timeout, or missing `CAP_NET_RAW`.
- Reuses the already-declared `socket2` + `libc` deps; no compose changes (the `dev` service already
  carries `CAP_NET_RAW`). `unsafe` is inline and minimal -- the production path confines `unsafe` to
  `src/socket/`.

## Plan

1. Receiver thread: create the raw `IPPROTO_UDP` socket, set a read timeout, signal readiness, then
   loop until a datagram for the marker port arrives (or the timeout fires).
2. Main thread: assemble the IPv4 + UDP + surplus bytes, set `IP_HDRINCL`, and `sendto` `127.0.0.1`.
3. Compare the received surplus area against what was sent; report PASS/FAIL.

## Tasks

- [ ] `examples/loopback_spike.rs`: raw send (`IP_HDRINCL`) of arbitrary surplus bytes.
- [ ] Raw recv + userspace port filter + surplus extraction.
- [ ] PASS/FAIL assertion, hexdump, and `CAP_NET_RAW` / timeout error messages.

## Definition of Done

- `docker compose run --rm dev sudo -E cargo run --example loopback_spike` prints the received
  surplus hexdump and `PASS: surplus bytes survived loopback`, exiting 0 (raw sockets need effective
  `CAP_NET_RAW`, which is held by root via the container's passwordless `sudo`).
- Optionally confirmed on the wire with `tcpdump -i lo -X udp port 39016` showing `UDP Length` <
  `IP Total Length` (trailing bytes after the 8-byte UDP header).
- Build/`fmt --check`/`clippy --all-targets -D warnings` stay green with the example present.
