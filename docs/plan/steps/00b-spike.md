# Step 0.5: Surplus-area spike over a staged MTU-limited link (throwaway)

Status: implemented; verified green in the `dev` service (awaiting review/commit)

## Goal

De-risk the project's core premise *before* building any RFC 9868 machinery: confirm that a UDP
datagram whose `UDP Length` is smaller than the IP `Total Length` -- i.e. one carrying trailing
**surplus area** bytes -- survives a raw send -> raw recv round-trip over a realistic, **MTU-limited**
path, and pin down what the raw-socket send/recv layer does at the boundaries.

This is a **walking skeleton**, not a conformance step: arbitrary surplus bytes, no OCS, no TLV
options, no FRAG, no IPv6, no library wiring. Its findings fold into the real Steps 8-9
(`src/socket/{send,recv}.rs`), after which the spike can be deleted. It also **prototypes the Step 17
netns/veth harness**.

## Why a staged link, not loopback

The `dev` container's loopback MTU is 65536, so loopback never fragments and never constrains a
datagram -- a surplus of any size "just fits", which proves nothing about a real path. So the spike
stages a **veth pair split across two network namespaces**, both ends at **MTU 1500**: the only way
to make the MTU actually bite (a veth with both ends in one namespace short-circuits via local
delivery and never clocks the packet across the wire). Because a network namespace is per-process,
the sender and receiver are **separate processes** -- a client (default netns, 10.0.0.1) and a server
(netns `spk`, 10.0.0.2).

## Findings (the point of the spike)

Two behaviours of the Linux raw `IP_HDRINCL` path, confirmed on the wire, shape everything downstream.
Both were checked against RFC 9868 (§5, §8, §11.4, §21) with no contradictions -- they are Linux
host-stack behaviours that are *consistent with* (Finding A) and *motivate* (Finding B) the RFC, not
RFC requirements:

- **Finding A -- IP Total Length is forced to the buffer length.** Writing a smaller IP Total Length
  than the bytes handed to the kernel does not hide the trailing bytes: the kernel rewrites IP Total
  Length to the buffer length, so every appended byte is delivered as surplus. The originally
  hypothesised "append bytes *beyond* IP Total Length so the receiver can't see them" is therefore
  unconstructable on this path (`hide-attempt` demonstrates it). This is consistent with the RFC's
  surplus model: §21 redefines the IP payload "beyond the UDP Length but within the IP Length" as the
  surplus, and §8 has options use the *entire* surplus area, so no addressable region exists *beyond*
  IP Length -- the kernel rewrite is a host-stack detail the RFC does not speak to.
- **Finding B -- the `IP_HDRINCL` path will not fragment.** A send larger than the link MTU fails
  with `EMSGSIZE` (even with DF clear), where a normal UDP socket would fragment. So a surplus plus
  its UDP data must fit within one MTU-sized datagram; larger logical payloads need RFC 9868's FRAG
  option (Steps 11-12), not IP fragmentation (`over-mtu` demonstrates it). The RFC independently argues
  against IP fragmentation for UDP Options: §5 and §11.4 introduce FRAG to carry messages "larger than
  allowed by the IP MTU/EMTU_R" while copying the transport ports into each fragment (unlike IP
  fragments). So the local-API limit (`EMSGSIZE`) and the RFC's path argument converge on "use FRAG".

## Components

- `examples/common/mod.rs` -- shared constants, the case table, `build_datagram`, `match_marker`, the
  RFC 1071 / UDP checksums, and `IP_HDRINCL` setup (the only `unsafe`, inline and minimal).
- `examples/spike_client.rs` -- default netns; raw `IP_HDRINCL` send of each case to 10.0.0.2; gates
  the send-limit case (`over-mtu` must fail `EMSGSIZE`).
- `examples/spike_server.rs` -- netns `spk`; raw `SOCK_RAW`/`IPPROTO_UDP` recv (the kernel delivers
  full, reassembled datagrams); per-case checks the surplus arrived intact; gates delivery.
- `scripts/spike.sh` -- orchestrator: creates the netns + veth + MTU-1500 link, builds, runs server
  then client in their namespaces, prints the report, and tears the link down (`trap ... EXIT`).
  Subcommands `up` / `down` / `--keep` for manual `tcpdump -i veth-h` inspection.

## Cases

- `sweep-0/8/40/max` -- a surplus of 0/8/40/**1472** bytes inside a `<= 1500` datagram (the last is
  the maximum surplus that fits one MTU); each must arrive byte-for-byte intact. (gating, server)
- `hide-attempt` -- fill the UDP payload, write an IP Total Length that declares *no* surplus, append
  40 bytes anyway; the receiver still sees all 40 (Finding A). (gating, server)
- `over-mtu` -- a 3000-byte datagram; the send must fail `EMSGSIZE` (Finding B). (gating, client)

## Tasks

- [x] `examples/common/mod.rs`: constants, case table, datagram builder, marker matcher, checksums.
- [x] `examples/spike_client.rs`: raw `IP_HDRINCL` send; `EMSGSIZE` assertion for `over-mtu`.
- [x] `examples/spike_server.rs`: raw recv, surplus extraction, per-case PASS/FAIL, Finding-A note.
- [x] `scripts/spike.sh`: netns/veth/MTU-1500 setup, run, trap teardown; `up`/`down`/`--keep`.

## Definition of Done

- `docker compose run --rm dev sudo -E scripts/spike.sh` prints the per-case report and exits 0:
  `sweep-*` and `hide-attempt` PASS on the server (with the Finding-A note on `hide-attempt`),
  `over-mtu` PASS on the client (`EMSGSIZE`, Finding B). (`-E` keeps the dev `HOME` so cargo finds its
  cache; the link setup needs `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`, effective for root via `sudo`.)
- Teardown leaves no `spk` netns, `veth-h`, or readiness file behind.
- Optional wire check: `scripts/spike.sh up`, then `tcpdump -i veth-h -n -v` shows IP Total Length
  tracking the buffer length (Finding A); `scripts/spike.sh down` to clean up.
- Build / `fmt --check` / `clippy --all-targets -D warnings` stay green with the examples present.
