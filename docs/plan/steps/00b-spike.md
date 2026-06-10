# Step 0.5: Surplus-area spike over a staged MTU-limited link (throwaway)

Status: done; verified on `achim` (spike lane exit 0 plus a tcpdump wire check on `veth-h`)

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

Loopback has a large MTU, so it never fragments and never constrains a datagram -- a surplus of any
size "just fits", which proves nothing about a real path. So the spike stages a **veth pair split
across two network namespaces**, both ends at **MTU 1500**: the only way to make the MTU actually
bite (a veth with both ends in one namespace short-circuits via local delivery and never clocks the
packet across the wire). Because a network namespace is per-process, the sender and receiver are
**separate processes** -- a client (default netns, 10.0.0.1) and a server (netns `spk`, 10.0.0.2).

## Findings (the point of the spike)

Three behaviours of the Linux raw-socket path, confirmed on the wire, shape everything downstream.
All were checked against RFC 9868 (§5, §8, §11.4, §21) with no contradictions -- they are Linux
host-stack behaviours that are *consistent with* (Finding A), *motivate* (Finding B), or *put the
burden on the receiver exactly where the RFC's receive order expects it* (Finding C), not RFC
requirements:

- **Finding A -- IP Total Length is forced to the buffer length.** Writing a smaller IP Total Length
  than the bytes handed to the kernel does not hide the trailing bytes: the kernel rewrites IP Total
  Length to the buffer length, so every appended byte is delivered as surplus. The originally
  hypothesised "append bytes *beyond* IP Total Length so the receiver can't see them" is therefore
  unconstructable on this path (the `under` variants demonstrate it). This is consistent with the RFC's
  surplus model: §21 redefines the IP payload "beyond the UDP Length but within the IP Length" as the
  surplus, and §8 has options use the *entire* surplus area, so no addressable region exists *beyond*
  IP Length -- the kernel rewrite is a host-stack detail the RFC does not speak to.
- **Finding B -- the `IP_HDRINCL` path will not fragment.** A send larger than the link MTU fails
  with `EMSGSIZE` (even with DF clear), where a normal UDP socket would fragment. So a surplus plus
  its UDP data must fit within one MTU-sized datagram; larger logical payloads need RFC 9868's FRAG
  option (Steps 11-12), not IP fragmentation (every over-MTU combo demonstrates it). The RFC independently argues
  against IP fragmentation for UDP Options: §5 and §11.4 introduce FRAG to carry messages "larger than
  allowed by the IP MTU/EMTU_R" while copying the transport ports into each fragment (unlike IP
  fragments). So the local-API limit (`EMSGSIZE`) and the RFC's path argument converge on "use FRAG".
- **Finding C -- the raw receive path delivers without any UDP-level validation.** A zero UDP
  checksum, a deliberately wrong checksum, a UDP Length field claiming more bytes than the IP
  datagram holds, and a UDP Length below 8 all arrive at the `SOCK_RAW`/`IPPROTO_UDP` socket
  unfiltered (the four header-anomaly cases). The kernel's UDP checksum/length checks
  live in the `SOCK_DGRAM` delivery path, which raw sockets bypass. Consequence: the Step 10
  receive pipeline must itself verify the UDP checksum and the UDP Length consistency before
  trusting the surplus math -- which is precisely the first two steps of RFC 9868's receive order.

## Components

- `examples/common/mod.rs` -- shared constants, the case generator `cases()`, `build_datagram`,
  `match_marker`, the RFC 1071 / UDP checksums, and `IP_HDRINCL` setup (the only `unsafe`, inline
  and minimal).
- `examples/spike_client.rs` -- default netns; raw `IP_HDRINCL` send of each case to 10.0.0.2; gates
  the send-limit cases (every over-MTU combo must fail `EMSGSIZE`).
- `examples/spike_server.rs` -- netns `spk`; raw `SOCK_RAW`/`IPPROTO_UDP` recv (the kernel delivers
  full, reassembled datagrams); per-case checks the surplus arrived intact (wire combos) or logs
  the observed anomaly shape (`WireRaw`); gates delivery.
- `scripts/spike.sh` -- orchestrator: creates the netns + veth + MTU-1500 link, builds, runs server
  then client in their namespaces, prints the report, and tears the link down (`trap ... EXIT`).
  Subcommands `up` / `down` for manual `tcpdump -i veth-h` inspection.

## Cases

The hand-written table became a deterministic generator (`cases()` in `examples/common/mod.rs`,
97 cases); client and server build the identical list, and the expectation per case is *derived*
(physical size > MTU -> `SendFails`, else `Wire`), never listed by hand.

- **Cross product** (92 combos): user-data sizes `{0, 1, 13, 1392}` x surplus sizes
  `{0, 1, 8, 39, 40, 1471, 1472, 1473}` x written-IP-Total-Length variants `honest` (= physical),
  `under` (declares *no* surplus -- the old `hide-attempt`; only when there is one), and `over`
  (declares 40 bytes more than the buffer). The dims cross the MTU boundary from both sides for
  every user-data size (e.g. `d0-s1472` arrives, `d0-s1473` fails `EMSGSIZE`, `d1392-s1471`
  fails); odd sizes are covered on both axes. The `under`/`over` variants confirm Finding A in
  *both* directions: the kernel rewrites a lying IP Total Length to the buffer length whether it
  understates or overstates (42 delivered cases carried a lying value; all arrived with
  total == buffer).
- `over-mtu-3000` -- the far-over-MTU case kept from the original table (Finding B). (gating, client)
- **Header-anomaly cases** (4, `WireRaw`): does the kernel validate anything UDP-level before
  handing the datagram to `SOCK_RAW`/`IPPROTO_UDP`? `cksum-zero` (checksum 0 = "no checksum"),
  `cksum-bad` (deliberately wrong checksum), `len-overclaim` (UDP Length field 500 of 48
  available bytes), `len-under-8` (UDP Length 4, shorter than the UDP header). Gated only on
  *arrival*; the observed shape is logged, not judged. Result -- **Finding C: all four are
  delivered.** The raw-socket receive path bypasses UDP-level validation entirely (no
  checksum check, no length-consistency check), so the Step 10 receive pipeline must validate
  the UDP checksum and the UDP Length itself, exactly as RFC 9868's receive order prescribes.

## Tasks

- [x] `examples/common/mod.rs`: constants, case table, datagram builder, marker matcher, checksums.
- [x] `examples/spike_client.rs`: raw `IP_HDRINCL` send; `EMSGSIZE` assertions for the over-MTU combos.
- [x] `examples/spike_server.rs`: raw recv, surplus extraction, per-case PASS/FAIL, Finding-A note.
- [x] `scripts/spike.sh`: netns/veth/MTU-1500 setup, run, trap teardown; `up`/`down`.
- [x] Expand the table into the combinatorial generator + anomaly cases (Finding C).

## Definition of Done

- `scripts/vm-ubuntu-server.sh spike` prints the per-case report and exits 0: all 69 deliverable
  cases (65 wire combos + 4 anomaly cases) PASS on the server (with Finding-A notes on the
  lying-Total-Length variants), all 28 over-MTU combos PASS on the client (`EMSGSIZE`, Finding B).
  (The lane cross-builds the examples on the Mac, syncs the static musl binaries to `achim`, and
  runs `scripts/spike.sh` there with `SPIKE_SKIP_BUILD=1` and `SPIKE_BIN_DIR=bin`; spike.sh
  re-execs itself under `sudo env ...` for link setup and raw sockets.)
- Teardown leaves no `spk` netns, `veth-h`, or readiness file behind.
- Optional wire check: `scripts/spike.sh up`, then `tcpdump -i veth-h -n -v` shows IP Total Length
  tracking the buffer length (Finding A); `scripts/spike.sh down` to clean up.
- Build / `fmt --check` / `clippy --all-targets -D warnings` stay green with the examples present.
