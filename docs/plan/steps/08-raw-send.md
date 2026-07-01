# Step 8: Raw socket send/recv path

Status: done (Linux, requires CAP_NET_RAW)

## Goal

Send and receive datagrams with a surplus area over Linux raw sockets, proving the kernel-facing
premise in one root-gated round trip. Step 9 is merged here: raw send and raw receive are
implemented and verified together as one socket step.

## Design decisions (locked at planning; see the "Rationale" section)

- **Pure assembly, thin I/O.** A pure, `cfg`-free, `unsafe`-free `assemble_datagram(...)` composes the
  full IP datagram from the existing wire/options primitives; only the two thin socket wrappers are
  privileged. This mirrors the receive side (`recv::pipeline` pure vs `socket::recv` privileged).
- **Assembly lives in `src/socket/send.rs`.** It needs both `wire::{ip,udp}` and `options::{serialize
  output, ocs}`. Since `options` sits **above** `wire` (`options::ocs` imports `wire::checksum`; `wire`
  never imports `options`), a hypothetical `wire::assemble` would invert that layering. `socket` sits
  above both, so a pure helper there is layering-clean and reusable by the later `api` layer.
- **Loopback demux is by `(dst_port, src_port)`, not by source address.** On `127.0.0.1` in one
  process `src == dst == 127.0.0.1`, so an `ip.src == own_src` own-source filter would discard the
  very datagram the DoD must receive. The source-address own-source skip is a real-NIC/netns measure
  (Step 17) and is **off** on loopback; the source port is caller-chosen and untouched by the kernel
  under `IP_HDRINCL`, so it is the reliable userspace demux key. IP Identification is **not** usable
  as a marker (the kernel may overwrite it, limitation L1).
- **`assemble_datagram` returns `Vec<u8>`, not `Result<_, SerializeError>`.** `SerializeError` is
  reserved for option serialization; a too-large datagram is not caught here but surfaces at send time
  as `EMSGSIZE` (Step 0.5 Finding B). Structural invariants are `debug_assert`ed.

## Requirements

- Send: an `AF_INET` `SOCK_RAW` socket with `IP_HDRINCL` set (via `socket2`).
- Send: build the IP header, the UDP header with UDP Length < IP Total Length (creating the surplus
  area), and the surplus area from Steps 5/6.
- Send: compute the UDP checksum and the OCS in userspace (the kernel does not for raw sockets).
- Send: set the IP Total Length explicitly to the buffer length and rely on the kernel's `IP_HDRINCL`
  field-fill behavior (Step 0.5 Finding A: the kernel forces Total Length to the buffer length and
  recomputes the IP header checksum, so the explicit value must equal the buffer length for nothing to
  change on the wire).
- Receive: an `AF_INET` `SOCK_RAW` `IPPROTO_UDP` socket that receives full incoming IP datagrams,
  including the surplus area; it performs **no** UDP-level validation (Finding C: that is the Step 10
  pipeline's job).
- Receive: filter by destination port in userspace (raw sockets do no port demux); optionally also by
  source port for the loopback marker pair. A BPF filter is explicitly **not** used in this step
  (userspace filtering is simpler; revisit only if noise volume ever demands it).
- Receive: mitigate raw-socket noise by binding a dummy `SOCK_DGRAM` on the destination port to absorb
  ICMP port-unreachable, and by an optional source-address own-source skip (`own_src: Option<Ipv4Addr>`,
  `None` on loopback).
- A typed `RecvError::PermissionDenied` when the process lacks `CAP_NET_RAW` (`EPERM`/`EACCES`); any
  other I/O error, including a `> MTU` send's `EMSGSIZE`, maps to `RecvError::Io`.

## Lean verification

**Not applicable** for Step 8 (unchanged from the original scope). Socket I/O, the `IP_HDRINCL` kernel
behavior (Findings A/B), raw-socket delivery, port filtering, ICMP noise, and capabilities are system
effects, covered by the root-gated achim tests and Step 17.

The step adds one pure helper, `assemble_datagram`, but its postconditions (IP Total Length == buffer
length; UDP Length < IP Total Length; the emitted OCS validates) are already discharged by the
Steps 2/5/6 Lean spec plus the shared property/fuzz oracle that re-derives every offset from the
produced buffer and runs `ocs::validate`. A dedicated Lean obligation for `assemble_datagram` would be
contract-permitted (`LEAN_RFC9868_VALIDATION.md`, "pure buffer-building functions satisfy wire
postconditions") but would only re-chain already-proven primitives, so it is deliberately **not**
added here (Simplicity First). It may be picked up later as a human-gated follow-up.

## Plan

1. **Pure `assemble_datagram`** in `src/socket/send.rs` (no `cfg`, no `unsafe`, root-free):
   - `udp_len = 8 + user_data.len()`; `natural_start = 20 + udp_len`; `needs_pad = natural_start % 2 == 1`.
   - `surplus_len = needs_pad as usize + options_body.len()`; `total_len = 20 + udp_len + surplus_len`.
   - `IpRepr { src, dst, ihl: 5, total_len }.write(&mut buf[..20])` (writes the IP checksum).
   - `UdpHeader { .., length: udp_len, checksum: 0 }`, then `compute_checksum(&ip, user_data)` (covers
     the pseudo-header + UDP header + user data **only** — never the surplus), then `write`.
   - Copy `user_data`; leave the pad byte `0` when `needs_pad`; place `options_body` at
     `ocs_at = natural_start + needs_pad`.
   - `ocs::compute(&mut buf[ocs_at..ocs_at + options_body.len()], surplus_len as u16)` — `body` starts
     at the OCS field, `surplus_len` includes the pad (per `ocs.rs`).
   - `debug_assert_eq!(total_len as usize, buf.len())`, `debug_assert!(udp_len < total_len)`.
2. **`RawSender`** (`#[cfg(target_os = "linux")]`): open `AF_INET SOCK_RAW IPPROTO_UDP`, `set_hdrincl`
   (the one required `unsafe`, a private safe wrapper), `send(dst, datagram)` via
   `send_to(datagram, SocketAddrV4::new(dst, 0))` (the sockaddr port is ignored under `IP_HDRINCL`).
3. **`RawReceiver`** (`#[cfg(target_os = "linux")]`): open the `SOCK_RAW IPPROTO_UDP` socket, bind a
   dummy `SOCK_DGRAM` on `dst_port` (held for the receiver's lifetime; absorbs ICMP port-unreachable),
   `recv()` into a `MaybeUninit` buffer (the confined post-recv init `unsafe`), filter by
   `(dst_port[, src_port])`, apply the optional `own_src` skip, return the full raw IP-datagram bytes.
   No UDP/OCS/option validation here (Step 10 owns that; the pipeline does not yet exist).
4. **Error + cfg**: `EPERM`/`EACCES` -> `PermissionDenied`, else `Io`; strict
   `#[cfg(target_os = "linux")]` on every `libc`/`SOCK_RAW`/`IP_HDRINCL`/`MaybeUninit` touch, with
   `#[cfg(not(target_os = "linux"))]` stubs returning `io::ErrorKind::Unsupported` so the macOS host
   build, the two `src/bin` CLIs, and `clippy -D warnings` stay green. **No `#[cfg(unix)]`** (it
   includes macOS).
5. **Property + fuzz** (root-free, added this step): `tests/properties_assemble.rs` and
   `fuzz/fuzz_targets/socket_assemble.rs` (plus its `fuzz/Cargo.toml` `[[bin]]`) share one oracle via
   `include!` (the `tests/common/mod.rs` pattern). The oracle re-derives every offset from the buffer,
   **forces odd-start cases** so the pad/OCS split is exercised, asserts `ocs::validate` accepts the
   correct `surplus_len` and rejects a wrong one, and asserts the bytes from `ocs_at` equal the
   `OptionsBuilder` body after `compute`. No runtime file reads (achim ships only the test binary).
6. **Root-gated loopback round trip** (`#[ignore]`, `#[cfg(target_os = "linux")]`, single process on
   `127.0.0.1`, achim `ignored` lane under `ACHIM_SUDO=1`): `assemble -> RawSender.send -> RawReceiver.recv`.
   Assertions are made on the **re-parsed received** datagram (not the sent buffer — Finding A/L1).
7. **Docs (same commit)**: refine this contract; correct the `socket/send` module description in
   `architecture.md` (it currently says "builds the IP header" — assembly is the pure helper, the
   socket only writes); update `journal.html` (entry + `#reference` note on the loopback demux caveat)
   and `glossary.html`; bump the ROADMAP status. The throwaway spike (`examples/spike_*.rs`, the
   `vm-ubuntu-server.sh spike` lane, `scripts/spike.sh`) may be removed once this path subsumes it —
   optional cleanup, human's call.

## Tasks

- [x] Pure `assemble_datagram` (IP + UDP + user data + pad + OCS-led body); `debug_assert` invariants.
- [x] `RawSender`: `SOCK_RAW` + `IP_HDRINCL` (single safe `unsafe` wrapper) + `send`.
- [x] `RawReceiver`: `SOCK_RAW`/`IPPROTO_UDP` recv + dummy `SOCK_DGRAM` ICMP sink + `(dst_port, src_port)`
      userspace filter + optional `own_src` skip; returns raw datagram bytes.
- [x] Privilege preflight + error mapping (`EPERM`/`EACCES` -> `PermissionDenied`; `EMSGSIZE` -> `Io`).
- [x] `cfg(target_os = "linux")` bodies + `cfg(not)` stubs; macOS host build + clippy stay green.
- [x] `tests/properties_assemble.rs` + `fuzz/fuzz_targets/socket_assemble.rs` sharing one odd-start-forcing oracle.
- [x] Root-gated `#[ignore]` loopback round trip; assertions on the re-parsed received datagram.
- [x] Docs: this file, `architecture.md` socket/send blurb, `journal.html`/`glossary.html`, ROADMAP status.

## Verification

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `scripts/vm-ubuntu-server.sh verify`
- `scripts/vm-ubuntu-server.sh ignored` (root-gated loopback round trip passed on `achim`)
- `scripts/pre-pr.sh` (all 11 lanes green in 390s)

## Definition of Done

Under a root-gated loopback test (single process, `127.0.0.1`, achim `ignored` lane):

- the bytes handed to the send socket equal the pure `assemble_datagram` output, which equals the
  serializer body after `ocs::compute` (byte-for-byte assert);
- on the **re-parsed received** datagram, IP Total Length == the sent buffer length (Finding A) and
  UDP Length < IP Total Length (the surplus area is present);
- the surplus bytes arrive byte-identical at the raw receive socket;
- a datagram sent to a different destination port is filtered out (userspace demux), deterministically
  (timeout-poll, no race);
- the dummy `SOCK_DGRAM` binds and the round trip completes with no ICMP-driven noise. (A hard
  "no ICMP on the wire" proof needs a separate sniffer and is deferred to Step 17; this step asserts
  the suppression is in place and the exchange is clean.)

Plus, root-free on every host: the property tests and the fuzz smoke pass; the macOS host build,
the two example CLIs, and `cargo clippy --all-targets -- -D warnings` stay green.

## Rationale

Planning review converged on:

- **Pure assembly outside the privileged/`unsafe`/`cfg` surface** so the crate's most testable logic
  (byte assembly, OCS back-patch offset, odd-start pad, the Total-Length invariant) is exercised by
  `cargo test`/proptest/fuzz without `CAP_NET_RAW`. Placed in `socket/send.rs` (not `wire::assemble`)
  to respect the `options`-above-`wire` layering that the code already follows.
- **The loopback own-source trap** as the single most dangerous flaw in the naive plan: source-address
  filtering breaks when `src == dst == 127.0.0.1`. Fixed by `(dst_port, src_port)` marker filtering,
  with `own_src` optional and off on loopback. This is also an FF1 finding (what userspace raw-socket
  demux can and cannot rely on) for the thesis insights inbox.
- **On-wire assertions must re-parse the received datagram**, since the kernel rewrites IP Total
  Length and the IP checksum under `IP_HDRINCL` (Finding A / L1); a build-time `debug_assert` on the
  sent buffer would over-claim.
