# Roadmap: RFC 9868 (UDP Transport Options) in Rust

This is the master plan. It is executed **step by step** with a human in the loop: one reviewed git
commit per step on the `rfc9868-impl` branch. Each step has a detailed file under `steps/` holding its
**Requirements / Plan / Tasks / Definition-of-Done**. This roadmap is the index and the single place
that tracks status.

## Documents

- [`requirements.md`](../requirements.md) - functional and non-functional requirements, the RFC 9868
  conformance matrix, and the userspace/raw-socket limitations (feeds FF1).
- [`architecture.md`](../architecture.md) - module responsibilities, the data model with type and
  method signatures, the send/receive data flows, and the design rules.
- [`wire-format.md`](../wire-format.md) - byte-level reference: surplus-area layout, the OCS
  algorithm, the option TLV/extended forms, the option-kind registry, and the FRAG layouts.
- [`steps/`](steps/) - one file per step (0-17) with Requirements / Plan / Tasks / DoD.
- The repo-root [`CLAUDE.md`](../../CLAUDE.md) holds the working conventions and a condensed overview.

## Goal

Build a userspace, RFC 9868-conformant reference library for UDP Transport Options, plus example peer
CLIs, and an evaluation harness, to answer two research questions:

- **FF1:** which RFC 9868 requirements are fully / partially / not implementable in userspace over
  raw sockets?
- **FF2:** how far does the surplus area survive along real network paths, and how do NAT and filter
  devices treat datagrams that carry it?

## Locked decisions

- **Rust**, userspace only, **raw sockets** (no kernel modules, no TUN/TAP).
- **Linux only**, `AF_INET`/`AF_INET6` `SOCK_RAW`. Send uses `IP_HDRINCL` (we build the IP header so
  UDP Length can be smaller than IP Total Length, creating the surplus area; we compute the UDP
  checksum and the OCS ourselves). Receive uses a `SOCK_RAW` `IPPROTO_UDP` socket that gets full IP
  datagrams with the surplus area intact; port filtering in userspace. No Ethernet/L2 framing.
- **In scope:** TLV framework; OCS; must-support options (EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES);
  zero-copy parser; serializer; FRAG fragmentation + reassembly; two-tier API; IPv4 + IPv6; unit +
  loopback integration tests; example peer CLIs.
- **Out of scope:** TIME; AUTH/UCMP/UENC; RFC 9869 (DPLPMTUD); kernel modules; stateful protocols.

## Architecture

See `../../CLAUDE.md` for the module map and design rules (parse borrowed / decode owned;
IP-version-generic wire layer; pure pipeline vs privileged I/O).

Dependencies: `socket2` + `libc` (raw sockets), `thiserror` (errors), `crc32c` (APC), `clap` (CLIs),
`log` (diagnostics). Hand-rolled: RFC 1071 checksum, TLV parser/serializer, OCS.

## Steps and status

Legend: [ ] pending, [~] in progress, [x] done.

| # | Step | Definition of Done | Status |
|---|------|---------------------|--------|
| 0 | Bootstrap: lib+bin layout, deps, stub module tree, `model` consts, `CLAUDE.md`, this roadmap + step stubs, `rustfmt.toml`, `rust-toolchain.toml`, gitignore `.idea`, branch `rfc9868-impl`, Linux Docker image (`Dockerfile` + `compose.yml`) | `cargo build` + `fmt --check` + `clippy -D warnings` green (host and in-container); first commit present | [x] |
| 1 | RFC 1071 checksum primitive | unit tests vs RFC example + hand vectors (odd-length, all-zero); `sum + complement == 0` | [ ] |
| 2 | Wire model: `IpRepr` V4+V6, IPv4+IPv6 + UDP headers, pseudo-header checksum, `locate_surplus` | round-trip parse->build; UDP cksum vs known datagram; surplus offset+pad correct even/odd | [ ] |
| 3 | `OptionKind` model + SAFE/UNSAFE + must-support + framing rules | exhaustive table tests; `is_must_support` correct for 0..7 | [ ] |
| 4 | Zero-copy TLV parser (`OptionsIter`/`OptionRef`) | correct iteration; truncated/overrun/bad-extended each one `Err` + halt; no panic on random input | [ ] |
| 5 | Serializer (`OptionsBuilder`): ordering, NOP align, EOL + zero-fill, extended length | serialize->parse round-trip; canonical order; even length; golden-byte test | [ ] |
| 6 | OCS compute + validate (two-pass back-patch; odd-pad zero) | validates to 0; any byte flip fails; OCS==0-with-nonzero-UDP-cksum flagged | [ ] |
| 7 | Typed options: APC (CRC32C), MDS, MRDS, REQ, RES | each round-trips encode->parse->decode; APC vs `crc32c` + vector; wrong length -> `ParseError` | [ ] |
| 8 | Raw send path (`IP_HDRINCL`) | root-gated loopback: serializer bytes hit the socket unchanged; UDP Length < IP Total Length on wire | [ ] |
| 9 | Raw recv socket | root-gated loopback: **surplus bytes arrive intact**; ports filtered; no spurious ICMP | [ ] |
| 10 | Receive pipeline (pure) | table-driven tests cover deliver/discard, unknown SAFE/UNSAFE, cksum0 x OCS matrix, NOP flood (no root) | [ ] |
| 11 | FRAG fragmentation (send) | N bytes reassemble to N; atomic single-fragment valid; respects MRDS cap | [ ] |
| 12 | FRAG reassembly (recv) | in/out-of-order ok; overlap aborts; caps fire; GC; pairs isolated; no re-process loop | [ ] |
| 13 | Two-tier API + error types | `cargo doc` builds; high-level >MRDS send auto-fragments and recv reassembles transparently | [ ] |
| 14 | Example peer CLIs (`udpopt-send`/`udpopt-recv`) | `--help` works; documented loopback run sends options and the receiver prints them decoded | [ ] |
| 15 | Loopback integration suite (root-gated `--ignored` lane) | passes under `sudo -E cargo test -- --ignored`; skipped (not failed) without privilege | [ ] |
| 16 | IPv6 socket wiring (`AF_INET6`, `IPV6_HDRINCL`) | `::1` loopback round-trip with surplus + options + FRAG; pipeline path shared with v4 | [ ] |
| 17 | Evaluation runbook + netns/veth/tunnel scripts | scripts create the staged env on Linux; runbook reproduces integration results; quick-start verified | [ ] |

## Top risks (Linux AF_INET raw) and mitigations

- **Raw recv duplicate/ICMP noise**: bind a dummy `SOCK_DGRAM` to absorb ICMP port-unreachable;
  filter own-source in userspace (Step 9).
- **`IP_HDRINCL` field fill** (kernel may set Total Length if 0, computes the IP checksum, may rewrite
  Identification): set Total Length explicitly; Step 8 asserts Total Length > UDP Length on the wire.
- **CAP_NET_RAW / root**: keep the privileged surface to Steps 8, 9, 14-16; everything else is
  root-free; integration tests are `#[ignore]`-gated so "green" stays trustworthy.
- **Loopback != real NIC**: use `127.0.0.1`/`::1` plus a veth/netns path (Step 17); document offload
  disabling (`ethtool -K`).
- **Reassembly DoS**: per-pair byte/segment caps, global partial cap, <= 2 min timeout, GC,
  overlap -> abort (Step 12).
- **UDP cksum == 0 x OCS ambiguity**: explicit disposition matrix (Step 10).

## Verification

- Per step: the DoD above; `cargo build` + `cargo fmt --check` + `cargo clippy -- -D warnings` stay
  green; the step's unit tests pass.
- Functional (root-free): `cargo test`.
- Integration (root, Linux): `sudo -E cargo test -- --ignored`.
- On macOS, all Linux runtime steps go through the Docker Compose `dev` service, e.g.
  `docker compose run --rm dev sudo -E cargo test -- --ignored` (the container carries
  `NET_RAW`/`NET_ADMIN`, effective for root, so the root-gated lane runs via `sudo -E`).
- End-to-end: the `udpopt-send`/`udpopt-recv` CLIs over loopback, confirmed with a `tcpdump`/Wireshark
  capture showing the surplus area on the wire.
- Empirical (Step 17): the netns/veth runbook for the thesis's staged environments.
