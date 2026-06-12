# Roadmap: RFC 9868 (UDP Transport Options) in Rust

This is the master plan. It is executed **step by step** with a human in the loop: one reviewed git
commit per step on `main`. Each step has a detailed file under `steps/` holding its
**Requirements / Plan / Tasks / Definition-of-Done**. This roadmap is the index and the single place
that tracks status.

## Documents

- [`requirements.md`](../requirements.md) - functional and non-functional requirements, the RFC 9868
  conformance matrix, and the userspace/raw-socket limitations (feeds FF1).
- [`architecture.md`](../architecture.md) - module responsibilities, the data model with type and
  method signatures, the send/receive data flows, and the design rules.
- [`wire-format.md`](../wire-format.md) - byte-level reference: surplus-area layout, the OCS
  algorithm, the option TLV/extended forms, the option-kind registry, and the FRAG layouts.
- [`steps/`](steps/) - one file per step (0-15, 17; 16 removed with IPv6) with Requirements / Plan / Tasks / DoD.
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
- **Linux only**, `AF_INET` `SOCK_RAW`. Send uses `IP_HDRINCL` (we build the IP header so
  UDP Length can be smaller than IP Total Length, creating the surplus area; we compute the UDP
  checksum and the OCS ourselves). Receive uses a `SOCK_RAW` `IPPROTO_UDP` socket that gets full IP
  datagrams with the surplus area intact; port filtering in userspace. No Ethernet/L2 framing.
- **In scope:** TLV framework; OCS; must-support options (EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES);
  zero-copy parser; serializer; FRAG fragmentation + reassembly; two-tier API; IPv4; unit +
  loopback integration tests; example peer CLIs.
- **Out of scope:** IPv6; TIME; AUTH/UCMP/UENC; RFC 9869 (DPLPMTUD); kernel modules; stateful protocols.

## Architecture

See `../../CLAUDE.md` for the module map and design rules (parse borrowed / decode owned;
IPv4-only wire layer; pure pipeline vs privileged I/O).

Dependencies: `socket2` + `libc` (raw sockets), `thiserror` (errors), `crc32c` (APC), `clap` (CLIs),
`log` (diagnostics). Hand-rolled: RFC 1071 checksum, TLV parser/serializer, OCS.

## Steps and status

Legend: [ ] pending, [~] in progress, [x] done.

| # | Step | Definition of Done | Status |
|---|------|---------------------|--------|
| 0 | Bootstrap: lib+bin layout, deps, stub module tree, `model` consts, `CLAUDE.md`, this roadmap + step stubs, `rustfmt.toml`, `rust-toolchain.toml`, gitignore `.idea`, musl cross target + `achim` remote run setup | `cargo build` + `fmt --check` + `clippy -D warnings` green (host and `--target aarch64-unknown-linux-musl`); first commit present | [x] |
| 0.5 | Spike (throwaway): client/server raw send->recv of **arbitrary** surplus bytes over a staged **1500-MTU veth link across two netns**, to de-risk surplus-area survival and the raw-socket send/recv limits before any machinery (folded into Steps 8-9; prototypes the Step 17 harness) | `scripts/spike.sh` exits 0: surplus survives intact up to the MTU; documents Finding A (`IP_HDRINCL` forces IP Total Length = buffer) and Finding B (`IP_HDRINCL` won't fragment, >MTU send -> `EMSGSIZE`) | [x] |
| 1 | RFC 1071 checksum primitive | unit tests vs RFC example + hand vectors (odd-length, all-zero); `sum + complement == 0` | [x] |
| 2 | Wire model: `IpRepr` (IPv4), IPv4 + UDP headers, pseudo-header checksum, `locate_surplus` | round-trip parse->build; UDP cksum vs known datagram; surplus offset+pad correct even/odd | [x] |
| 3 | `OptionKind` model + SAFE/UNSAFE + must-support + framing rules | exhaustive table tests; `is_must_support` correct for 0..7 | [ ] |
| 4 | Zero-copy TLV parser (`OptionsIter`/`OptionRef`) | correct iteration; truncated/overrun/bad-extended each one `Err` + halt; no panic on random input | [ ] |
| 5 | Serializer (`OptionsBuilder`): ordering, NOP align, EOL + zero-fill, extended length | serialize->parse round-trip; canonical order; even length; golden-byte test | [ ] |
| 6 | OCS compute + validate (two-pass back-patch; odd-pad zero; computed 0x0000 sent as 0xFFFF) | validates (one's-complement zero); any byte flip fails; OCS==0-with-nonzero-UDP-cksum flagged | [ ] |
| 7 | Typed options: APC (CRC32C), MDS, MRDS, REQ, RES | each round-trips encode->parse->decode; APC vs `crc32c` + vector; wrong length -> `ParseError` | [ ] |
| 8 | Raw send path (`IP_HDRINCL`) | root-gated loopback: serializer bytes hit the socket unchanged; UDP Length < IP Total Length on wire | [ ] |
| 9 | Raw recv socket | root-gated loopback: **surplus bytes arrive intact** (premise smoke-tested at Step 0.5); ports filtered; no spurious ICMP | [ ] |
| 10 | Receive pipeline (pure) | table-driven tests cover deliver/discard, unknown SAFE/UNSAFE, cksum0 x OCS matrix, NOP flood (no root) | [ ] |
| 11 | FRAG fragmentation (send) | N bytes reassemble to N; atomic single-fragment valid; respects MRDS cap | [ ] |
| 12 | FRAG reassembly (recv) | in/out-of-order ok; overlap aborts; caps fire; GC; pairs isolated; no re-process loop | [ ] |
| 13 | Two-tier API + error types | `cargo doc` builds; high-level send too large for one datagram auto-fragments (capped by peer MRDS, over-cap send fails) and recv reassembles transparently | [ ] |
| 14 | Example peer CLIs (`udpopt-send`/`udpopt-recv`) | `--help` works; documented loopback run sends options and the receiver prints them decoded | [ ] |
| 15 | Loopback integration suite (root-gated `--ignored` lane) | passes through `scripts/vm-ubuntu-server.sh ignored`; skipped (not failed) without privilege | [ ] |
| 17 | Evaluation runbook + netns/veth/tunnel scripts (prototyped by the Step 0.5 spike's `scripts/spike.sh`) | scripts create the staged env on Linux; runbook reproduces integration results; quick-start verified | [ ] |

The 15 -> 17 numbering gap is intentional: **step 16 removed from scope (IPv6), 2026-06** -- the
mechanism is IP-version-neutral and fully demonstrated on IPv4; IPv6 raw-socket semantics
(`IPV6_HDRINCL`) added platform fragility without protocol insight. Step numbers and FR IDs stay
stable (no renumbering).

## Top risks (Linux AF_INET raw) and mitigations

- **Surplus area stripped by the local stack** (the FF2 premise): de-risked up front by the Step 0.5
  spike over a staged 1500-MTU veth link, which proves `UDP Length` < `IP Total Length` survives raw
  send -> raw recv (up to the MTU) before any TLV/OCS/FRAG work begins; real path/middlebox survival
  is the separate Step 17 experiment.
- **Raw recv duplicate/ICMP noise**: bind a dummy `SOCK_DGRAM` to absorb ICMP port-unreachable;
  filter own-source in userspace (Step 9).
- **`IP_HDRINCL` field fill** (Step 0.5 Finding A: the kernel forces IP Total Length to the buffer
  length and recomputes the IP checksum): create the surplus by making the buffer longer than
  `UDP Length` implies -- IP Total Length then follows the buffer automatically; Step 8 asserts
  Total Length > UDP Length on the wire (consistent with RFC 9868 §8/§21, which bound the surplus by
  IP Length). Finding B: `IP_HDRINCL` will not fragment (>MTU -> `EMSGSIZE`), so datagrams must stay
  <= MTU and oversize logical payloads go through FRAG (RFC 9868 §5/§11.4 motivate FRAG for exactly
  this: messages larger than the IP MTU travel via FRAG, not IP fragmentation).
- **CAP_NET_RAW / root**: keep the privileged surface to Steps 8, 9, 14-15; everything else is
  root-free; integration tests are `#[ignore]`-gated so "green" stays trustworthy.
- **Loopback != real NIC**: use `127.0.0.1` plus a veth/netns path (Step 17); document offload
  disabling (`ethtool -K`).
- **Reassembly DoS**: per-pair byte/segment caps, global partial cap, <= 2 min timeout, GC,
  overlap -> abort (Step 12).
- **UDP cksum == 0 x OCS ambiguity**: explicit disposition matrix (Step 10).

## Verification

- Per step: the DoD above; `cargo build` + `cargo fmt --check` + `cargo clippy --all-targets -- -D
  warnings` stay green; the step's unit tests pass.
- Lean track (spec first): each step with Lean obligations extends the spec in
  `formal/lean-rfc9868/` *before* implementing and proves its theorems after (`lake build` green,
  no `sorry`) in the same step commit; the per-step "Lean verification" sections and
  `LEAN_RFC9868_VALIDATION.md` define the scope. Socket I/O and middlebox behavior stay outside
  the Lean claim (empirical lanes above).
- Before every PR (opening and updating): the mandatory local gate `scripts/pre-pr.sh` (host
  fmt/clippy/test with 1024 proptest cases, achim cross verify, time-boxed libFuzzer smoke). Every
  step that adds a parsing surface extends the property tests and fuzz targets in the same commit.
- Functional (root-free): `cargo test` locally, plus `scripts/vm-ubuntu-server.sh test`
  (cross-compiled test binaries execute on `achim` via the cargo runner).
- Integration (root, Linux on `achim`): `scripts/vm-ubuntu-server.sh ignored` (the runner executes
  the test binaries under sudo on `achim`).
- On macOS, all Linux runtime steps are cross-compiled for `aarch64-unknown-linux-musl` and only
  *executed* on `achim` via `scripts/vm-ubuntu-server.sh`, e.g. `verify` for the normal lane and
  `ignored` for root-gated tests; `achim` carries no Rust toolchain.
- End-to-end: the `udpopt-send`/`udpopt-recv` CLIs over loopback, confirmed with a `tcpdump`/Wireshark
  capture showing the surplus area on the wire.
- Empirical (Step 17): the netns/veth runbook for the thesis's staged environments.
