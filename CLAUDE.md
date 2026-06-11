# CLAUDE.md

Guidance for Claude Code (and human contributors) working in this repository.

## Project overview

A userspace **reference implementation of RFC 9868 (Transport Options for UDP)** in Rust.
RFC 9868 (published October 2025) carries transport options in the **surplus area**.

The contribution is twofold and equally weighted:

1. an open-source, RFC 9868-conformant reference library of the core mechanisms for userspace, and
2. an empirical study of how far the surplus area survives real network paths and middleboxes
   (research questions FF1 and FF2 in the thesis).

The work proceeds **step by step** (not one-shot), agentic with a **human in the loop**: one reviewed
git commit per step on `main`. The authoritative plan is `docs/plan/ROADMAP.md`,
with a per-step file under `docs/plan/steps/`.

## Build and test commands

The library and binaries **compile** on any platform, but the raw-socket paths only **run** on Linux.

**`scripts/pre-pr.sh` is mandatory before opening or updating any PR.** Its lanes, fail-fast in
order: `cargo fmt --check`, host clippy (`-D warnings`), host `cargo test` with `PROPTEST_CASES`
(default 1024), `scripts/vm-ubuntu-server.sh verify` (achim cross build + test + fmt + clippy), and
a time-boxed libFuzzer smoke (`PRE_PR_FUZZ_SECONDS`, default 60s per target) on the macOS host.
One-time prerequisites: `rustup toolchain install nightly` and `cargo install cargo-fuzz`. The
achim ssh runner forwards no environment, so the cross-target property tests always run the
proptest default of 256 cases.

## Scope

In scope: the TLV options framework; the Option Checksum (OCS, RFC 9868 Section 9); the must-support
options EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES; a zero-copy parser and a serializer; FRAG
fragmentation and reassembly (cache, timeout, garbage collection, DoS limits); the two-tier API;
IPv4 and IPv6; unit tests and loopback integration tests; example sender/receiver peer CLIs.

Out of scope: the TIME option; the reserved AUTH/UCMP/UENC options; the REQ/RES-for-PMTUD use case of
RFC 9869 (DPLPMTUD); kernel modules; bidirectional/stateful protocols.

## Architecture (module map)

```
src/
  model.rs       protocol constants and limits (option kinds, fixed lengths, MRDS defaults, limits)
  error.rs       ParseError, RecvError
  wire/
    checksum.rs  RFC 1071 one's-complement Internet checksum            [hand-rolled]
    ip.rs        IpRepr { V4, V6 }: transport-payload length, pseudo-header seed; header parse/build
    udp.rs       UdpHeader parse/build + UDP checksum
    surplus.rs   SurplusLayout + locate_surplus()
  options/
    kind.rs      OptionKind + SAFE/UNSAFE + must-support classification
    parse.rs     OptionRef<'a> / OptionsIter<'a>: zero-copy, total, never panics   [hand-rolled]
    serialize.rs OptionsBuilder: must-support-first, NOP align, EOL + zero-fill     [hand-rolled]
    ocs.rs       compute/validate OCS (reserved-first, two-pass back-patch)         [hand-rolled]
    typed.rs     TypedOption trait + Copy structs: Apc, Mds, Mrds, Req, Res, Frag
    (mod.rs)     RawOption (owned counterpart of OptionRef)
  frag/
    split.rs     fragmentation (send): non-terminal/terminal fragments, atomic case
    reassembly.rs ReassemblyCache keyed by FragKey: offset-sort, overlap, timeout, GC, limits
  recv/
    pipeline.rs  process_datagram(): pure receive state machine (no I/O, root-free)
  socket/
    send.rs      raw send via IP_HDRINCL                                            [Linux, root]
    recv.rs      raw SOCK_RAW IPPROTO_UDP receive                                   [Linux, root]
  api/mod.rs     low-level (explicit options) + high-level (transparent OCS + FRAG)
  bin/           udpopt-send, udpopt-recv (example peer CLIs)
```

Design rules:

- **Parse borrowed, decode owned.** Only `OptionRef`/`OptionsIter` carry a lifetime; typed options
  are fixed-length `Copy` PODs. The borrow never crosses the public API boundary.
- **IP-version-generic from the wire layer.** `IpRepr` covers V4 and V6 so the surplus math, the UDP
  pseudo-header, and FRAG keying are written once. Only the `AF_INET6` socket wiring is V6-specific.
- **Pure pipeline vs privileged I/O.** `recv/pipeline.rs` is a pure function over byte buffers
  (root-free, fully unit-testable); the socket modules are thin and root-gated.
- **Strictly single-threaded and synchronous.** No threads, no async, no background tasks anywhere
  (library, binaries, tests, examples). Time-based logic (the FRAG reassembly timeout and GC) is
  caller-driven via a passed-in timestamp (`gc(&mut self, now: Instant)`), never a background thread.

## Key RFC 9868 facts

- The **surplus area** can begin at any byte offset; its leading **OCS** is aligned to the first
  2-byte boundary of the area relative to the IP datagram start. If the natural start is odd, a
  single `0x00` pad byte precedes the OCS, and that pad must be zero.
- **Option framing:** `Kind(1) [+ Length(1) + Value]`. EOL (0) and NOP (1) are single-byte (no
  Length). `Length == 255` selects the extended 2-byte length form.
- **Must-support kinds:** 0 EOL, 1 NOP, 2 APC (len 6, CRC32C of user data), 3 FRAG (len 10
  non-terminal / 12 terminal), 4 MDS (len 4), 5 MRDS (len 5), 6 REQ (len 6), 7 RES (len 6).
  SAFE = 0..=191, UNSAFE = 192..=255.
- **OCS** uses the RFC 1071 sum over the whole surplus area (with the OCS field treated as zero) plus
  the 16-bit surplus length; it must be the first content in the surplus area; the receiver checks
  that the sum is the one's-complement zero (folded sum `0xFFFF`). A computed `0x0000` is sent as
  `0xFFFF`; a zero OCS is legal only when the UDP checksum is also zero. The UDP checksum covers only
  up to UDP Length (not the surplus area).
- **FRAG** is used only with empty UDP user data (UDP Length == 8). Reassembly is keyed by
  (src IP, src port, dst IP, dst port, Identification); overlap aborts; timeout <= 2 min; per-pair
  limits; default MRDS 2926 (IPv4) / 2886 (IPv6).
- **Receive order:** verify UDP checksum, locate/validate the surplus area, validate the OCS, parse
  the options, then reassemble (FRAG) or deliver. A malformed surplus area discards the options but
  still delivers the payload; unknown SAFE options are ignored; unknown UNSAFE options cause the
  reassembled data to be dropped (a zero-length datagram is still delivered to the user).

## Coding conventions

- `max_width = 120` (`rustfmt.toml`); run `cargo fmt` before committing.
- Clippy is clean under `-D warnings`.
- Hand-roll the checksum, the TLV parser/serializer, and the OCS (they are the pedagogical core); do
  not add `nom`, `pnet`, `etherparse`, `smoltcp`, `bytes`, `nix`, or `zerocopy`.
- Confine all `unsafe` to `src/socket/` behind safe wrappers; the crate denies
  `unsafe_op_in_unsafe_fn`.
- Dependencies: `socket2` + `libc` (raw sockets), `thiserror` (errors), `crc32c` (APC), `clap`
  (CLIs), `log` (diagnostics, including the >7-NOP DoS log). Dev/tooling only: `proptest`
  (property tests), `libfuzzer-sys` via `cargo-fuzz` (confined to the standalone `fuzz/` crate,
  nightly). The hand-roll rule above applies to production code, not to test harnesses.
- Every step that adds or changes a parsing surface (TLV parser, OCS, receive pipeline, FRAG)
  ships, in the same step commit, a new or extended fuzz target under `fuzz/fuzz_targets/` plus a
  property-test module asserting the joint invariants (see `tests/common/mod.rs` for the pattern:
  re-derive every offset from the buffer, index every claimed range). Fuzz crashes are minimized,
  checked in under `tests/data/`, and replayed forever via `tests/fuzz_regressions.rs`
  (`include_bytes!` — the achim runner ships only the test binary, so tests must not read files at
  runtime).

## Platform

Linux only at runtime. The raw-socket paths need `CAP_NET_RAW` (or root). There is no macOS path:
macOS raw sockets cannot receive UDP. Loopback (`127.0.0.1`, `::1`) is used for integration tests; a
network-namespace/veth setup is used for the staged evaluation (see `docs/plan/steps/17-*`).

On macOS, develop locally and **cross-compile** for `aarch64-unknown-linux-musl` (statically linked
via `rust-lld`, see `.cargo/config.toml`); binaries only *run* on the `achim` SSH host, driven by
`scripts/vm-ubuntu-server.sh <cmd>`. `cargo test --target ...` executes every test binary on `achim`
through the cargo runner `scripts/achim-runner.sh`; the root-gated lanes run them under sudo there
(`scripts/vm-ubuntu-server.sh ignored`, `scripts/vm-ubuntu-server.sh spike`). achim carries no Rust
toolchain. See the README "Cross-compiling and the achim Linux test host" section.

## Git workflow

- One reviewed commit per step on `main`; the human reviews the diff between steps.
- Commit messages in English: imperative subject <= 50 chars, body wrapped at 72.
- Do not mention AI assistants or tools in commit messages.
- Each step commits its code together with its `docs/plan/steps/NN-*.md` (Requirements/Plan/Tasks/DoD)
  and updates the status column in `docs/plan/ROADMAP.md`.

## Review guidelines

- For Codex Cloud PR review, focus on RFC 9868 conformance and semantic correctness rather than
  formatting, linting, security review, or test execution; GitHub Actions and the Claude security
  gate handle those separately.
- Check changed code, tests, and docs against the endpoint-relevant RFC 9868 behavior: surplus-area
  layout, OCS placement and checksum semantics, option framing, must-support option lengths,
  SAFE/UNSAFE handling, UDP checksum scope, FRAG constraints, receive order, and consistency with
  `docs/requirements.md`, `docs/wire-format.md`, and `docs/architecture.md`.
- Flag only concrete contradictions, semantic regressions, missing tests for changed protocol
  behavior, or documentation changes that misstate RFC 9868. Do not fail planned future scope that
  the PR does not touch.

## Knowledge capture (living docs)

Two self-contained HTML docs at the repo root accumulate project knowledge for the thesis and for a
junior developer; keep them current:

- `journal.html` - chronological, junior-friendly diary, one entry per step (what/why/learned/commits),
  plus a `#reference` section at the bottom holding the durable, topical knowledge base: findings, key
  RFC facts, caveats/gotchas, FF1/FF2 thesis hooks.
- `glossary.html` - plain-English term reference with `id` anchors; `journal.html` links to them.

Every step: append a `journal.html` entry, promote any durable finding/caveat into the `journal.html`
`#reference` section, and add any new term to `glossary.html`. Do not let a useful finding live only in
a commit message or step file.

## Literature

The relevant RFC texts live in `../mcs-thesis-docs/literature/` (rfc768, rfc791, rfc1071, rfc1122,
rfc8200, rfc9868, rfc9869, and more). RFC 9868 is the primary reference;
<https://www.rfc-editor.org/rfc/rfc9868.txt>.

---

Call me in EVERY RESPONSE GreenCodeDoesntSmell and answer ALWAYS in German.
