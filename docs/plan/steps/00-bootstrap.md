# Step 0: Bootstrap

Status: done

> Historical-snapshot note (2026-07-13): this file records the Step 0 plan and its then-current DoD.
> The `AF_INET6` socket clause at the bottom predates the deliberate IPv6 scope cut and is not a
> current project requirement; the maintained implementation and verification surface is IPv4-only.

## Goal

Turn the `cargo new` scaffold into a library-plus-binaries crate with the full module skeleton, the
dependency set, the planning documents, and the tooling configuration, so every later step adds one
focused, reviewable commit on top.

## Requirements

- Convert the binary-only crate to a **library** (`src/lib.rs`) plus two example binaries
  (`src/bin/udpopt-send.rs`, `src/bin/udpopt-recv.rs`).
- Add dependencies: `thiserror`, `socket2`, `libc` (`crc32c`, `log`, and `clap` arrive with their
  steps 7, 10, and 14).
- Create the **stub module tree** matching the approved architecture; all public types are declared,
  behavior is deferred to later steps; the tree compiles cleanly.
- Centralize protocol constants in `src/model.rs`.
- Add `CLAUDE.md`, `docs/plan/ROADMAP.md`, and the per-step files under `docs/plan/steps/`.
- Add `rustfmt.toml` (`max_width = 120`) and `rust-toolchain.toml` (channel 1.96, rustfmt + clippy).
- Ignore `/.idea`; keep `Cargo.lock` tracked.
- Work on `main`.
- Provide a **cross-compile + remote-run environment** so the Linux-only raw-socket paths can be
  exercised from a macOS host: binaries are built locally for `aarch64-unknown-linux-musl`
  (`rust-lld`, `.cargo/config.toml`) and only executed on the `achim` SSH host; test binaries travel
  through the cargo runner `scripts/achim-runner.sh`, the lanes through `scripts/vm-ubuntu-server.sh`.

## Lean verification

Not applicable: this step is scaffolding only and adds no RFC-visible behavior to formalize. The
Lean track itself (a `formal/lean-rfc9868/` Lake project with a repo-pinned `lean-toolchain`) is
bootstrapped in Step 3; see `LEAN_RFC9868_VALIDATION.md`.

## Plan

1. Remove `src/main.rs`.
2. Write `Cargo.toml`, `rustfmt.toml`, `rust-toolchain.toml`, `.gitignore`.
3. Write `src/lib.rs` and the module tree with documented public types only.
4. Write `CLAUDE.md`, `docs/plan/ROADMAP.md`, and the step files.
5. Verify the build, formatting, and lint; commit.

## Tasks

- [x] Delete `src/main.rs`.
- [x] `Cargo.toml` (lib + 2 bins + deps); `rustfmt.toml`; `rust-toolchain.toml`; `.gitignore`.
- [x] `src/lib.rs`, `src/model.rs`, `src/error.rs`.
- [x] `src/wire/{mod,checksum,ip,udp,surplus}.rs`.
- [x] `src/options/{mod,kind,parse,serialize,ocs,typed}.rs`.
- [x] `src/frag/{mod,split,reassembly}.rs`, `src/recv/{mod,pipeline}.rs`,
  `src/socket/{mod,send,recv}.rs`, `src/api/mod.rs`.
- [x] `src/bin/udpopt-send.rs`, `src/bin/udpopt-recv.rs`.
- [x] `CLAUDE.md`, `docs/plan/ROADMAP.md`, `docs/plan/steps/*.md`.
- [x] Commit on `main`.
- [x] `.cargo/config.toml` (musl target: `rust-lld` + runner), `scripts/achim-runner.sh`,
  `scripts/vm-ubuntu-server.sh`; README "Cross-compiling and the achim Linux test host" section.

## Definition of Done

- `cargo build`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all succeed.
- The repository has its first commit on `main`, and the module tree mirrors the roadmap.
- `scripts/vm-ubuntu-server.sh verify` succeeds (cross-build local, test binaries execute on
  `achim`); an `AF_INET`/`AF_INET6` `SOCK_RAW` socket and an `ip netns`+`veth` round-trip both
  succeed on `achim` through the root-gated lanes.
