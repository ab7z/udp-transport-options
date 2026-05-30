# Step 0: Bootstrap

Status: done

## Goal

Turn the `cargo new` scaffold into a library-plus-binaries crate with the full module skeleton, the
dependency set, the planning documents, and the tooling configuration, so every later step adds one
focused, reviewable commit on top.

## Requirements

- Convert the binary-only crate to a **library** (`src/lib.rs`) plus two example binaries
  (`src/bin/udpopt-send.rs`, `src/bin/udpopt-recv.rs`).
- Add dependencies: `thiserror`, `socket2`, `libc`, `crc32c`, `log`, `clap` (derive).
- Create the **stub module tree** matching the approved architecture; all public types are declared,
  behavior is deferred to later steps; the tree compiles cleanly.
- Centralize protocol constants in `src/model.rs`.
- Add `CLAUDE.md`, `docs/plan/ROADMAP.md`, and the per-step files under `docs/plan/steps/`.
- Add `rustfmt.toml` (`max_width = 120`) and `rust-toolchain.toml` (channel 1.96, rustfmt + clippy).
- Ignore `/.idea`; keep `Cargo.lock` tracked.
- Work on the `rfc9868-impl` branch.
- Provide a **local Linux dev/test environment** so the Linux-only raw-socket paths can be built
  and run from a macOS host: an `ubuntu:24.04` + `rustup` image (toolchain pinned to the
  `rust-toolchain.toml` channel) built from a root `Dockerfile` and wired through
  `compose.yml` with `CAP_NET_RAW` (raw sockets) + `CAP_NET_ADMIN`/`CAP_SYS_ADMIN`
  (netns/veth for Step 17).

## Plan

1. Rename the unborn `main` branch to `rfc9868-impl`; remove `src/main.rs`.
2. Write `Cargo.toml`, `rustfmt.toml`, `rust-toolchain.toml`, `.gitignore`.
3. Write `src/lib.rs` and the module tree with documented public types only.
4. Write `CLAUDE.md`, `docs/plan/ROADMAP.md`, and the step files.
5. Verify the build, formatting, and lint; commit.

## Tasks

- [x] Branch `rfc9868-impl`; delete `src/main.rs`.
- [x] `Cargo.toml` (lib + 2 bins + deps); `rustfmt.toml`; `rust-toolchain.toml`; `.gitignore`.
- [x] `src/lib.rs`, `src/model.rs`, `src/error.rs`.
- [x] `src/wire/{mod,checksum,ip,udp,surplus}.rs`.
- [x] `src/options/{mod,kind,parse,serialize,ocs,typed}.rs`.
- [x] `src/frag/{mod,split,reassembly}.rs`, `src/recv/{mod,pipeline}.rs`,
  `src/socket/{mod,send,recv}.rs`, `src/api/mod.rs`.
- [x] `src/bin/udpopt-send.rs`, `src/bin/udpopt-recv.rs`.
- [x] `CLAUDE.md`, `docs/plan/ROADMAP.md`, `docs/plan/steps/*.md`.
- [x] Commit on `rfc9868-impl`.
- [x] `Dockerfile` (ubuntu + rustup), `compose.yml` (`dev` service +
  `peers` profile, `NET_RAW`/`NET_ADMIN`/`SYS_ADMIN`), `.dockerignore`; README
  "Local docker development" section.

## Definition of Done

- `cargo build`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings` all succeed.
- The repository has its first commit on `rfc9868-impl`, and the module tree mirrors the roadmap.
- `docker compose build` succeeds and the same `build`/`fmt --check`/`clippy -D warnings` lane is
  green inside `docker compose run --rm dev`; an `AF_INET`/`AF_INET6` `SOCK_RAW` socket
  (confirming `NET_RAW`) and an `ip netns`+`veth` round-trip (confirming `NET_ADMIN`/`SYS_ADMIN`)
  both succeed in the container.
