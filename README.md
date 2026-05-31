# udp-transport-options

A userspace Rust reference implementation of
[RFC 9868: Transport Options for UDP](https://www.rfc-editor.org/rfc/rfc9868.txt).

RFC 9868 stores UDP transport options in the surplus area: bytes after the UDP
Length field but before the end of the IP transport payload. This crate is
intended to implement that mechanism in userspace, with raw sockets used only
for the Linux send/receive boundary.

This repository contains the crate layout, protocol constants, core data types,
error types, planning docs, and placeholder example CLIs. Most protocol behavior
is tracked in [`docs/plan/ROADMAP.md`](docs/plan/ROADMAP.md).

## Development workflow

> **This reference implementation is built with AI-assisted ("agentic") coding
> under human review.** We are deliberately transparent about this.

The work proceeds **step by step** (not one-shot): each step is planned in
[`docs/plan/ROADMAP.md`](docs/plan/ROADMAP.md) and its per-step file under
[`docs/plan/steps/`](docs/plan/steps/), implemented with an AI coding agent, and
landed as **one human-reviewed git commit per step**. Every change is read and
approved by a human before it is committed; the human remains accountable for the
code.

## Scope

Planned in scope:

- TLV option parsing and serialization
- Option Checksum (OCS)
- must-support options: EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES
- FRAG fragmentation and reassembly
- IPv4 and IPv6 support
- low-level and high-level APIs
- example sender/receiver CLIs

Out of scope: kernel modules, TIME, AUTH/UCMP/UENC, and RFC 9869 DPLPMTUD.

## Build

The library and binaries should compile on any platform. Raw-socket runtime
paths are Linux-only and require `CAP_NET_RAW` or root.

```sh
cargo build
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

## Local docker development

The raw-socket paths only run on Linux, and macOS cannot receive raw UDP at all.
To build and run them locally, use the bundled Linux Docker image via the `dev`
service. It is granted `CAP_NET_RAW` (raw sockets) plus
`CAP_NET_ADMIN`/`CAP_SYS_ADMIN` (netns/veth for the Step 17 harness). The service
runs as a non-root user, and those capabilities are effective only for root, so
the root-gated lane goes through the preconfigured passwordless `sudo`:

```sh
docker compose build
docker compose run --rm dev cargo build
docker compose run --rm dev cargo test

# root-gated loopback lane (raw sockets need effective CAP_NET_RAW):
docker compose run --rm dev sudo -E cargo test -- --ignored
docker compose run --rm dev bash        # interactive shell

# Step 0.5 spike: surplus-area survival over a staged 1500-MTU veth link across two netns
docker compose run --rm dev sudo -E scripts/spike.sh
```

Two-peer end-to-end runs over a shared bridge network use the `peers` profile:

```sh
docker compose --profile peers up -d
docker compose exec peer-recv bash
docker compose exec peer-send bash
```

The repository is bind-mounted into the container, while the build-heavy paths
(`target/` and the cargo registry) live on named volumes, so most of Rust's file
I/O stays native to the Linux VM. For the best bind-mount performance on macOS,
enable **VirtioFS** in Docker Desktop.
