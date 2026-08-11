# udp-transport-options

A userspace Rust reference implementation of
[RFC 9868: Transport Options for UDP](https://www.rfc-editor.org/rfc/rfc9868.txt).

RFC 9868 stores UDP transport options in the surplus area: bytes after the end
of the UDP user data (the extent indicated by the UDP Length field) but before
the end of the IP transport payload. This crate implements the in-scope endpoint mechanism in
userspace, with raw sockets used only
for the Linux send/receive boundary.

This repository contains the parser/serializer, checksum and OCS logic, the must-support options,
FRAG split/reassembly, low- and high-level APIs, example peer CLIs, formal models, and Linux test and
evaluation lanes. The requirement-to-implementation mapping lives in
[`docs/requirements.md`](docs/requirements.md); roadmap history lives in
[`docs/plan/ROADMAP.md`](docs/plan/ROADMAP.md).

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

Implemented endpoint scope:

- TLV option parsing and serialization
- Option Checksum (OCS)
- must-support options: EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES
- FRAG fragmentation and reassembly
- IPv4 support
- low-level and high-level APIs
- example sender/receiver CLIs

The receive API reports TLV-option status and the fixed OCS status separately and can require a
successful OCS. REQ/RES are wire-level pass-through options: the library never auto-responds, and a
caller that sends RES must supply a token that it previously received in REQ. Low-level automatic
fragmentation requires an explicit FRAG Identification; `Peer` owns a per-peer generator seeded from
the operating system by default.

Out of scope: IPv6, kernel modules, TIME, AUTH/UCMP/UENC, and RFC 9869 DPLPMTUD.

## Build

The library and binaries should compile on any platform. Raw-socket runtime
paths are Linux-only and require `CAP_NET_RAW` or root.

```sh
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Formal verification artifacts live in `formal/lean-rfc9868/`. Run
`scripts/lean-gate.sh` to build the Lean specification and audit theorem axioms.
Lean covers pure RFC 9868 wire/spec invariants; raw-socket and middlebox behavior
remain empirical and are checked by the Linux lanes.

On a Linux host everything runs natively and self-contained: `cargo test`,
`sudo cargo test -- --ignored` (root-gated raw-socket lane), and
`scripts/spike.sh` need nothing beyond the pinned Rust toolchain and `iproute2`.

## Cross-compiling and the Linux test hosts

The raw-socket paths only run on Linux, and macOS cannot receive raw UDP at all,
so Linux binaries are **cross-compiled on the Mac** for either `aarch64-unknown-linux-musl`
or `x86_64-unknown-linux-musl` (statically linked via Rust's bundled `rust-lld`, no
extra linker toolchain needed) and only **executed** on a matching SSH host. Test
binaries are shipped and run there transparently by the cargo runner
`scripts/achim-runner.sh` (wired up in `.cargo/config.toml`); the remote host stays a
bare network testbed without a Rust toolchain.

```sh
scripts/vm-ubuntu-server.sh bootstrap      # one-time: add the local musl target; check ssh/sudo/rsync
                                           # and tcpdump/tshark/python3 (wire lane) on achim
scripts/vm-ubuntu-server.sh build          # cargo build --target aarch64-unknown-linux-musl (local)
scripts/vm-ubuntu-server.sh test           # cargo test --target ...; test binaries execute on achim
scripts/vm-ubuntu-server.sh fmt
scripts/vm-ubuntu-server.sh clippy         # lints the Linux cfg paths via --target
scripts/vm-ubuntu-server.sh verify         # build + test + fmt + clippy

# root-gated loopback lane (raw sockets need effective CAP_NET_RAW):
# the runner executes the test binaries under sudo on achim
scripts/vm-ubuntu-server.sh ignored
scripts/vm-ubuntu-server.sh shell

# Step 0.5 spike: surplus-area survival over a staged 1500-MTU veth link across two netns;
# cross-builds the spike examples, syncs the binaries, and runs scripts/spike.sh on achim
scripts/vm-ubuntu-server.sh spike

# Step 10.5 wire-verification lane: tcpdump captures the wire_probe scenario set on loopback and
# the independent checker scripts/wire-check.py verifies the post-kernel bytes (plus a tshark
# L3/L4 cross-check; one-time prerequisite on achim: sudo apt-get install -y tshark)
scripts/vm-ubuntu-server.sh wire

# Step 17 FF2/P2 controlled local evaluation lanes. Artifacts land under /tmp/uoe-<epoch>/ on achim.
scripts/vm-ubuntu-server.sh eval veth
scripts/vm-ubuntu-server.sh eval router
scripts/vm-ubuntu-server.sh eval nat
scripts/vm-ubuntu-server.sh eval filter

# x86_64 Linux host example:
VM_UBUNTU_SERVER_HOST=root@x86-test-host \
VM_UBUNTU_SERVER_TARGET=x86_64-unknown-linux-musl \
scripts/vm-ubuntu-server.sh verify
```

Set `VM_UBUNTU_SERVER_HOST` to use a different SSH alias, or `VM_UBUNTU_SERVER_DIR` to use another
remote run directory (binaries land in its `bin/`). Set `VM_UBUNTU_SERVER_TARGET` to the musl target
matching the remote `uname -m`; it defaults to `aarch64-unknown-linux-musl`. The host needs
passwordless `sudo` and `rsync`, nothing else.

See [`docs/evaluation.md`](docs/evaluation.md) for the FF2/P2 verdict taxonomy, capture artifacts,
offload notes, and Wireshark/tshark interpretation limits. The reproducible repository lanes cover
namespace/veth, routing, Linux NAT, and a filter negative control. A separate external campaign at
commit `7b11140` added initial Hetzner path observations and an ephemeral WireGuard control. It found
both survival and loss boundaries, but it does not complete FF2.
