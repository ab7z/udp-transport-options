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
