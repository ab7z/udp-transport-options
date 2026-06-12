//! # udp-transport-options
//!
//! A userspace reference implementation of [RFC 9868] (Transport Options for UDP) in Rust.
//!
//! RFC 9868 carries transport options in the *surplus area*: the bytes between the end of the UDP
//! payload (delimited by the UDP Length field) and the end of the IP transport payload (IPv4 Total
//! Length minus the IHL). Because the operating system's UDP stack delivers only the
//! UDP-length-bounded payload, this crate accesses the surplus area with raw sockets (`AF_INET`
//! `SOCK_RAW`) on Linux.
//!
//! ## Module map
//!
//! - [`model`]   - protocol constants and limits.
//! - [`error`]   - error types.
//! - [`wire`]    - Internet checksum, IP/UDP headers, surplus-area location.
//! - [`options`] - option kinds, zero-copy parser, serializer, OCS, typed options.
//! - [`frag`]    - UDP-level fragmentation (FRAG) and reassembly.
//! - [`recv`]    - the pure receive-side processing pipeline.
//! - [`socket`]  - raw-socket I/O (Linux only, requires `CAP_NET_RAW`).
//! - [`api`]     - the low-level and high-level public APIs.
//!
//! ## Scope
//!
//! In scope: the TLV options framework, the Option Checksum (OCS), the must-support options
//! (EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES), fragmentation/reassembly, and IPv4.
//! Out of scope: IPv6, the TIME option, the reserved AUTH/UCMP/UENC options, RFC 9869 (DPLPMTUD),
//! and kernel modules. See `docs/plan/ROADMAP.md` for the full plan.
//!
//! [RFC 9868]: https://www.rfc-editor.org/rfc/rfc9868.txt

#![deny(unsafe_op_in_unsafe_fn)]

pub mod api;
pub mod error;
pub mod frag;
pub mod model;
pub mod options;
pub mod recv;
pub mod socket;
pub mod wire;
