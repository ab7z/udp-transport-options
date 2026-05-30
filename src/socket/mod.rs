//! Raw-socket I/O (Linux only).
//!
//! Sending and receiving the surplus area requires `AF_INET`/`AF_INET6` `SOCK_RAW` sockets and the
//! `CAP_NET_RAW` capability (or root). All `unsafe` FFI is confined to this module behind safe
//! wrappers. The send path (Step 8) uses `IP_HDRINCL`; the receive path (Step 9) reads full IP
//! datagrams with the surplus area intact.

pub mod recv;
pub mod send;
