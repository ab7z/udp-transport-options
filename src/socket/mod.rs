//! Raw-socket I/O (Linux only).
//!
//! Sending and receiving the surplus area requires `AF_INET` `SOCK_RAW` sockets and the
//! `CAP_NET_RAW` capability (or root). All `unsafe` FFI is confined to this module behind safe
//! wrappers. Step 8 covers both the `IP_HDRINCL` send path and the receive path that reads full IP
//! datagrams with the surplus area intact.

pub mod recv;
pub mod send;

#[cfg(target_os = "linux")]
use std::io;

#[cfg(target_os = "linux")]
use crate::error::SocketError;

#[cfg(target_os = "linux")]
pub(crate) fn map_socket_error(error: io::Error) -> SocketError {
    match error.raw_os_error() {
        Some(libc::EPERM | libc::EACCES) => SocketError::PermissionDenied,
        _ => SocketError::Io(error),
    }
}
