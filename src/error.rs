//! Error types for parsing, receiving, and raw-socket operations.

use thiserror::Error;

/// Errors produced while parsing or validating the surplus area and its options.
///
/// Per RFC 9868, a malformed surplus area generally causes a receiver to discard the options while
/// still delivering the UDP user data; these variants identify *why* the options were rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// An option's Length field is invalid for its Kind (too short, or not the fixed size).
    #[error("invalid length {len} for option kind {kind:#04x}")]
    InvalidLength {
        /// The option Kind byte.
        kind: u8,
        /// The Length value that was rejected.
        len: usize,
    },

    /// An option claims to extend past the end of the surplus area.
    #[error("option at offset {offset} overruns the surplus area")]
    Overrun {
        /// Byte offset within the surplus area at which the overrun was detected.
        offset: usize,
    },

    /// The single alignment pad byte that precedes an odd-offset OCS was non-zero.
    #[error("surplus-area alignment pad byte must be zero")]
    NonZeroPad,

    /// The Option Checksum (OCS) did not validate to zero over the surplus area.
    #[error("option checksum (OCS) validation failed")]
    OcsMismatch,
}

/// Errors produced by the receive pipeline and the raw sockets.
#[derive(Debug, Error)]
pub enum RecvError {
    /// The surplus area could not be parsed (the payload is still delivered to the application).
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// An underlying I/O error from a raw socket.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A raw-socket operation needs `CAP_NET_RAW` (or root) and the process lacks it.
    #[error("operation requires CAP_NET_RAW or root privileges")]
    PermissionDenied,
}
