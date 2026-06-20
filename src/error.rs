//! Error types for parsing, receiving, and raw-socket operations.

use thiserror::Error;

/// Errors produced while parsing or validating the surplus area and its options.
///
/// Per RFC 9868, a malformed surplus area generally causes a receiver to discard the options while
/// still delivering the UDP user data; these variants identify *why* the options were rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// An option's Length field is invalid at the current validation layer.
    ///
    /// The TLV parser uses this for framing-invalid lengths; later typed decoders can use the
    /// same variant for fixed-size option validation.
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

/// Errors that invalidate the whole IP datagram.
///
/// Unlike [`ParseError`], which rejects the options while the UDP user data is still delivered, a
/// `HeaderError` means the datagram itself cannot be trusted and is dropped (RFC 9868 Section 14
/// disposition). Produced by `IpRepr::parse` and `UdpHeader::parse`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HeaderError {
    /// The buffer is too short to hold the IP header it claims.
    #[error("IP header truncated: need {need} bytes, have {have}")]
    IpTruncated {
        /// The number of bytes the header requires.
        need: usize,
        /// The number of bytes actually available.
        have: usize,
    },

    /// The IP version nibble is not 4.
    #[error("unsupported IP version {0}")]
    UnsupportedVersion(u8),

    /// The IPv4 Internet Header Length field is below the minimum of 5 words (RFC 791 Section 3.1).
    #[error("IPv4 IHL {0} is below the minimum of 5")]
    BadIhl(u8),

    /// The IPv4 Total Length is inconsistent with the header or the buffer.
    #[error("IP length field {length} is inconsistent with the header or buffer")]
    BadIpLength {
        /// The rejected length-field value.
        length: u16,
    },

    /// The IPv4 header checksum did not validate (RFC 791 Section 3.1).
    #[error("IPv4 header checksum mismatch")]
    IpChecksumMismatch,

    /// The transport protocol is not UDP (17).
    #[error("transport protocol {0} is not UDP")]
    UnexpectedProtocol(u8),

    /// The buffer is too short to hold the eight-byte UDP header.
    #[error("UDP header truncated: need 8 bytes, have {have}")]
    UdpTruncated {
        /// The number of bytes actually available.
        have: usize,
    },

    /// The UDP Length field is below the 8-byte header minimum (RFC 768; FR-49).
    #[error("UDP Length {length} is below the 8-byte header minimum")]
    UdpLengthInvalid {
        /// The rejected UDP Length value.
        length: u16,
    },
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
