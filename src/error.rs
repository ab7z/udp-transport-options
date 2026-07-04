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
    /// same variant for fixed-size option validation. When typed decoders report this after the
    /// parser has stripped framing, `len` is the implied default TLV length (`value_len + 2`);
    /// callers that need the exact wire Length for extended-framed options should report it at the
    /// framing layer.
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

    /// FRAG appeared more than once in one options area.
    #[error("FRAG option cannot appear more than once")]
    DuplicateFrag,

    /// The single alignment pad byte that precedes an odd-offset OCS was non-zero.
    #[error("surplus-area alignment pad byte must be zero")]
    NonZeroPad,

    /// The Option Checksum (OCS) did not validate to zero over the surplus area.
    #[error("option checksum (OCS) validation failed")]
    OcsMismatch,
}

/// Errors produced while serializing UDP options into a canonical surplus-area body.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SerializeError {
    /// EOL and NOP are reserved for builder-owned termination and alignment.
    #[error("option kind {kind:#04x} is reserved for the serializer")]
    ReservedKind {
        /// The rejected option Kind byte.
        kind: u8,
    },

    /// Step 5 only emits SAFE options; UNSAFE options require the later FRAG/reassembly scope.
    #[error("unsafe option kind {kind:#04x} cannot be serialized at this layer")]
    UnsafeKind {
        /// The rejected option Kind byte.
        kind: u8,
    },

    /// The Kind is known or reserved by RFC 9868 but not implemented by this send-side builder.
    #[error("assigned or reserved safe option kind {kind:#04x} cannot be serialized at this layer")]
    UnsupportedAssignedKind {
        /// The rejected option Kind byte.
        kind: u8,
    },

    /// FRAG can appear at most once in one options area.
    #[error("FRAG option cannot be serialized more than once")]
    DuplicateFrag,

    /// The value cannot be represented in the 16-bit Extended Length format.
    #[error("value for option kind {kind:#04x} is too long: {value_len} bytes, max {max} bytes")]
    ValueTooLong {
        /// The option Kind byte.
        kind: u8,
        /// The rejected value length.
        value_len: usize,
        /// The largest encodable value length.
        max: usize,
    },

    /// A known fixed-size option was supplied with a value length that cannot be emitted validly.
    #[error("invalid value length {value_len} for fixed-size option kind {kind:#04x}")]
    InvalidFixedValueLength {
        /// The option Kind byte.
        kind: u8,
        /// The rejected value length.
        value_len: usize,
    },

    /// The serialized OCS-led body would exceed the even 16-bit length limit.
    #[error("serialized options body is too long: {len} bytes, max {max} bytes")]
    BodyTooLong {
        /// The rejected body length.
        len: usize,
        /// The largest body length this serializer emits.
        max: usize,
    },

    /// The final FRAG data start offset cannot be represented in the 16-bit FRAG field.
    #[error("fragment data start {start} exceeds the 16-bit FRAG field max {max}")]
    FragmentStartTooLarge {
        /// The computed offset from the start of the UDP header.
        start: usize,
        /// The largest representable FRAG start offset.
        max: usize,
    },
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
    /// The IP or UDP header invalidates the whole datagram, so nothing is delivered.
    #[error("header error: {0}")]
    Header(#[from] HeaderError),

    /// The surplus area could not be parsed (the payload is still delivered to the application).
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),

    /// The UDP Length field exceeds the IP transport payload length (FR-49).
    #[error("UDP Length {udp_len} exceeds IP transport payload length {transport_payload_len}")]
    UdpLengthExceedsIpPayload {
        /// The UDP Length field from the datagram.
        udp_len: u16,
        /// The parsed IP transport-payload length.
        transport_payload_len: usize,
    },

    /// A present UDP checksum failed validation.
    #[error("UDP checksum mismatch: expected {expected:#06x}, actual {actual:#06x}")]
    UdpChecksumMismatch {
        /// The checksum computed over the pseudo-header, UDP header, and UDP user data.
        expected: u16,
        /// The checksum field from the wire.
        actual: u16,
    },

    /// An underlying I/O error from a raw socket.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A raw-socket operation needs `CAP_NET_RAW` (or root) and the process lacks it.
    #[error("operation requires CAP_NET_RAW or root privileges")]
    PermissionDenied,
}
