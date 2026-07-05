//! Protocol constants and limits from RFC 9868.
//!
//! These are the single source of truth for option Kind values, fixed option lengths, the
//! SAFE/UNSAFE boundary, and the reassembly defaults and DoS limits. Higher-level modules build on
//! these constants so that the magic numbers from the RFC live in exactly one place.

/// Option Kind values (RFC 9868, Table of UDP Option Kinds).
pub mod kind {
    /// End of Options List (single byte, no Length).
    pub const EOL: u8 = 0;
    /// No Operation (single byte, no Length).
    pub const NOP: u8 = 1;
    /// Additional Payload Checksum (CRC32C of the UDP user data).
    pub const APC: u8 = 2;
    /// Fragmentation.
    pub const FRAG: u8 = 3;
    /// Maximum Datagram Size.
    pub const MDS: u8 = 4;
    /// Maximum Reassembled Datagram Size.
    pub const MRDS: u8 = 5;
    /// Echo Request.
    pub const REQ: u8 = 6;
    /// Echo Response.
    pub const RES: u8 = 7;
    /// Timestamp (out of scope for this implementation).
    pub const TIME: u8 = 8;
    /// Authentication (reserved, out of scope for this implementation).
    pub const AUTH: u8 = 9;
    /// RFC3692-style experiments (out of scope for this implementation).
    pub const EXP: u8 = 127;
    /// First reserved SAFE Kind after EXP.
    pub const SAFE_RESERVED_MIN: u8 = 128;
    /// Last reserved SAFE Kind before the UNSAFE range.
    pub const SAFE_RESERVED_MAX: u8 = 191;

    /// Lowest Kind value in the UNSAFE range. Kinds `0..=191` are SAFE, `192..=255` are UNSAFE.
    pub const UNSAFE_MIN: u8 = 192;

    /// Sentinel Length value selecting the extended (2-byte) length form.
    pub const EXTENDED_LENGTH_MARKER: u8 = 255;
}

/// Fixed total lengths (Kind + Length + Value) of the fixed-size options, in bytes.
pub mod length {
    /// APC: Kind + Length + 4-byte CRC32C.
    pub const APC: u8 = 6;
    /// FRAG, non-terminal fragment: Kind + Length + FragStart(2) + Id(4) + FragOffset(2).
    pub const FRAG_NON_TERMINAL: u8 = 10;
    /// FRAG, terminal fragment: non-terminal plus the 2-byte Reassembled-Datagram-Option-Start.
    pub const FRAG_TERMINAL: u8 = 12;
    /// MDS: Kind + Length + 2-byte size.
    pub const MDS: u8 = 4;
    /// MRDS: Kind + Length + 2-byte size + 1-byte segment count.
    pub const MRDS: u8 = 5;
    /// REQ: Kind + Length + 4-byte token.
    pub const REQ: u8 = 6;
    /// RES: Kind + Length + 4-byte token.
    pub const RES: u8 = 6;
    /// TIME: Kind + Length + two 4-byte timestamp fields.
    pub const TIME: u8 = 10;
    /// EXP minimum: Kind + Length + 16-bit UDP ExID.
    pub const EXP_MIN: u8 = 4;
    /// The OCS occupies a fixed 2-byte checksum at the start of the surplus area.
    pub const OCS: u8 = 2;
    /// UDP header length, used by FRAG pointers that are relative to the UDP header start.
    pub const UDP_HEADER: u8 = 8;
}

/// Reassembly defaults and DoS limits (RFC 9868, Section on FRAG and Security Considerations).
pub mod limits {
    use std::time::Duration;

    /// Default Maximum Reassembled Datagram Size for IPv4 when no MRDS option was received.
    pub const MRDS_DEFAULT_IPV4: u16 = 2926;
    /// Minimum number of fragments an implementation must be able to reassemble.
    pub const MIN_REASSEMBLY_SEGMENTS: u8 = 2;
    /// Upper bound on the fragment-reassembly timeout.
    pub const REASSEMBLY_TIMEOUT_MAX: Duration = Duration::from_secs(120);
    /// Number of consecutive NOP options beyond which a receiver should log a possible DoS.
    pub const NOP_RUN_DOS_THRESHOLD: usize = 7;
}
