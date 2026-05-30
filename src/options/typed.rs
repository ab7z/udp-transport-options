//! Strongly typed option values and the [`TypedOption`] trait.
//!
//! Every typed option in scope is fixed-length, so these are `Copy` plain-old-data with no lifetime;
//! `decode` borrows the value bytes only transiently and returns an owned value. The trait methods
//! and the `decode`/`encode` bodies are added in Step 7.

use crate::error::ParseError;
use crate::options::kind::OptionKind;

/// A strongly typed UDP option that can be decoded from, and encoded to, its wire bytes.
pub trait TypedOption: Copy {
    /// The Kind this type represents.
    const KIND: OptionKind;

    /// Decode the option's value bytes (no framing) into an owned value.
    fn decode(value: &[u8]) -> Result<Self, ParseError>;

    /// Append the complete option (Kind + Length + Value) to `out`.
    fn encode(&self, out: &mut Vec<u8>);
}

/// Additional Payload Checksum: a CRC32C over the UDP user data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Apc {
    /// CRC32C (Castagnoli) of the UDP user data.
    pub crc32c: u32,
}

/// Maximum Datagram Size: the largest datagram the sender can receive without IP fragmentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mds {
    /// Maximum datagram size, in bytes.
    pub max_datagram_size: u16,
}

/// Maximum Reassembled Datagram Size and the maximum number of fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mrds {
    /// Maximum reassembled datagram size, in bytes.
    pub max_reassembled_size: u16,
    /// Maximum number of fragments the sender can reassemble.
    pub max_segments: u8,
}

/// Echo Request: an opaque 4-byte token the peer may echo back in a [`Res`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Req {
    /// Opaque request token.
    pub token: [u8; 4],
}

/// Echo Response: echoes the token from a received [`Req`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Res {
    /// Echoed request token.
    pub token: [u8; 4],
}

/// The Fragmentation option (RFC 9868). `rdos` distinguishes terminal from non-terminal fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frag {
    /// Byte offset, from the start of the UDP header, where this fragment's data begins.
    pub frag_start: u16,
    /// Identifier shared by all fragments of one original datagram.
    pub identification: u32,
    /// Byte offset, in the reassembled datagram, where this fragment's data belongs.
    pub frag_offset: u16,
    /// `Some(rdos)` for a terminal fragment (the Reassembled-Datagram-Option-Start); `None` for a
    /// non-terminal fragment.
    pub rdos: Option<u16>,
}
