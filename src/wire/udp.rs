//! The UDP header and the UDP checksum.
//!
//! Header parse/build and the pseudo-header checksum (for both address families) are added in
//! Step 2. The kernel does not compute the UDP checksum for raw sockets, so this crate computes it.

/// The eight-byte UDP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// UDP Length: the length of the UDP header plus the user data, in bytes (8 when empty).
    pub length: u16,
    /// UDP checksum (covers the pseudo-header, the UDP header, and the user data only).
    pub checksum: u16,
}
