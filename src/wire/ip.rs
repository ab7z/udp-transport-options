//! IP-version-generic representation plus IPv4/IPv6 header parsing and building.
//!
//! [`IpRepr`] exposes exactly what the UDP-options layer needs (addresses, the transport-payload
//! length, and a pseudo-header seed for the UDP checksum) so that surplus-area math, the UDP
//! pseudo-header, and FRAG keying are written once for both address families. Header parse/build
//! and the method bodies are added in Step 2.

use std::net::{Ipv4Addr, Ipv6Addr};

/// An IP-version-generic view of the header fields the UDP-options layer depends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpRepr {
    /// IPv4 header fields.
    V4 {
        /// Source address.
        src: Ipv4Addr,
        /// Destination address.
        dst: Ipv4Addr,
        /// Internet Header Length, in 32-bit words.
        ihl: u8,
        /// Total Length field (IPv4 header + transport payload), in bytes.
        total_len: u16,
    },
    /// IPv6 header fields.
    V6 {
        /// Source address.
        src: Ipv6Addr,
        /// Destination address.
        dst: Ipv6Addr,
        /// Payload Length field (extension headers + transport payload), in bytes.
        payload_len: u16,
        /// Total length of any extension headers preceding the transport payload, in bytes.
        ext_hdr_len: u16,
    },
}
