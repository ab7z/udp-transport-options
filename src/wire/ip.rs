//! IP-version-generic representation plus IPv4/IPv6 header parsing and building.
//!
//! [`IpRepr`] exposes exactly what the UDP-options layer needs (addresses, the transport-payload
//! length, and a pseudo-header seed for the UDP checksum) so that surplus-area math, the UDP
//! pseudo-header, and FRAG keying are written once for both address families.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::HeaderError;
use crate::wire::checksum::{Checksum, internet_checksum};

/// The UDP protocol number (RFC 768), used as IPv4 Protocol and IPv6 Next Header.
pub(crate) const IPPROTO_UDP: u8 = 17;

/// The fixed IPv4 header length in bytes when no IP options are present (IHL 5).
const IPV4_MIN_HEADER_LEN: usize = 20;
/// The fixed IPv6 base header length in bytes (RFC 8200 Section 3).
const IPV6_HEADER_LEN: usize = 40;
/// TTL (IPv4) / Hop Limit (IPv6) emitted by [`IpRepr::write`].
const DEFAULT_TTL: u8 = 64;

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

impl IpRepr {
    /// Parses the leading IP header and returns the repr plus the byte offset of the transport
    /// payload from the start of the IP datagram.
    ///
    /// IPv4 options (IHL > 5) are skipped, never decoded, and the header checksum is verified
    /// (RFC 791 Section 3.1). IPv6 extension headers in scope (Hop-by-Hop directly after the base
    /// header, Destination Options) are skipped by their length so the transport-payload math
    /// accounts for them (RFC 9868 Section 7); Routing, Fragment, AH, ESP, a misplaced Hop-by-Hop,
    /// and any other non-UDP chain end are rejected. Trailing buffer bytes beyond the IP length
    /// field are tolerated and ignored.
    pub fn parse(bytes: &[u8]) -> Result<(IpRepr, usize), HeaderError> {
        let &version_octet = bytes.first().ok_or(HeaderError::IpTruncated { need: 1, have: 0 })?;
        match version_octet >> 4 {
            4 => Self::parse_v4(bytes),
            6 => Self::parse_v6(bytes),
            version => Err(HeaderError::UnsupportedVersion(version)),
        }
    }

    fn parse_v4(bytes: &[u8]) -> Result<(IpRepr, usize), HeaderError> {
        if bytes.len() < IPV4_MIN_HEADER_LEN {
            return Err(HeaderError::IpTruncated {
                need: IPV4_MIN_HEADER_LEN,
                have: bytes.len(),
            });
        }
        let ihl = bytes[0] & 0x0f;
        if ihl < 5 {
            return Err(HeaderError::BadIhl(ihl));
        }
        let header_len = usize::from(ihl) * 4;
        if bytes.len() < header_len {
            return Err(HeaderError::IpTruncated {
                need: header_len,
                have: bytes.len(),
            });
        }
        let total_len = u16::from_be_bytes([bytes[2], bytes[3]]);
        if usize::from(total_len) < header_len || usize::from(total_len) > bytes.len() {
            return Err(HeaderError::BadIpLength { length: total_len });
        }
        if bytes[9] != IPPROTO_UDP {
            return Err(HeaderError::UnexpectedProtocol(bytes[9]));
        }
        // A header summed together with its stored checksum folds to one's-complement zero.
        if internet_checksum(&bytes[..header_len]) != 0 {
            return Err(HeaderError::IpChecksumMismatch);
        }
        let src = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[12..16]).expect("4-byte slice"));
        let dst = Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[16..20]).expect("4-byte slice"));
        Ok((
            IpRepr::V4 {
                src,
                dst,
                ihl,
                total_len,
            },
            header_len,
        ))
    }

    fn parse_v6(bytes: &[u8]) -> Result<(IpRepr, usize), HeaderError> {
        if bytes.len() < IPV6_HEADER_LEN {
            return Err(HeaderError::IpTruncated {
                need: IPV6_HEADER_LEN,
                have: bytes.len(),
            });
        }
        let payload_len = u16::from_be_bytes([bytes[4], bytes[5]]);
        if usize::from(payload_len) > bytes.len() - IPV6_HEADER_LEN {
            return Err(HeaderError::BadIpLength { length: payload_len });
        }
        let payload_end = IPV6_HEADER_LEN + usize::from(payload_len);
        let mut next_header = bytes[6];
        let mut offset = IPV6_HEADER_LEN;
        // Skip the in-scope extension headers by their length; their contents are never decoded.
        // Hop-by-Hop (0) — legal only directly after the base header (RFC 8200 Section 4.1) — and
        // Destination Options (60) share the `Next Header (1) | Hdr Ext Len (1, in 8-octet units
        // excluding the first)` layout (RFC 8200 Section 4). Routing (43) is rejected like
        // Fragment/AH/ESP: its final-destination pseudo-header semantics (RFC 8200 Section 8.1)
        // are out of scope.
        while matches!(next_header, 0 | 60) {
            if next_header == 0 && offset != IPV6_HEADER_LEN {
                return Err(HeaderError::UnexpectedProtocol(0));
            }
            if offset + 2 > payload_end {
                return Err(HeaderError::IpTruncated {
                    need: offset + 2,
                    have: payload_end,
                });
            }
            let ext_len = (usize::from(bytes[offset + 1]) + 1) * 8;
            if offset + ext_len > payload_end {
                return Err(HeaderError::BadIpLength { length: payload_len });
            }
            next_header = bytes[offset];
            offset += ext_len;
        }
        if next_header != IPPROTO_UDP {
            return Err(HeaderError::UnexpectedProtocol(next_header));
        }
        let ext_hdr_len = u16::try_from(offset - IPV6_HEADER_LEN).expect("bounded by payload_len, a u16");
        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).expect("16-byte slice"));
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).expect("16-byte slice"));
        Ok((
            IpRepr::V6 {
                src,
                dst,
                payload_len,
                ext_hdr_len,
            },
            offset,
        ))
    }

    /// Writes the IP header into `out` (V4: exactly 20 bytes, V6: exactly 40 bytes).
    ///
    /// Building IPv4 options or IPv6 extension headers is out of scope, so V4 requires `ihl == 5`
    /// and V6 requires `ext_hdr_len == 0`. The IPv4 header checksum is computed and back-patched.
    /// Panics if `out` is shorter than [`Self::header_len`].
    pub fn write(&self, out: &mut [u8]) {
        match *self {
            IpRepr::V4 {
                src,
                dst,
                ihl,
                total_len,
            } => {
                assert_eq!(ihl, 5, "building IPv4 options is out of scope");
                let out = &mut out[..IPV4_MIN_HEADER_LEN];
                out.fill(0);
                out[0] = 0x45; // version 4, IHL 5
                out[2..4].copy_from_slice(&total_len.to_be_bytes());
                out[8] = DEFAULT_TTL;
                out[9] = IPPROTO_UDP;
                out[12..16].copy_from_slice(&src.octets());
                out[16..20].copy_from_slice(&dst.octets());
                let checksum = internet_checksum(out);
                out[10..12].copy_from_slice(&checksum.to_be_bytes());
            }
            IpRepr::V6 {
                src,
                dst,
                payload_len,
                ext_hdr_len,
            } => {
                assert_eq!(ext_hdr_len, 0, "building IPv6 extension headers is out of scope");
                let out = &mut out[..IPV6_HEADER_LEN];
                out.fill(0);
                out[0] = 0x60; // version 6, traffic class and flow label zero
                out[4..6].copy_from_slice(&payload_len.to_be_bytes());
                out[6] = IPPROTO_UDP;
                out[7] = DEFAULT_TTL; // hop limit
                out[8..24].copy_from_slice(&src.octets());
                out[24..40].copy_from_slice(&dst.octets());
            }
        }
    }

    /// Byte offset of the transport payload from the start of the IP datagram: `ihl * 4` (V4) or
    /// `40 + ext_hdr_len` (V6).
    pub fn header_len(&self) -> usize {
        match *self {
            IpRepr::V4 { ihl, .. } => usize::from(ihl) * 4,
            IpRepr::V6 { ext_hdr_len, .. } => IPV6_HEADER_LEN + usize::from(ext_hdr_len),
        }
    }

    /// Length of the IP transport payload in bytes: `total_len - ihl * 4` (V4) or
    /// `payload_len - ext_hdr_len` (V6).
    pub fn transport_payload_len(&self) -> usize {
        match *self {
            IpRepr::V4 { ihl, total_len, .. } => usize::from(total_len).saturating_sub(usize::from(ihl) * 4),
            IpRepr::V6 {
                payload_len,
                ext_hdr_len,
                ..
            } => usize::from(payload_len).saturating_sub(usize::from(ext_hdr_len)),
        }
    }

    /// Folds the UDP pseudo-header into a fresh RFC 1071 accumulator, identically for V4 and V6.
    ///
    /// V4: source and destination addresses, a zero byte plus protocol 17, and the UDP Length
    /// (RFC 768). V6: the 128-bit addresses, the 32-bit upper-layer length (here the UDP Length,
    /// whose high half is zero), three zero bytes, and Next Header 17 (RFC 8200 Section 8.1).
    /// Callers continue with the UDP header and user data, then take `finish()`.
    pub fn pseudo_header_sum(&self, udp_len: u16) -> Checksum {
        let mut sum = Checksum::new();
        match *self {
            IpRepr::V4 { src, dst, .. } => {
                sum.add_slice(&src.octets());
                sum.add_slice(&dst.octets());
                sum.add_u16(u16::from(IPPROTO_UDP));
                sum.add_u16(udp_len);
            }
            IpRepr::V6 { src, dst, .. } => {
                sum.add_slice(&src.octets());
                sum.add_slice(&dst.octets());
                sum.add_u16(0); // upper-layer packet length, high half
                sum.add_u16(udp_len);
                sum.add_u16(0); // zero, zero
                sum.add_u16(u16::from(IPPROTO_UDP)); // zero, next header
            }
        }
        sum
    }

    /// The source address, used to build a FRAG reassembly key.
    pub fn src_addr(&self) -> IpAddr {
        match *self {
            IpRepr::V4 { src, .. } => IpAddr::V4(src),
            IpRepr::V6 { src, .. } => IpAddr::V6(src),
        }
    }

    /// The destination address, used to build a FRAG reassembly key.
    pub fn dst_addr(&self) -> IpAddr {
        match *self {
            IpRepr::V4 { dst, .. } => IpAddr::V4(dst),
            IpRepr::V6 { dst, .. } => IpAddr::V6(dst),
        }
    }
}

/// 192.0.2.1:12345 -> 198.51.100.2:53, TTL 64, id 0, UDP payload "hello" (UDP checksum 0x9f5c).
///
/// Shared with the `wire::udp` tests; the checksums were computed with an independent RFC 1071
/// implementation and verified receiver-side (data plus stored checksum folds to all ones).
#[cfg(test)]
pub(crate) const V4_HELLO_DATAGRAM: [u8; 33] = [
    0x45, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x8e, 0x95, 0xc0, 0x00, 0x02, 0x01, 0xc6, 0x33, 0x64,
    0x02, // IPv4 header, header checksum 0x8e95
    0x30, 0x39, 0x00, 0x35, 0x00, 0x0d, 0x9f, 0x5c, // UDP header, length 13
    b'h', b'e', b'l', b'l', b'o',
];

/// [2001:db8::1]:12345 -> [2001:db8::2]:53, hop limit 64, UDP payload "hello" (UDP checksum 0x301f).
#[cfg(test)]
pub(crate) const V6_HELLO_DATAGRAM: [u8; 53] = [
    0x60, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x11, 0x40, // IPv6 header: payload length 13, next header 17
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // dst
    0x30, 0x39, 0x00, 0x35, 0x00, 0x0d, 0x30, 0x1f, // UDP header, length 13
    b'h', b'e', b'l', b'l', b'o',
];

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_hello_repr() -> IpRepr {
        IpRepr::V4 {
            src: Ipv4Addr::new(192, 0, 2, 1),
            dst: Ipv4Addr::new(198, 51, 100, 2),
            ihl: 5,
            total_len: 33,
        }
    }

    fn v6_hello_repr() -> IpRepr {
        IpRepr::V6 {
            src: "2001:db8::1".parse().unwrap(),
            dst: "2001:db8::2".parse().unwrap(),
            payload_len: 13,
            ext_hdr_len: 0,
        }
    }

    #[test]
    fn v4_parse_known_datagram() {
        let (repr, offset) = IpRepr::parse(&V4_HELLO_DATAGRAM).unwrap();
        assert_eq!(repr, v4_hello_repr());
        assert_eq!(offset, 20);
        assert_eq!(repr.header_len(), 20);
        assert_eq!(repr.transport_payload_len(), 13);
        assert_eq!(repr.src_addr(), IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(repr.dst_addr(), IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));
    }

    #[test]
    fn v4_write_matches_golden_bytes() {
        let mut out = [0u8; 20];
        v4_hello_repr().write(&mut out);
        assert_eq!(out, V4_HELLO_DATAGRAM[..20]);
    }

    #[test]
    fn v4_parse_skips_ip_options() {
        // The same datagram with IHL 6 and four NOP-padded IPv4 option bytes (kind 1).
        let mut datagram = Vec::from(&V4_HELLO_DATAGRAM[..]);
        datagram.splice(20..20, [0x01, 0x01, 0x01, 0x01]);
        datagram[0] = 0x46;
        datagram[2..4].copy_from_slice(&37u16.to_be_bytes());
        datagram[10..12].copy_from_slice(&[0, 0]);
        let checksum = internet_checksum(&datagram[..24]);
        datagram[10..12].copy_from_slice(&checksum.to_be_bytes());

        let (repr, offset) = IpRepr::parse(&datagram).unwrap();
        assert_eq!(offset, 24);
        assert_eq!(repr.header_len(), 24);
        assert_eq!(repr.transport_payload_len(), 13);
    }

    #[test]
    fn v4_rejects_corrupt_input() {
        let truncated = &V4_HELLO_DATAGRAM[..19];
        assert_eq!(
            IpRepr::parse(truncated),
            Err(HeaderError::IpTruncated { need: 20, have: 19 })
        );

        let mut wrong_version = V4_HELLO_DATAGRAM;
        wrong_version[0] = 0x55;
        assert_eq!(IpRepr::parse(&wrong_version), Err(HeaderError::UnsupportedVersion(5)));

        let mut bad_ihl = V4_HELLO_DATAGRAM;
        bad_ihl[0] = 0x44;
        assert_eq!(IpRepr::parse(&bad_ihl), Err(HeaderError::BadIhl(4)));

        let mut short_total_len = V4_HELLO_DATAGRAM;
        short_total_len[2..4].copy_from_slice(&19u16.to_be_bytes());
        assert_eq!(
            IpRepr::parse(&short_total_len),
            Err(HeaderError::BadIpLength { length: 19 })
        );

        let mut long_total_len = V4_HELLO_DATAGRAM;
        long_total_len[2..4].copy_from_slice(&34u16.to_be_bytes());
        assert_eq!(
            IpRepr::parse(&long_total_len),
            Err(HeaderError::BadIpLength { length: 34 })
        );

        let mut not_udp = V4_HELLO_DATAGRAM;
        not_udp[9] = 6;
        assert_eq!(IpRepr::parse(&not_udp), Err(HeaderError::UnexpectedProtocol(6)));

        let mut flipped = V4_HELLO_DATAGRAM;
        flipped[16] ^= 0x01;
        assert_eq!(IpRepr::parse(&flipped), Err(HeaderError::IpChecksumMismatch));
    }

    #[test]
    fn v6_parse_and_write_round_trip() {
        let (repr, offset) = IpRepr::parse(&V6_HELLO_DATAGRAM).unwrap();
        assert_eq!(repr, v6_hello_repr());
        assert_eq!(offset, 40);
        assert_eq!(repr.header_len(), 40);
        assert_eq!(repr.transport_payload_len(), 13);

        let mut out = [0u8; 40];
        repr.write(&mut out);
        assert_eq!(out, V6_HELLO_DATAGRAM[..40]);
    }

    #[test]
    fn v6_parse_accounts_hop_by_hop_ext_header() {
        // Insert one 8-byte Hop-by-Hop header (next header 17, length 0 = 8 octets, PadN options).
        let mut datagram = Vec::from(&V6_HELLO_DATAGRAM[..]);
        datagram.splice(40..40, [0x11, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]);
        datagram[4..6].copy_from_slice(&21u16.to_be_bytes());
        datagram[6] = 0; // hop-by-hop

        let (repr, offset) = IpRepr::parse(&datagram).unwrap();
        assert_eq!(offset, 48);
        assert_eq!(repr.header_len(), 48);
        assert_eq!(repr.transport_payload_len(), 13);
        let IpRepr::V6 {
            payload_len,
            ext_hdr_len,
            ..
        } = repr
        else {
            panic!("expected V6");
        };
        assert_eq!(payload_len, 21);
        assert_eq!(ext_hdr_len, 8);
    }

    #[test]
    fn v6_rejects_corrupt_input() {
        let truncated = &V6_HELLO_DATAGRAM[..39];
        assert_eq!(
            IpRepr::parse(truncated),
            Err(HeaderError::IpTruncated { need: 40, have: 39 })
        );

        let mut long_payload_len = V6_HELLO_DATAGRAM;
        long_payload_len[4..6].copy_from_slice(&14u16.to_be_bytes());
        assert_eq!(
            IpRepr::parse(&long_payload_len),
            Err(HeaderError::BadIpLength { length: 14 })
        );

        let mut not_udp = V6_HELLO_DATAGRAM;
        not_udp[6] = 6;
        assert_eq!(IpRepr::parse(&not_udp), Err(HeaderError::UnexpectedProtocol(6)));

        // A Hop-by-Hop header whose length runs past the payload end.
        let mut overrunning_ext = Vec::from(&V6_HELLO_DATAGRAM[..]);
        overrunning_ext.splice(40..40, [0x11, 0x07, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]);
        overrunning_ext[4..6].copy_from_slice(&21u16.to_be_bytes());
        overrunning_ext[6] = 0;
        assert_eq!(
            IpRepr::parse(&overrunning_ext),
            Err(HeaderError::BadIpLength { length: 21 })
        );
    }

    #[test]
    fn v6_rejects_misplaced_or_unsupported_ext_headers() {
        // A Routing header (43) is rejected: its final-destination pseudo-header semantics
        // (RFC 8200 Section 8.1) are out of scope.
        let mut routing = V6_HELLO_DATAGRAM;
        routing[6] = 43;
        assert_eq!(IpRepr::parse(&routing), Err(HeaderError::UnexpectedProtocol(43)));

        // Hop-by-Hop is legal only directly after the base header (RFC 8200 Section 4.1): here it
        // follows a Destination Options header instead.
        let mut misplaced_hbh = Vec::from(&V6_HELLO_DATAGRAM[..]);
        misplaced_hbh.splice(
            40..40,
            [
                0x00, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, // Destination Options, next header 0
                0x11, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, // Hop-by-Hop, next header 17
            ],
        );
        misplaced_hbh[4..6].copy_from_slice(&29u16.to_be_bytes());
        misplaced_hbh[6] = 60; // destination options first
        assert_eq!(IpRepr::parse(&misplaced_hbh), Err(HeaderError::UnexpectedProtocol(0)));
    }

    #[test]
    fn pseudo_header_sum_matches_reference() {
        // Independently computed over the RFC 768 / RFC 8200 Section 8.1 pseudo-header fields.
        assert_eq!(v4_hello_repr().pseudo_header_sum(13).sum(), 0xec55);
        assert_eq!(v6_hello_repr().pseudo_header_sum(13).sum(), 0x5b93);
    }
}
