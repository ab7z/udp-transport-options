//! IPv4 header parsing and building plus the fields the UDP-options layer needs.
//!
//! [`IpRepr`] exposes exactly what the UDP-options layer needs (addresses, the transport-payload
//! length, and a pseudo-header seed for the UDP checksum) so that surplus-area math, the UDP
//! pseudo-header, and FRAG keying are written once.

use std::net::Ipv4Addr;

use crate::error::HeaderError;
use crate::wire::checksum::{Checksum, internet_checksum};

/// The UDP protocol number (RFC 768), used as the IPv4 Protocol.
pub(crate) const IPPROTO_UDP: u8 = 17;

/// The fixed IPv4 header length in bytes when no IP options are present (IHL 5).
const IPV4_MIN_HEADER_LEN: usize = 20;
/// TTL emitted by [`IpRepr::write`].
const DEFAULT_TTL: u8 = 64;

/// A view of the IPv4 header fields the UDP-options layer depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRepr {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// Internet Header Length, in 32-bit words.
    pub ihl: u8,
    /// Total Length field (IPv4 header + transport payload), in bytes.
    pub total_len: u16,
}

impl IpRepr {
    /// Parses the leading IP header and returns the repr plus the byte offset of the transport
    /// payload from the start of the IP datagram.
    ///
    /// IPv4 options (IHL > 5) are skipped, never decoded, and the header checksum is verified
    /// (RFC 791 Section 3.1). Trailing buffer bytes beyond the IP length field are tolerated and
    /// ignored.
    pub fn parse(bytes: &[u8]) -> Result<(IpRepr, usize), HeaderError> {
        let &version_octet = bytes.first().ok_or(HeaderError::IpTruncated { need: 1, have: 0 })?;
        match version_octet >> 4 {
            4 => Self::parse_v4(bytes),
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
            IpRepr {
                src,
                dst,
                ihl,
                total_len,
            },
            header_len,
        ))
    }

    /// Writes the IP header into `out` (exactly 20 bytes).
    ///
    /// Building IPv4 options is out of scope, so this cannot round-trip a repr that [`Self::parse`]
    /// accepted from a datagram carrying them. The IPv4 header checksum is computed and back-patched.
    ///
    /// # Panics
    ///
    /// Panics if `out` is shorter than [`Self::header_len`], or if the repr carries IPv4 options
    /// this writer cannot build (`ihl != 5`).
    pub fn write(&self, out: &mut [u8]) {
        assert_eq!(self.ihl, 5, "building IPv4 options is out of scope");
        let out = &mut out[..IPV4_MIN_HEADER_LEN];
        out.fill(0);
        out[0] = 0x45; // version 4, IHL 5
        out[2..4].copy_from_slice(&self.total_len.to_be_bytes());
        out[8] = DEFAULT_TTL;
        out[9] = IPPROTO_UDP;
        out[12..16].copy_from_slice(&self.src.octets());
        out[16..20].copy_from_slice(&self.dst.octets());
        let checksum = internet_checksum(out);
        out[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    /// Byte offset of the transport payload from the start of the IP datagram: `ihl * 4`.
    pub fn header_len(&self) -> usize {
        usize::from(self.ihl) * 4
    }

    /// Length of the IP transport payload in bytes: `total_len - ihl * 4`.
    pub fn transport_payload_len(&self) -> usize {
        usize::from(self.total_len).saturating_sub(usize::from(self.ihl) * 4)
    }

    /// Folds the UDP pseudo-header into a fresh RFC 1071 accumulator.
    ///
    /// Source and destination addresses, a zero byte plus protocol 17, and the UDP Length
    /// (RFC 768). Callers continue with the UDP header and user data, then take `finish()`.
    pub fn pseudo_header_sum(&self, udp_len: u16) -> Checksum {
        let mut sum = Checksum::new();
        sum.add_slice(&self.src.octets());
        sum.add_slice(&self.dst.octets());
        sum.add_u16(u16::from(IPPROTO_UDP));
        sum.add_u16(udp_len);
        sum
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_hello_repr() -> IpRepr {
        IpRepr {
            src: Ipv4Addr::new(192, 0, 2, 1),
            dst: Ipv4Addr::new(198, 51, 100, 2),
            ihl: 5,
            total_len: 33,
        }
    }

    #[test]
    fn v4_parse_known_datagram() {
        let (repr, offset) = IpRepr::parse(&V4_HELLO_DATAGRAM).unwrap();
        assert_eq!(repr, v4_hello_repr());
        assert_eq!(offset, 20);
        assert_eq!(repr.header_len(), 20);
        assert_eq!(repr.transport_payload_len(), 13);
        assert_eq!(repr.src, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(repr.dst, Ipv4Addr::new(198, 51, 100, 2));
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
    fn parse_rejects_ipv6_as_unsupported_version() {
        // A version-6 datagram (version nibble 6) is out of scope and rejected by the wildcard arm.
        let ipv6 = [
            0x60, 0x00, 0x00, 0x00, 0x00, 0x0d, 0x11, 0x40, // IPv6 header: payload length 13, next header 17
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // src
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, // dst
            0x30, 0x39, 0x00, 0x35, 0x00, 0x0d, 0x30, 0x1f, // UDP header, length 13
            b'h', b'e', b'l', b'l', b'o',
        ];
        assert_eq!(IpRepr::parse(&ipv6), Err(HeaderError::UnsupportedVersion(6)));
    }

    #[test]
    fn pseudo_header_sum_matches_reference() {
        // Independently computed over the RFC 768 pseudo-header fields.
        assert_eq!(v4_hello_repr().pseudo_header_sum(13).sum(), 0xec55);
    }
}
