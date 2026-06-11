//! The UDP header and the UDP checksum.
//!
//! The kernel does not compute the UDP checksum for raw sockets, so this crate computes it. The
//! checksum covers the pseudo-header, the UDP header, and the user data only — never the surplus
//! area, which RFC 9868 bounds by the UDP Length field (RFC 9868 Section 17).

use crate::error::HeaderError;
use crate::wire::ip::IpRepr;

/// The fixed length of the UDP header in bytes (RFC 768).
pub const HEADER_LEN: usize = 8;

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

impl UdpHeader {
    /// Parses the eight-byte UDP header.
    ///
    /// Rejects a UDP Length below 8 (RFC 768; FR-49 lower bound). The upper bound — UDP Length no
    /// larger than the IP transport payload — needs the [`IpRepr`] and is the receive pipeline's
    /// check. The stored checksum is not verified here.
    pub fn parse(bytes: &[u8]) -> Result<UdpHeader, HeaderError> {
        if bytes.len() < HEADER_LEN {
            return Err(HeaderError::UdpTruncated { have: bytes.len() });
        }
        let length = u16::from_be_bytes([bytes[4], bytes[5]]);
        if usize::from(length) < HEADER_LEN {
            return Err(HeaderError::UdpLengthInvalid { length });
        }
        Ok(UdpHeader {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            length,
            checksum: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }

    /// Writes the eight header bytes in network byte order.
    ///
    /// # Panics
    ///
    /// Panics if `out` is shorter than [`HEADER_LEN`].
    pub fn write(&self, out: &mut [u8]) {
        out[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[4..6].copy_from_slice(&self.length.to_be_bytes());
        out[6..8].copy_from_slice(&self.checksum.to_be_bytes());
    }

    /// Computes the wire-value UDP checksum over the pseudo-header, this header (with the checksum
    /// field taken as zero), and the user data only — the surplus area never enters this sum
    /// (RFC 768; RFC 9868 Section 17).
    ///
    /// A computed zero is transmitted as `0xFFFF` (RFC 768), so this never returns 0; the
    /// receive-side acceptance of a stored zero checksum ("no checksum", RFC 9868 Section 14) is
    /// the pipeline's policy, not handled here.
    ///
    /// # Panics
    ///
    /// Panics if `self.length` does not equal `HEADER_LEN + data.len()` — a mismatch would
    /// silently yield a checksum over the wrong byte range.
    pub fn compute_checksum(&self, ip: &IpRepr, data: &[u8]) -> u16 {
        assert_eq!(
            usize::from(self.length),
            HEADER_LEN + data.len(),
            "UDP Length must cover the user data"
        );
        let mut sum = ip.pseudo_header_sum(self.length);
        sum.add_u16(self.src_port);
        sum.add_u16(self.dst_port);
        sum.add_u16(self.length);
        // The checksum field itself contributes zero to the sum.
        sum.add_slice(data);
        match sum.finish() {
            0 => 0xffff,
            checksum => checksum,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ip::{V4_HELLO_DATAGRAM, V6_HELLO_DATAGRAM};

    fn hello_header() -> UdpHeader {
        UdpHeader {
            src_port: 12345,
            dst_port: 53,
            length: 13,
            checksum: 0x9f5c,
        }
    }

    #[test]
    fn parse_write_round_trip() {
        let header = UdpHeader::parse(&V4_HELLO_DATAGRAM[20..]).unwrap();
        assert_eq!(header, hello_header());

        let mut out = [0u8; HEADER_LEN];
        header.write(&mut out);
        assert_eq!(out, V4_HELLO_DATAGRAM[20..28]);
    }

    #[test]
    fn checksum_matches_known_good_v4_datagram() {
        // The odd-length payload "hello" exercises the trailing-byte rule of the RFC 1071 sum.
        let (ip, offset) = IpRepr::parse(&V4_HELLO_DATAGRAM).unwrap();
        let header = UdpHeader::parse(&V4_HELLO_DATAGRAM[offset..]).unwrap();
        let checksum = header.compute_checksum(&ip, &V4_HELLO_DATAGRAM[offset + HEADER_LEN..]);
        assert_eq!(checksum, 0x9f5c);
        assert_eq!(checksum, header.checksum);
    }

    #[test]
    fn checksum_matches_known_good_v6_datagram() {
        let (ip, offset) = IpRepr::parse(&V6_HELLO_DATAGRAM).unwrap();
        let header = UdpHeader::parse(&V6_HELLO_DATAGRAM[offset..]).unwrap();
        let checksum = header.compute_checksum(&ip, &V6_HELLO_DATAGRAM[offset + HEADER_LEN..]);
        assert_eq!(checksum, 0x301f);
        assert_eq!(checksum, header.checksum);
    }

    #[test]
    fn checksum_covers_user_data_only() {
        // The same datagram with four trailing surplus bytes: the user data slice (bounded by UDP
        // Length) is unchanged, so the checksum must not change either (FR-03).
        let mut with_surplus = Vec::from(&V4_HELLO_DATAGRAM[..]);
        with_surplus.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        with_surplus[2..4].copy_from_slice(&37u16.to_be_bytes());

        let header = hello_header();
        let ip = IpRepr::V4 {
            src: "192.0.2.1".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
            ihl: 5,
            total_len: 37,
        };
        let user_data = &with_surplus[28..28 + usize::from(header.length) - HEADER_LEN];
        assert_eq!(header.compute_checksum(&ip, user_data), 0x9f5c);
    }

    #[test]
    fn computed_zero_transmits_as_ffff() {
        // Independently constructed so the one's-complement sum is 0xffff: the complement is 0,
        // which RFC 768 requires to be transmitted as all ones.
        let header = UdpHeader {
            src_port: 12345,
            dst_port: 53,
            length: 10,
            checksum: 0,
        };
        let ip = IpRepr::V4 {
            src: "192.0.2.1".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
            ihl: 5,
            total_len: 30,
        };
        assert_eq!(header.compute_checksum(&ip, &[0xe3, 0x34]), 0xffff);
    }

    #[test]
    fn parse_rejects_corrupt_input() {
        assert_eq!(
            UdpHeader::parse(&V4_HELLO_DATAGRAM[20..27]),
            Err(HeaderError::UdpTruncated { have: 7 })
        );

        let mut short_length = [0u8; HEADER_LEN];
        hello_header().write(&mut short_length);
        short_length[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            UdpHeader::parse(&short_length),
            Err(HeaderError::UdpLengthInvalid { length: 7 })
        );
    }
}
