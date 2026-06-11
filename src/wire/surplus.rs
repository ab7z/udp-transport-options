//! Locating the surplus area within an IP datagram.
//!
//! The surplus area runs from the end of the UDP payload (UDP Length) to the end of the IP transport
//! payload (RFC 9868 Section 7). The OCS must begin on a 2-byte boundary relative to the start of
//! the IP datagram; if the area's natural start is odd, a single zero pad byte precedes the OCS
//! (RFC 9868 Section 8).

use crate::model::length::OCS;
use crate::wire::ip::IpRepr;
use crate::wire::udp::UdpHeader;

/// The computed layout of the surplus area relative to the start of the IP datagram.
///
/// `starts_at..starts_at + len` is exactly the surplus area: the alignment pad byte, when present,
/// is the area's first byte (RFC 9868 Section 8 — "option area bytes used for alignment before the
/// OCS MUST be zero"), and the OCS field sits at `starts_at + usize::from(needs_pad)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurplusLayout {
    /// Byte offset of the surplus area from the start of the IP datagram. Odd exactly when
    /// `needs_pad` (the single zero pad byte that precedes the OCS lives at this offset).
    pub starts_at: usize,
    /// Whether a single zero pad byte precedes the OCS (true when `starts_at` is odd).
    pub needs_pad: bool,
    /// Length of the surplus area in bytes, including any pad byte and the OCS.
    pub len: usize,
}

/// Computes where the surplus area lives, or `None` when there is no usable surplus area.
///
/// The surplus area is the IP transport payload past the UDP Length (RFC 9868 Section 7). Its
/// natural start offset is counted from byte 0 of the IP datagram — for IPv6 that is the base
/// header, so extension headers count toward the offset (RFC 9868 Section 8). Returns `None` when
/// there is no surplus, when the area is too small to hold the aligned OCS plus any required pad
/// byte (RFC 9868 Section 8: options exist only "as long as there remains enough space for the
/// aligned OCS"), or — defensively — when the UDP Length exceeds the transport payload; that
/// datagram is invalid (FR-49) and must already have been dropped by the receive pipeline.
pub fn locate_surplus(ip: &IpRepr, udp: &UdpHeader) -> Option<SurplusLayout> {
    let surplus = ip.transport_payload_len().checked_sub(usize::from(udp.length))?;
    if surplus == 0 {
        return None;
    }
    let natural_start = ip.header_len() + usize::from(udp.length);
    let needs_pad = natural_start % 2 == 1;
    if surplus < usize::from(needs_pad) + usize::from(OCS) {
        return None;
    }
    Some(SurplusLayout {
        starts_at: natural_start,
        needs_pad,
        len: surplus,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(total_len: u16) -> IpRepr {
        IpRepr::V4 {
            src: "192.0.2.1".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
            ihl: 5,
            total_len,
        }
    }

    fn udp(length: u16) -> UdpHeader {
        UdpHeader {
            src_port: 12345,
            dst_port: 53,
            length,
            checksum: 0,
        }
    }

    #[test]
    fn even_natural_start() {
        // Header 20 + UDP Length 12 = natural start 32 (even): no pad, OCS at 32.
        let layout = locate_surplus(&v4(36), &udp(12)).unwrap();
        assert_eq!(
            layout,
            SurplusLayout {
                starts_at: 32,
                needs_pad: false,
                len: 4
            }
        );
    }

    #[test]
    fn odd_natural_start_pads_one_byte() {
        // Header 20 + UDP Length 13 = surplus starts at 33 (odd): pad byte at 33, OCS at 34.
        let layout = locate_surplus(&v4(38), &udp(13)).unwrap();
        assert_eq!(
            layout,
            SurplusLayout {
                starts_at: 33,
                needs_pad: true,
                len: 5
            }
        );
    }

    #[test]
    fn none_when_udp_length_fills_payload() {
        assert_eq!(locate_surplus(&v4(33), &udp(13)), None);
    }

    #[test]
    fn none_when_udp_length_exceeds_payload() {
        // Transport payload 10 < UDP Length 13: invalid per FR-49, dropped upstream; defensively None.
        assert_eq!(locate_surplus(&v4(30), &udp(13)), None);
    }

    #[test]
    fn none_when_no_room_for_aligned_ocs() {
        // Even start, surplus 1: no room for the 2-byte OCS.
        assert_eq!(locate_surplus(&v4(33), &udp(12)), None);
        // Odd start, surplus 2: no room for pad + OCS.
        assert_eq!(locate_surplus(&v4(35), &udp(13)), None);
        // Odd start, surplus 3: pad + OCS fit exactly.
        let layout = locate_surplus(&v4(36), &udp(13)).unwrap();
        assert_eq!(
            layout,
            SurplusLayout {
                starts_at: 33,
                needs_pad: true,
                len: 3
            }
        );
    }

    #[test]
    fn even_minimal_surplus_holds_ocs_exactly() {
        // Even start, surplus 2: exactly the OCS, no room for any option — still a valid layout.
        let layout = locate_surplus(&v4(34), &udp(12)).unwrap();
        assert_eq!(
            layout,
            SurplusLayout {
                starts_at: 32,
                needs_pad: false,
                len: 2
            }
        );
    }

    #[test]
    fn v4_ip_options_shift_natural_start() {
        // IHL 6 (one 4-byte IP option): header 24 + UDP Length 12 = natural start 36 (still even —
        // an IPv4 header length is always a multiple of 4, so IP options never flip the parity).
        let ip = IpRepr::V4 {
            src: "192.0.2.1".parse().unwrap(),
            dst: "198.51.100.2".parse().unwrap(),
            ihl: 6,
            total_len: 40,
        };
        let layout = locate_surplus(&ip, &udp(12)).unwrap();
        assert_eq!(
            layout,
            SurplusLayout {
                starts_at: 36,
                needs_pad: false,
                len: 4
            }
        );
    }

    #[test]
    fn v6_ext_header_shifts_natural_start() {
        // Base header 40 + extension headers 8 + UDP Length 13 = surplus starts at 61 (odd):
        // pad byte at 61, OCS at 62.
        let ip = IpRepr::V6 {
            src: "2001:db8::1".parse().unwrap(),
            dst: "2001:db8::2".parse().unwrap(),
            payload_len: 25,
            ext_hdr_len: 8,
        };
        let layout = locate_surplus(&ip, &udp(13)).unwrap();
        assert_eq!(
            layout,
            SurplusLayout {
                starts_at: 61,
                needs_pad: true,
                len: 4
            }
        );
    }
}
