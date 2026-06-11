//! Property-based tests over the wire layer (Step 2 hardening).
//!
//! These check model-independent joint invariants between the parsed headers and the raw buffer —
//! relations a wrong shared mental model cannot satisfy by construction, unlike hand-derived
//! expected values. Case count: proptest reads `PROPTEST_CASES` at runtime (the pre-PR gate runs
//! 1024 on the host; the achim ssh runner forwards no environment, so the cross-target lane runs
//! the proptest default of 256).

mod common;

use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::sample::Index;
use udp_transport_options::wire::checksum::internet_checksum;
use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::surplus::locate_surplus;
use udp_transport_options::wire::udp::{self, UdpHeader};

/// Builds a complete IPv4 datagram: header (IHL 5, or IHL 6 with four spliced NOP IP options),
/// UDP header with a computed checksum, user data, and trailing surplus bytes.
fn build_v4(src: Ipv4Addr, dst: Ipv4Addr, ihl: u8, ports: (u16, u16), user: &[u8], surplus: &[u8]) -> Vec<u8> {
    assert!(ihl == 5 || ihl == 6);
    let header_len = usize::from(ihl) * 4;
    let udp_length = u16::try_from(udp::HEADER_LEN + user.len()).unwrap();
    let total_len = u16::try_from(header_len + usize::from(udp_length) + surplus.len()).unwrap();
    let mut buf = vec![0u8; usize::from(total_len)];

    // IpRepr::write only emits IHL-5 headers; for IHL 6 the NOP options are spliced in by hand and
    // the header checksum back-patched (same pattern as the v4_parse_skips_ip_options unit test).
    let ip = IpRepr::V4 {
        src,
        dst,
        ihl,
        total_len,
    };
    IpRepr::V4 {
        src,
        dst,
        ihl: 5,
        total_len,
    }
    .write(&mut buf);
    if ihl == 6 {
        buf[0] = 0x46;
        buf[20..24].fill(0x01); // four NOP IP options
        buf[10..12].fill(0);
        let checksum = internet_checksum(&buf[..header_len]);
        buf[10..12].copy_from_slice(&checksum.to_be_bytes());
    }

    write_udp_and_payload(&ip, header_len, ports, user, surplus, &mut buf);
    buf
}

/// Builds a complete IPv6 datagram, optionally with one 8-byte Hop-by-Hop extension header.
fn build_v6(src: Ipv6Addr, dst: Ipv6Addr, with_ext: bool, ports: (u16, u16), user: &[u8], surplus: &[u8]) -> Vec<u8> {
    let ext_hdr_len = if with_ext { 8 } else { 0 };
    let udp_length = u16::try_from(udp::HEADER_LEN + user.len()).unwrap();
    let payload_len = u16::try_from(usize::from(ext_hdr_len) + usize::from(udp_length) + surplus.len()).unwrap();
    let mut buf = vec![0u8; 40 + usize::from(payload_len)];

    let ip = IpRepr::V6 {
        src,
        dst,
        payload_len,
        ext_hdr_len,
    };
    IpRepr::V6 {
        src,
        dst,
        payload_len,
        ext_hdr_len: 0,
    }
    .write(&mut buf);
    if with_ext {
        buf[6] = 0; // hop-by-hop directly after the base header
        buf[40..48].copy_from_slice(&[0x11, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]);
    }

    write_udp_and_payload(&ip, 40 + usize::from(ext_hdr_len), ports, user, surplus, &mut buf);
    buf
}

fn write_udp_and_payload(ip: &IpRepr, udp_at: usize, ports: (u16, u16), user: &[u8], surplus: &[u8], buf: &mut [u8]) {
    let mut header = UdpHeader {
        src_port: ports.0,
        dst_port: ports.1,
        length: u16::try_from(udp::HEADER_LEN + user.len()).unwrap(),
        checksum: 0,
    };
    header.checksum = header.compute_checksum(ip, user);
    header.write(&mut buf[udp_at..udp_at + udp::HEADER_LEN]);
    let user_at = udp_at + udp::HEADER_LEN;
    buf[user_at..user_at + user.len()].copy_from_slice(user);
    buf[user_at + user.len()..].copy_from_slice(surplus);
}

/// User data lengths weighted toward the parity edge cases (even/odd UDP Length, empty).
fn user_data() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        1 => Just(Vec::new()),
        1 => vec(any::<u8>(), 1..=1),
        1 => vec(any::<u8>(), 4..=5),
        3 => vec(any::<u8>(), 0..=64),
    ]
}

/// Surplus lengths forcing the 0/1/2/3 minimal-area boundaries alongside larger areas.
fn surplus_data() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        4 => vec(any::<u8>(), 0..=3),
        3 => vec(any::<u8>(), 4..=32),
    ]
}

fn v4_datagram() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<[u8; 4]>(),
        any::<[u8; 4]>(),
        prop_oneof![Just(5u8), Just(6u8)],
        any::<(u16, u16)>(),
        user_data(),
        surplus_data(),
    )
        .prop_map(|(src, dst, ihl, ports, user, surplus)| build_v4(src.into(), dst.into(), ihl, ports, &user, &surplus))
}

fn v6_datagram() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<[u8; 16]>(),
        any::<[u8; 16]>(),
        any::<bool>(),
        any::<(u16, u16)>(),
        user_data(),
        surplus_data(),
    )
        .prop_map(|(src, dst, with_ext, ports, user, surplus)| {
            build_v6(src.into(), dst.into(), with_ext, ports, &user, &surplus)
        })
}

fn valid_datagram() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![v4_datagram(), v6_datagram()]
}

/// Raw bytes plus valid datagrams with 1..=4 XOR-flipped bytes: mutations reach far deeper into
/// the parse chain than unstructured bytes, which rarely survive the IP header checksum.
fn arbitrary_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        vec(any::<u8>(), 0..=128),
        (valid_datagram(), vec((any::<Index>(), 1u8..=255), 1..=4)).prop_map(|(mut buf, flips)| {
            for (index, mask) in flips {
                let at = index.index(buf.len());
                buf[at] ^= mask;
            }
            buf
        }),
    ]
}

proptest! {
    /// Property 1a: IPv4 header write -> parse round-trip, offset == header_len.
    #[test]
    fn v4_header_round_trip(src in any::<[u8; 4]>(), dst in any::<[u8; 4]>(), payload_len in 0u16..=200) {
        let total_len = 20 + payload_len;
        let ip = IpRepr::V4 { src: src.into(), dst: dst.into(), ihl: 5, total_len };
        let mut buf = vec![0u8; usize::from(total_len)];
        ip.write(&mut buf);
        let (parsed, offset) = IpRepr::parse(&buf).unwrap();
        prop_assert_eq!(&parsed, &ip);
        prop_assert_eq!(offset, ip.header_len());
    }

    /// Property 1b: IPv6 header write -> parse round-trip, offset == header_len.
    #[test]
    fn v6_header_round_trip(src in any::<[u8; 16]>(), dst in any::<[u8; 16]>(), payload_len in 0u16..=200) {
        let ip = IpRepr::V6 { src: src.into(), dst: dst.into(), payload_len, ext_hdr_len: 0 };
        let mut buf = vec![0u8; 40 + usize::from(payload_len)];
        ip.write(&mut buf);
        let (parsed, offset) = IpRepr::parse(&buf).unwrap();
        prop_assert_eq!(&parsed, &ip);
        prop_assert_eq!(offset, ip.header_len());
    }

    /// Property 2: on any successfully built datagram, header_len + transport_payload_len equals
    /// the real buffer end (the builders size the buffer from the declared lengths).
    #[test]
    fn declared_lengths_match_buffer(buf in valid_datagram()) {
        let (ip, offset) = IpRepr::parse(&buf).unwrap();
        prop_assert_eq!(offset, ip.header_len());
        prop_assert_eq!(ip.header_len() + ip.transport_payload_len(), buf.len());
    }

    /// Property 3: UDP header write -> parse round-trip for any field values with length >= 8.
    #[test]
    fn udp_header_round_trip(src_port in any::<u16>(), dst_port in any::<u16>(), length in 8u16.., checksum in any::<u16>()) {
        let header = UdpHeader { src_port, dst_port, length, checksum };
        let mut out = [0u8; udp::HEADER_LEN];
        header.write(&mut out);
        prop_assert_eq!(UdpHeader::parse(&out).unwrap(), header);
    }

    /// Property 4: receiver-side verification — the pseudo-header plus the UDP header (with its
    /// stored checksum) plus the user data folds to one's-complement zero.
    #[test]
    fn stored_checksum_verifies_to_zero(buf in valid_datagram()) {
        let (ip, offset) = IpRepr::parse(&buf).unwrap();
        let header = UdpHeader::parse(&buf[offset..]).unwrap();
        let mut sum = ip.pseudo_header_sum(header.length);
        sum.add_slice(&buf[offset..offset + usize::from(header.length)]);
        prop_assert_eq!(sum.finish(), 0);
    }

    /// Property 5: the UDP checksum covers the user data only — flipping arbitrary surplus bytes
    /// must leave receiver-side verification intact (RFC 9868 Section 17).
    #[test]
    fn checksum_ignores_surplus(buf in valid_datagram(), flips in vec((any::<Index>(), 1u8..=255), 1..=4)) {
        let mut buf = buf;
        let (ip, offset) = IpRepr::parse(&buf).unwrap();
        let header = UdpHeader::parse(&buf[offset..]).unwrap();
        if let Some(layout) = locate_surplus(&ip, &header) {
            for (index, mask) in flips {
                buf[layout.starts_at + index.index(layout.len)] ^= mask;
            }
            let mut sum = ip.pseudo_header_sum(header.length);
            sum.add_slice(&buf[offset..offset + usize::from(header.length)]);
            prop_assert_eq!(sum.finish(), 0);
        }
    }

    /// Properties 6-9: the joint surplus-layout invariants (area ends at the IP datagram end, pad
    /// parity, OCS alignment, minimal-size iff) over structured datagrams. The oracle actually
    /// indexes every claimed range; see tests/common/mod.rs.
    #[test]
    fn surplus_layout_invariants(buf in valid_datagram()) {
        common::check_wire_invariants(&buf);
    }

    /// Property 10: the parse chain never panics and never yields out-of-bounds offsets on
    /// arbitrary or bit-flipped input.
    #[test]
    fn parse_chain_never_panics(buf in arbitrary_bytes()) {
        common::check_wire_invariants(&buf);
    }
}
