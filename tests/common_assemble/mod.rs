// Shared socket assembly oracle.
//
// Used by `mod common_assemble;` from property/integration tests and spliced into the
// `socket_assemble` fuzz target via `include!`. Keep this file free of inner attributes so both
// contexts compile the same assertions.

use std::net::Ipv4Addr;

use udp_transport_options::error::ParseError;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::ocs::{self, OcsCheck};
use udp_transport_options::options::serialize::OptionsBuilder;
use udp_transport_options::socket::send::assemble_datagram;
use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::surplus::locate_surplus;
use udp_transport_options::wire::udp::{self, UdpHeader};

#[allow(dead_code)]
pub fn options_body_from_fuzz_bytes(data: &[u8]) -> Vec<u8> {
    let mut builder = OptionsBuilder::new();
    if data.len() >= 4 {
        builder.push(OptionKind::Req, data[0..4].to_vec());
    }
    if data.len() >= 8 {
        builder.push(OptionKind::Res, data[4..8].to_vec());
    }
    if data.len() >= 10 {
        builder.push(OptionKind::Mds, data[8..10].to_vec());
    }
    if data.len() >= 13 {
        builder.push(OptionKind::Mrds, data[10..13].to_vec());
    }
    if data.len() >= 17 {
        builder.push(OptionKind::Apc, data[13..17].to_vec());
    }
    if data.len() > 17 {
        builder.push(OptionKind::Other(10), data[17..data.len().min(49)].to_vec());
    }
    builder.finish().expect("fixed fuzz-derived options are serializable")
}

#[allow(dead_code)]
pub fn check_assembly_invariants(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    user_data: &[u8],
    options_body: &[u8],
) {
    let datagram = assemble_datagram(src, dst, src_port, dst_port, user_data, options_body);
    check_datagram_matches(&datagram, src, dst, src_port, dst_port, user_data, options_body);
}

pub fn check_datagram_matches(
    datagram: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    user_data: &[u8],
    options_body: &[u8],
) {
    let (ip, udp_at) = IpRepr::parse(datagram).expect("assembled datagram must parse as IPv4 UDP");
    assert_eq!(ip.src, src);
    assert_eq!(ip.dst, dst);
    assert_eq!(udp_at, ip.header_len());
    assert_eq!(usize::from(ip.total_len), datagram.len());
    assert_eq!(ip.header_len() + ip.transport_payload_len(), datagram.len());

    let udp = UdpHeader::parse(&datagram[udp_at..]).expect("assembled UDP header must parse");
    assert_eq!(udp.src_port, src_port);
    assert_eq!(udp.dst_port, dst_port);
    assert_eq!(usize::from(udp.length), udp::HEADER_LEN + user_data.len());
    assert!(usize::from(udp.length) < ip.transport_payload_len());

    let user_at = udp_at + udp::HEADER_LEN;
    let natural_start = udp_at + usize::from(udp.length);
    assert_eq!(&datagram[user_at..natural_start], user_data);

    let mut sum = ip.pseudo_header_sum(udp.length);
    sum.add_slice(&datagram[udp_at..natural_start]);
    assert_eq!(sum.finish(), 0);
    assert_eq!(
        udp.checksum,
        UdpHeader { checksum: 0, ..udp }.compute_checksum(&ip, user_data)
    );

    let layout = locate_surplus(&ip, &udp).expect("assembled datagram must have usable surplus");
    assert_eq!(layout.starts_at, natural_start);
    assert_eq!(layout.needs_pad, natural_start % 2 == 1);
    assert_eq!(layout.range(), natural_start..datagram.len());
    if layout.needs_pad {
        assert_eq!(datagram[layout.starts_at], 0);
    }

    let body = &datagram[layout.ocs_at()..datagram.len()];
    assert_eq!(body.len(), options_body.len());
    let mut expected_body = options_body.to_vec();
    ocs::compute(&mut expected_body, layout.len as u16);
    assert_eq!(body, expected_body);
    assert_eq!(ocs::validate(body, layout.len as u16, udp.checksum), OcsCheck::Valid);

    if layout.len < u16::MAX as usize {
        assert_eq!(
            ocs::validate(body, (layout.len + 1) as u16, udp.checksum),
            OcsCheck::Error(ParseError::OcsMismatch)
        );
    }
}

#[allow(dead_code)]
pub fn force_odd_user_data(mut user_data: Vec<u8>) -> Vec<u8> {
    if user_data.len().is_multiple_of(2) {
        user_data.push(0xa5);
    }
    user_data
}
