// Shared FRAG reassembly oracle.
//
// Used by `mod common_frag_reassembly;` from property tests and spliced into the `frag_reassembly`
// fuzz target via `include!`. Keep this file free of inner attributes so both contexts compile the
// same assertions.

use std::net::Ipv4Addr;
use std::time::Instant;

use udp_transport_options::frag::reassembly::{FragKey, ReassemblyCache, ReassemblyLimits, ReassemblyOutcome};
use udp_transport_options::frag::split::{PeerFragmentLimits, SplitConfig, split_datagram};
use udp_transport_options::model::length;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::parse::OptionsIter;
use udp_transport_options::options::serialize::OptionsBuilder;
use udp_transport_options::options::typed::{Frag, TypedOption};

#[allow(dead_code)]
pub fn options_body_from_fuzz_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() || data[0].is_multiple_of(4) {
        return Vec::new();
    }

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
    if data.len() > 13 {
        builder.push(OptionKind::Other(10), data[13..data.len().min(45)].to_vec());
    }
    builder.finish().expect("fixed fuzz-derived options are serializable")
}

#[allow(dead_code)]
pub fn check_reassembly_invariants(
    payload: &[u8],
    per_datagram_options_body: &[u8],
    mut config: SplitConfig,
    reverse: bool,
) {
    config.peer = PeerFragmentLimits {
        max_reassembled_size: u16::MAX,
        max_segments: u8::MAX,
    };
    let Ok(fragments) = split_datagram(payload, per_datagram_options_body, config) else {
        return;
    };

    let mut cache = ReassemblyCache::with_limits(ReassemblyLimits {
        max_reassembled_size: usize::from(u16::MAX),
        max_segments: usize::from(u8::MAX),
        max_pending_partials: 8,
        timeout: udp_transport_options::model::limits::REASSEMBLY_TIMEOUT_MAX,
    });
    let key = FragKey {
        src: Ipv4Addr::new(192, 0, 2, 1),
        dst: Ipv4Addr::new(198, 51, 100, 2),
        src_port: 12345,
        dst_port: 54321,
        identification: config.identification,
    };

    let mut order: Vec<usize> = (0..fragments.len()).collect();
    if reverse {
        order.reverse();
    }
    let mut completed = None;
    for (position, index) in order.iter().copied().enumerate() {
        let (frag, data) = parsed_frag(&fragments[index].surplus_body);
        let outcome = cache.insert(key, frag, data, Instant::now());
        if position + 1 == order.len() {
            completed = Some(outcome);
        } else {
            assert_eq!(outcome, ReassemblyOutcome::Incomplete);
        }
    }

    let ReassemblyOutcome::Complete { tail, udp_length, .. } =
        completed.expect("non-empty fragment set should produce a final outcome")
    else {
        panic!("all split fragments should complete reassembly");
    };
    assert_eq!(tail, expected_tail(payload, per_datagram_options_body));
    assert_eq!(usize::from(udp_length), usize::from(length::UDP_HEADER) + payload.len());
    assert!(cache.is_empty());
}

fn parsed_frag(surplus_body: &[u8]) -> (Frag, &[u8]) {
    assert_eq!(&surplus_body[..usize::from(length::OCS)], &[0, 0]);
    let option = OptionsIter::new(&surplus_body[usize::from(length::OCS)..])
        .next()
        .expect("fragment body has a FRAG option")
        .expect("fragment body has a valid FRAG TLV");
    let frag = Frag::decode(option.value).expect("fragment body has a valid FRAG value");
    let data_start = usize::from(frag.frag_start) - usize::from(length::UDP_HEADER);
    assert!(data_start <= surplus_body.len());
    (frag, &surplus_body[data_start..])
}

fn expected_tail(payload: &[u8], per_datagram_options_body: &[u8]) -> Vec<u8> {
    let mut tail = payload.to_vec();
    if !per_datagram_options_body.is_empty() && (usize::from(length::UDP_HEADER) + payload.len()) % 2 == 1 {
        tail.push(0);
    }
    tail.extend_from_slice(per_datagram_options_body);
    tail
}
