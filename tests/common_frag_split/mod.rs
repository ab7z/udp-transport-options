// Shared FRAG split oracle.
//
// Used by `mod common_frag_split;` from property tests and spliced into the `frag_split` fuzz target
// via `include!`. Keep this file free of inner attributes so both contexts compile the same checks.

use udp_transport_options::frag::split::{Fragment, SplitConfig, split_datagram};
use udp_transport_options::model::{kind, length};
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
pub fn check_split_invariants(payload: &[u8], per_datagram_options_body: &[u8], config: SplitConfig) {
    let result = split_datagram(payload, per_datagram_options_body, config);
    let Ok(fragments) = result else {
        return;
    };

    check_fragments(payload, per_datagram_options_body, config, &fragments);
}

#[allow(dead_code)]
pub fn check_split_must_succeed(payload: &[u8], per_datagram_options_body: &[u8], config: SplitConfig) {
    let fragments = split_datagram(payload, per_datagram_options_body, config)
        .expect("bounded split case should fit peer and fragment limits");
    check_fragments(payload, per_datagram_options_body, config, &fragments);
}

fn check_fragments(payload: &[u8], per_datagram_options_body: &[u8], config: SplitConfig, fragments: &[Fragment]) {
    assert!(!fragments.is_empty());
    assert!(fragments.len() <= usize::from(config.peer.max_segments));
    assert_eq!(fragments.iter().filter(|fragment| fragment.terminal).count(), 1);
    assert!(fragments.last().expect("non-empty fragments").terminal);

    let atomic = fragments.len() == 1 && fragments[0].terminal;
    let mut reassembled_tail = Vec::new();
    let mut expected_offset = if atomic { 0 } else { usize::from(length::UDP_HEADER) };
    for fragment in fragments {
        assert!(fragment.surplus_body.len() <= config.max_fragment_surplus_len);
        let (frag, data) = parsed_frag(fragment);
        assert_eq!(frag.identification, config.identification);
        assert_eq!(frag.frag_offset, fragment.frag_offset);
        assert_eq!(usize::from(fragment.frag_offset), expected_offset);
        assert_eq!(frag.rdos, fragment.rdos);
        assert_eq!(fragment.terminal, frag.rdos.is_some());
        if fragment.terminal {
            assert_eq!(
                fragment.rdos,
                Some(u16::from(length::UDP_HEADER) + payload.len() as u16)
            );
        } else {
            assert_eq!(fragment.rdos, None);
        }

        reassembled_tail.extend_from_slice(data);
        expected_offset += data.len();
    }

    let mut expected_tail = payload.to_vec();
    if !per_datagram_options_body.is_empty() && (usize::from(length::UDP_HEADER) + payload.len()) % 2 == 1 {
        expected_tail.push(0);
    }
    expected_tail.extend_from_slice(per_datagram_options_body);
    assert_eq!(reassembled_tail, expected_tail);
}

fn parsed_frag(fragment: &Fragment) -> (Frag, &[u8]) {
    assert_eq!(&fragment.surplus_body[..usize::from(length::OCS)], &[0, 0]);
    let option = OptionsIter::new(&fragment.surplus_body[usize::from(length::OCS)..])
        .next()
        .expect("fragment body has a FRAG option")
        .expect("fragment body has a valid FRAG TLV");
    assert_eq!(option.kind.to_byte(), kind::FRAG);
    let frag = Frag::decode(option.value).expect("fragment body has a valid FRAG value");
    let data_start = usize::from(frag.frag_start) - usize::from(length::UDP_HEADER);
    assert!(data_start <= fragment.surplus_body.len());
    (frag, &fragment.surplus_body[data_start..])
}
