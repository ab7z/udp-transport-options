// Shared typed-option decoder invariant oracle.
//
// Used by property tests and the `options_typed` fuzz target. This stays at the typed value layer:
// arbitrary bytes must either decode only at the RFC-fixed value lengths or return InvalidLength.

use std::fmt::Debug;
use udp_transport_options::error::ParseError;
use udp_transport_options::model::{kind, length};
use udp_transport_options::options::typed::{Apc, Frag, Mds, Mrds, Req, Res, TypedOption};

fn implied_total_len(value_len: usize) -> usize {
    value_len + 2
}

fn assert_fixed_decoder<T>(value: &[u8], raw_kind: u8, total_len: u8)
where
    T: TypedOption + Debug + PartialEq,
{
    let decoded = T::decode(value);
    if value.len() == total_len as usize - 2 {
        let option = decoded.expect("fixed-length value should decode");
        let mut encoded = Vec::new();
        option.encode(&mut encoded);
        assert_eq!(encoded[0], raw_kind);
        assert_eq!(encoded[1], total_len);
        assert_eq!(T::decode(&encoded[2..]), Ok(option));
    } else {
        assert_eq!(
            decoded,
            Err(ParseError::InvalidLength {
                kind: raw_kind,
                len: implied_total_len(value.len()),
            })
        );
    }
}

fn assert_frag_decoder(value: &[u8]) {
    let decoded = Frag::decode(value);
    if value.len() == length::FRAG_NON_TERMINAL as usize - 2 || value.len() == length::FRAG_TERMINAL as usize - 2 {
        let option = decoded.expect("FRAG value should decode at either RFC length");
        assert_eq!(option.rdos.is_some(), value.len() == length::FRAG_TERMINAL as usize - 2);

        let mut encoded = Vec::new();
        option.encode(&mut encoded);
        assert_eq!(encoded[0], kind::FRAG);
        assert_eq!(
            encoded[1],
            if option.rdos.is_some() {
                length::FRAG_TERMINAL
            } else {
                length::FRAG_NON_TERMINAL
            }
        );
        assert_eq!(Frag::decode(&encoded[2..]), Ok(option));
    } else {
        assert_eq!(
            decoded,
            Err(ParseError::InvalidLength {
                kind: kind::FRAG,
                len: implied_total_len(value.len()),
            })
        );
    }
}

pub fn check_typed_decoder_invariants(value: &[u8]) {
    assert_fixed_decoder::<Apc>(value, kind::APC, length::APC);
    assert_fixed_decoder::<Mds>(value, kind::MDS, length::MDS);
    assert_fixed_decoder::<Mrds>(value, kind::MRDS, length::MRDS);
    assert_fixed_decoder::<Req>(value, kind::REQ, length::REQ);
    assert_fixed_decoder::<Res>(value, kind::RES, length::RES);
    assert_frag_decoder(value);
}
