//! Property-based tests over the canonical UDP option serializer (Step 5 hardening).
//!
//! The serializer owns canonicalization: it reserves the OCS placeholder, orders accepted SAFE
//! options, inserts only required inter-option NOP alignment, and emits EOL plus zero-fill.

mod common_options;

use proptest::collection::vec;
use proptest::prelude::*;
use udp_transport_options::model::kind;
use udp_transport_options::options::RawOption;
use udp_transport_options::options::kind::OptionKind;

fn safe_raw_option_strategy() -> impl Strategy<Value = RawOption> {
    prop_oneof![
        (Just(kind::APC), vec(any::<u8>(), 4..=4)),
        (
            Just(kind::FRAG),
            prop_oneof![vec(any::<u8>(), 8..=8), vec(any::<u8>(), 10..=10)]
        ),
        (Just(kind::MDS), vec(any::<u8>(), 2..=2)),
        (Just(kind::MRDS), vec(any::<u8>(), 3..=3)),
        (Just(kind::REQ), vec(any::<u8>(), 4..=4)),
        (Just(kind::RES), vec(any::<u8>(), 4..=4)),
        (10u8..=126, vec(any::<u8>(), 0..=300)),
    ]
    .prop_map(|(kind, value)| RawOption {
        kind: OptionKind::from_byte(kind),
        value,
    })
}

proptest! {
    #[test]
    fn serializer_output_round_trips_to_canonical_options(
        options in vec(safe_raw_option_strategy(), 0..=32)
    ) {
        common_options::check_serializer_invariants(options);
    }
}
