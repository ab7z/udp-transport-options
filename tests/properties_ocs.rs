//! Property-based tests over OCS compute and validation (Step 6 hardening).

mod common_ocs;

use proptest::collection::vec;
use proptest::prelude::*;
use udp_transport_options::model::kind;
use udp_transport_options::options::RawOption;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::ocs::{self, OcsCheck};
use udp_transport_options::options::serialize::OptionsBuilder;

fn representative_option_positions(len: usize) -> impl Iterator<Item = usize> {
    let mut positions = Vec::from([2, len / 2, len.saturating_sub(1)]);
    positions.sort_unstable();
    positions.dedup();
    positions.into_iter().filter(move |pos| *pos >= 2 && *pos < len)
}

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
    fn ocs_never_panics_or_loops(bytes in vec(any::<u8>(), 0..=2048)) {
        common_ocs::check_ocs_invariants(&bytes);
    }

    #[test]
    fn serialized_options_patch_and_validate(options in vec(safe_raw_option_strategy(), 0..=32)) {
        let mut builder = OptionsBuilder::new();
        builder.extend_raw(options);
        let Ok(mut body) = builder.finish() else {
            return Ok(());
        };

        let surplus_len = body.len() as u16;
        ocs::compute(&mut body, surplus_len);
        prop_assert_eq!(ocs::validate(&body, surplus_len, 0x1234), OcsCheck::Valid);

        if let Some(padded_len) = surplus_len.checked_add(1) {
            let mut padded = body.clone();
            ocs::compute(&mut padded, padded_len);
            prop_assert_eq!(ocs::validate(&padded, padded_len, 0x1234), OcsCheck::Valid);
        }

        for i in representative_option_positions(body.len()) {
            let mut corrupted = body.clone();
            corrupted[i] ^= 0x01;
            prop_assert_ne!(ocs::validate(&corrupted, surplus_len, 0x1234), OcsCheck::Valid);
        }
    }
}
