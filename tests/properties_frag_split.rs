//! Property-based tests for the Step 11 FRAG splitter.

mod common_frag_split;

use proptest::collection::vec;
use proptest::prelude::*;
use udp_transport_options::frag::split::{PeerFragmentLimits, SplitConfig};

proptest! {
    #[test]
    fn split_fragments_reassemble_to_the_original_tail(
        payload in vec(any::<u8>(), 0..=256),
        option_seed in vec(any::<u8>(), 0..=64),
        max_fragment_surplus_len in 32usize..=192,
        identification in any::<u32>(),
    ) {
        let options_body = common_frag_split::options_body_from_fuzz_bytes(&option_seed);
        let config = SplitConfig {
            max_fragment_surplus_len,
            peer: PeerFragmentLimits {
                max_reassembled_size: u16::MAX,
                max_segments: u8::MAX,
            },
            identification,
        };

        common_frag_split::check_split_invariants(&payload, &options_body, config);
    }

    #[test]
    fn small_bounded_splits_succeed_when_limits_are_sufficient(
        payload in vec(any::<u8>(), 0..=32),
        option_seed in vec(any::<u8>(), 0..=16),
        max_fragment_surplus_len in 16usize..=31,
        identification in any::<u32>(),
    ) {
        let options_body = common_frag_split::options_body_from_fuzz_bytes(&option_seed);
        let config = SplitConfig {
            max_fragment_surplus_len,
            peer: PeerFragmentLimits {
                max_reassembled_size: u16::MAX,
                max_segments: u8::MAX,
            },
            identification,
        };

        common_frag_split::check_split_must_succeed(&payload, &options_body, config);
    }
}
