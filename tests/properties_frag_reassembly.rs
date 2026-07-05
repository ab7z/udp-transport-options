//! Property-based tests for the Step 12 FRAG reassembler.

mod common_frag_reassembly;

use proptest::collection::vec;
use proptest::prelude::*;
use udp_transport_options::frag::split::{PeerFragmentLimits, SplitConfig};

proptest! {
    #[test]
    fn split_fragments_reassemble_in_either_order(
        payload in vec(any::<u8>(), 0..=128),
        option_seed in vec(any::<u8>(), 0..=48),
        max_fragment_surplus_len in 16usize..=128,
        identification in any::<u32>(),
        reverse in any::<bool>(),
    ) {
        let options_body = common_frag_reassembly::options_body_from_fuzz_bytes(&option_seed);
        let config = SplitConfig {
            max_fragment_surplus_len,
            peer: PeerFragmentLimits {
                max_reassembled_size: u16::MAX,
                max_segments: u8::MAX,
            },
            identification,
        };

        common_frag_reassembly::check_reassembly_invariants(&payload, &options_body, config, reverse);
    }
}
