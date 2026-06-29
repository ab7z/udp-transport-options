//! Property-based tests over typed must-support option decoding (Step 7 hardening).

mod common_typed;

use proptest::collection::vec;
use proptest::prelude::*;

proptest! {
    #[test]
    fn typed_decoders_never_panic_or_accept_bad_lengths(bytes in vec(any::<u8>(), 0..=64)) {
        common_typed::check_typed_decoder_invariants(&bytes);
    }
}
