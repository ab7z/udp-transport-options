//! Property-based tests over the zero-copy TLV parser (Step 4 hardening).
//!
//! The parser is intentionally total over arbitrary post-OCS bytes: malformed frames produce one
//! `ParseError` and then halt, while well-formed frames borrow value slices from the original input.

mod common_options;

use proptest::collection::vec;
use proptest::prelude::*;

proptest! {
    #[test]
    fn tlv_parser_never_panics_or_loops(bytes in vec(any::<u8>(), 0..=2048)) {
        common_options::check_tlv_parser_invariants(&bytes);
    }
}
