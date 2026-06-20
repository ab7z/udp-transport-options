//! Coverage-guided fuzzing of the post-OCS TLV option parser.
//!
//! ```sh
//! cargo +nightly fuzz run options_tlv fuzz/corpus/options_tlv fuzz/seeds/options_tlv -- \
//!     -max_total_time=60 -max_len=2048 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common_options/mod.rs");

fuzz_target!(|data: &[u8]| {
    check_tlv_parser_invariants(data);
});
