//! Coverage-guided fuzzing of typed must-support option decoders.
//!
//! ```sh
//! cargo +nightly fuzz run options_typed fuzz/corpus/options_typed fuzz/seeds/options_typed -- \
//!     -max_total_time=60 -max_len=64 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common_typed/mod.rs");

fuzz_target!(|data: &[u8]| {
    check_typed_decoder_invariants(data);
});
