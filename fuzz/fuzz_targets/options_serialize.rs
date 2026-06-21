//! Coverage-guided fuzzing of canonical option serialization plus parse-back invariants.
//!
//! ```sh
//! cargo +nightly fuzz run options_serialize fuzz/corpus/options_serialize \
//!     fuzz/seeds/options_serialize -- -max_total_time=60 -max_len=512 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common_options/mod.rs");

fuzz_target!(|data: &[u8]| {
    let options = raw_options_from_fuzz_bytes(data);
    check_serializer_invariants(options);
});
