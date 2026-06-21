//! Coverage-guided fuzzing of OCS compute and validation.
//!
//! ```sh
//! cargo +nightly fuzz run options_ocs fuzz/corpus/options_ocs fuzz/seeds/options_ocs -- \
//!     -max_total_time=60 -max_len=2048 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common_ocs/mod.rs");

fuzz_target!(|data: &[u8]| {
    check_ocs_invariants(data);
});
