//! Coverage-guided fuzzing of the Step 10 pure receive pipeline.
//!
//! ```sh
//! cargo +nightly fuzz run process_datagram fuzz/corpus/process_datagram \
//!     fuzz/seeds/process_datagram -- -max_total_time=60 -max_len=2048 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common_pipeline/mod.rs");

fuzz_target!(|data: &[u8]| {
    check_pipeline_invariants(data);
});
