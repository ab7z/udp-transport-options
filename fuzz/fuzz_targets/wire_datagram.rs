//! Coverage-guided fuzzing of the IP -> UDP -> surplus parse chain.
//!
//! The body is the shared joint-invariant oracle from tests/common/mod.rs, spliced in via
//! `include!` so the fuzzer and the test suite can never check different invariants. Run with
//! both corpora so new findings land in the gitignored working corpus while the curated seeds
//! stay fixed:
//!
//! ```sh
//! cargo +nightly fuzz run wire_datagram fuzz/corpus/wire_datagram fuzz/seeds/wire_datagram -- \
//!     -max_total_time=60 -max_len=2048 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common/mod.rs");

fuzz_target!(|data: &[u8]| {
    check_wire_invariants(data);
});
