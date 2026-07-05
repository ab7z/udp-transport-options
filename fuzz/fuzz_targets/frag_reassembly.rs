//! Coverage-guided fuzzing of the Step 12 FRAG reassembler.
//!
//! ```sh
//! cargo +nightly fuzz run frag_reassembly fuzz/corpus/frag_reassembly \
//!     fuzz/seeds/frag_reassembly -- -max_total_time=60 -max_len=512 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common_frag_reassembly/mod.rs");

fuzz_target!(|data: &[u8]| {
    let split_at = data.len().min(192);
    let payload = &data[..split_at];
    let options = options_body_from_fuzz_bytes(&data[split_at..]);
    let max_fragment_surplus_len = 16 + usize::from(data.first().copied().unwrap_or(0));
    let identification = u32::from_be_bytes([
        data.get(1).copied().unwrap_or(0x12),
        data.get(2).copied().unwrap_or(0x34),
        data.get(3).copied().unwrap_or(0x56),
        data.get(4).copied().unwrap_or(0x78),
    ]);
    let reverse = data.get(5).is_some_and(|byte| byte & 1 == 1);

    let config = SplitConfig {
        max_fragment_surplus_len,
        peer: PeerFragmentLimits {
            max_reassembled_size: u16::MAX,
            max_segments: u8::MAX,
        },
        identification,
    };

    check_reassembly_invariants(payload, &options, config, reverse);
});
