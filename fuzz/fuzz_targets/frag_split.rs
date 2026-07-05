//! Coverage-guided fuzzing of the Step 11 FRAG splitter.
//!
//! ```sh
//! cargo +nightly fuzz run frag_split fuzz/corpus/frag_split \
//!     fuzz/seeds/frag_split -- -max_total_time=60 -max_len=384 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use udp_transport_options::frag::split::PeerFragmentLimits;

include!("../../tests/common_frag_split/mod.rs");

fuzz_target!(|data: &[u8]| {
    let split_at = data.len().min(192);
    let payload = &data[..split_at];
    let options = options_body_from_fuzz_bytes(&data[split_at..]);
    let max_fragment_surplus_len = 16 + usize::from(data.first().copied().unwrap_or(0));
    let max_reassembled_size = u16::from_be_bytes([
        data.get(1).copied().unwrap_or(0xff),
        data.get(2).copied().unwrap_or(0xff),
    ]);
    let max_segments = data.get(3).copied().unwrap_or(u8::MAX);
    let identification = u32::from_be_bytes([
        data.get(4).copied().unwrap_or(0x12),
        data.get(5).copied().unwrap_or(0x34),
        data.get(6).copied().unwrap_or(0x56),
        data.get(7).copied().unwrap_or(0x78),
    ]);

    let config = SplitConfig {
        max_fragment_surplus_len,
        peer: PeerFragmentLimits {
            max_reassembled_size,
            max_segments,
        },
        identification,
    };

    check_split_invariants(payload, &options, config);
});
