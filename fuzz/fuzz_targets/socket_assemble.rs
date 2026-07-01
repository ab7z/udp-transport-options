//! Coverage-guided fuzzing of the Step 8 pure datagram assembler.
//!
//! ```sh
//! cargo +nightly fuzz run socket_assemble fuzz/corpus/socket_assemble \
//!     fuzz/seeds/socket_assemble -- -max_total_time=60 -max_len=256 -timeout=5 -rss_limit_mb=512
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;

include!("../../tests/common_assemble/mod.rs");

fuzz_target!(|data: &[u8]| {
    let src = std::net::Ipv4Addr::new(192, 0, 2, data.first().copied().unwrap_or(1));
    let dst = std::net::Ipv4Addr::new(198, 51, 100, data.get(1).copied().unwrap_or(2));
    let src_port = u16::from_be_bytes([data.get(2).copied().unwrap_or(0x30), data.get(3).copied().unwrap_or(0x39)]);
    let dst_port = u16::from_be_bytes([data.get(4).copied().unwrap_or(0x00), data.get(5).copied().unwrap_or(0x35)]);
    let split = data.len().min(80);
    let user = &data[..split];
    let options = options_body_from_fuzz_bytes(&data[split..]);

    check_assembly_invariants(src, dst, src_port, dst_port, user, &options);

    let odd_user = force_odd_user_data(user.to_vec());
    check_assembly_invariants(src, dst, src_port, dst_port, &odd_user, &options);
});
