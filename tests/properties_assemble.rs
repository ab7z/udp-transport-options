//! Property-based tests for the Step 8 pure datagram assembler.

mod common_assemble;

use std::net::Ipv4Addr;

use proptest::collection::vec;
use proptest::prelude::*;

fn user_data() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        1 => Just(Vec::new()),
        1 => vec(any::<u8>(), 1..=1),
        1 => vec(any::<u8>(), 2..=3),
        3 => vec(any::<u8>(), 0..=96),
    ]
}

fn options_body() -> impl Strategy<Value = Vec<u8>> {
    vec(any::<u8>(), 0..=64).prop_map(|seed| common_assemble::options_body_from_fuzz_bytes(&seed))
}

proptest! {
    #[test]
    fn assembled_datagram_satisfies_wire_invariants(
        src in any::<[u8; 4]>(),
        dst in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        user in user_data(),
        options in options_body(),
    ) {
        common_assemble::check_assembly_invariants(
            Ipv4Addr::from(src),
            Ipv4Addr::from(dst),
            src_port,
            dst_port,
            &user,
            &options,
        );
    }

    #[test]
    fn assembled_datagram_handles_odd_surplus_start(
        src in any::<[u8; 4]>(),
        dst in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        user in vec(any::<u8>(), 0..=95).prop_map(common_assemble::force_odd_user_data),
        options in options_body(),
    ) {
        prop_assert!(!user.len().is_multiple_of(2));
        common_assemble::check_assembly_invariants(
            Ipv4Addr::from(src),
            Ipv4Addr::from(dst),
            src_port,
            dst_port,
            &user,
            &options,
        );
    }
}
