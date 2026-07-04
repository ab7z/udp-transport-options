//! Property-based tests for the Step 10 pure receive pipeline.

mod common_assemble;
mod common_pipeline;

use std::net::Ipv4Addr;

use proptest::collection::vec;
use proptest::prelude::*;

proptest! {
    #[test]
    fn pipeline_is_total_over_arbitrary_datagrams(bytes in vec(any::<u8>(), 0..=2048)) {
        common_pipeline::check_pipeline_invariants(&bytes);
    }

    #[test]
    fn pipeline_accepts_assembled_datagrams(
        src in any::<[u8; 4]>(),
        dst in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        user in vec(any::<u8>(), 0..=96),
        seed in vec(any::<u8>(), 0..=64),
    ) {
        let options = common_assemble::options_body_from_fuzz_bytes(&seed);
        let datagram = udp_transport_options::socket::send::assemble_datagram(
            Ipv4Addr::from(src),
            Ipv4Addr::from(dst),
            src_port,
            dst_port,
            &user,
            &options,
        );
        common_pipeline::check_pipeline_invariants(&datagram);
    }
}
