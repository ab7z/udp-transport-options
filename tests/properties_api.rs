//! Property-based tests for the Step 13 public API composition.

use std::net::Ipv4Addr;
use std::time::Instant;

use proptest::collection::vec;
use proptest::prelude::*;
use udp_transport_options::api::{
    ApiDelivery, DatagramAddrs, ReceivePolicy, SendConfig, SendOptions, build_outgoing_datagrams, decode_datagram,
};
use udp_transport_options::frag::reassembly::{ReassemblyCache, ReassemblyLimits};
use udp_transport_options::frag::split::PeerFragmentLimits;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::typed::Req;

fn addrs() -> DatagramAddrs {
    DatagramAddrs {
        src: Ipv4Addr::new(192, 0, 2, 10),
        dst: Ipv4Addr::new(198, 51, 100, 20),
        src_port: 11111,
        dst_port: 22222,
    }
}

fn send_options(seed: &[u8]) -> SendOptions {
    let mut options = SendOptions::new();
    if seed.len() >= 4 {
        options.push_typed(Req {
            token: seed[0..4].try_into().expect("length checked"),
        });
    }
    options
}

proptest! {
    #[test]
    fn high_level_api_round_trips_payload_and_supported_options(
        payload in vec(any::<u8>(), 0..=96),
        option_seed in vec(any::<u8>(), 0..=8),
        identification in any::<u32>(),
    ) {
        let config = SendConfig {
            max_datagram_len: 64,
            peer: PeerFragmentLimits {
                max_reassembled_size: 512,
                max_segments: 8,
            },
            identification,
            ..SendConfig::default()
        };
        let datagrams = build_outgoing_datagrams(addrs(), &payload, send_options(&option_seed), config)
            .expect("bounded generated datagrams should fit the configured peer");

        let mut cache = ReassemblyCache::with_limits(ReassemblyLimits {
            max_reassembled_size: 512,
            max_segments: 8,
            max_pending_partials: 8,
            timeout: udp_transport_options::model::limits::REASSEMBLY_TIMEOUT_MAX,
        });
        let mut delivery = ApiDelivery::Buffered;
        for datagram in &datagrams {
            delivery = decode_datagram(datagram, &mut cache, Instant::now(), &ReceivePolicy::default())
                .expect("generated datagrams should decode");
        }

        let ApiDelivery::Received(received) = delivery else {
            panic!("final generated datagram should deliver");
        };
        prop_assert_eq!(received.data, payload);
        if option_seed.len() >= 4 {
            prop_assert!(received.options.iter().any(|option| option.kind == OptionKind::Req));
        }
    }
}
