use std::net::Ipv4Addr;
use std::time::Instant;

use udp_transport_options::api::{
    ApiDelivery, DatagramAddrs, FragmentationMode, OptionSource, OptionStatus, ReceivePolicy, SendConfig, SendOptions,
    build_datagram, build_outgoing_datagrams, decode_datagram,
};
use udp_transport_options::error::{ReceivePolicyError, SendError, SplitError};
use udp_transport_options::frag::reassembly::{ReassemblyCache, ReassemblyLimits};
use udp_transport_options::frag::split::PeerFragmentLimits;
use udp_transport_options::model::length;
use udp_transport_options::options::RawOption;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::typed::{Apc, Req};
use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::surplus::locate_surplus;
use udp_transport_options::wire::udp::UdpHeader;

const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 20);
const SRC_PORT: u16 = 11111;
const DST_PORT: u16 = 22222;

fn addrs() -> DatagramAddrs {
    DatagramAddrs {
        src: SRC,
        dst: DST,
        src_port: SRC_PORT,
        dst_port: DST_PORT,
    }
}

fn raw(kind: OptionKind, value: &[u8]) -> RawOption {
    RawOption {
        kind,
        value: value.to_vec(),
    }
}

fn decode_one(datagram: &[u8]) -> ApiDelivery {
    decode_datagram(
        datagram,
        &mut ReassemblyCache::new(),
        Instant::now(),
        &ReceivePolicy::default(),
    )
    .expect("api decode succeeds")
}

#[test]
fn low_level_raw_option_round_trip() {
    let req = raw(OptionKind::Req, &[1, 2, 3, 4]);
    let datagram = build_datagram(addrs(), b"hello", std::slice::from_ref(&req)).unwrap();

    let ApiDelivery::Received(received) = decode_one(&datagram) else {
        panic!("expected received datagram");
    };
    assert_eq!(received.data, b"hello");
    assert_eq!(received.options, vec![req]);
    assert_eq!(received.reports[0].kind, OptionKind::Req);
    assert_eq!(received.reports[0].status, OptionStatus::Success);
    assert_eq!(received.reports[0].source, OptionSource::Datagram);
}

#[test]
fn low_level_rejects_frag_with_user_data() {
    let frag = raw(OptionKind::Frag, &[0; 8]);
    assert!(matches!(
        build_datagram(addrs(), b"payload", &[frag]),
        Err(SendError::InvalidConfig { .. })
    ));
}

#[test]
fn typed_send_options_and_apc_are_reported() {
    let mut options = SendOptions::new().with_apc();
    options.push_typed(Req { token: [9, 8, 7, 6] });
    let datagrams = build_outgoing_datagrams(addrs(), b"typed", options, SendConfig::default()).unwrap();
    assert_eq!(datagrams.len(), 1);

    let ApiDelivery::Received(received) = decode_one(&datagrams[0]) else {
        panic!("expected received datagram");
    };
    assert_eq!(received.data, b"typed");
    assert!(received.options.iter().any(|option| option.kind == OptionKind::Apc));
    assert!(received.options.iter().any(|option| option.kind == OptionKind::Req));
    assert!(
        received
            .reports
            .iter()
            .any(|report| report.kind == OptionKind::Apc && report.status == OptionStatus::Success)
    );
}

#[test]
fn apc_failure_is_reported_without_dropping_payload() {
    let bad_apc = raw(OptionKind::Apc, &0x1234_5678u32.to_be_bytes());
    assert_ne!(Apc::compute(b"payload").crc32c, 0x1234_5678);
    let datagram = build_datagram(addrs(), b"payload", &[bad_apc]).unwrap();

    let ApiDelivery::Received(received) = decode_one(&datagram) else {
        panic!("expected payload delivery despite APC failure");
    };
    assert_eq!(received.data, b"payload");
    assert!(received.options.is_empty());
    assert_eq!(received.reports.len(), 1);
    assert_eq!(received.reports[0].kind, OptionKind::Apc);
    assert_eq!(received.reports[0].status, OptionStatus::Failed);
}

#[test]
fn required_option_policy_filters_missing_or_failed_options() {
    let policy = ReceivePolicy::new().require_option(OptionKind::Apc).unwrap();

    let missing = build_datagram(addrs(), b"payload", &[]).unwrap();
    assert_eq!(
        decode_datagram(&missing, &mut ReassemblyCache::new(), Instant::now(), &policy).unwrap(),
        ApiDelivery::Filtered
    );

    let bad_apc = raw(OptionKind::Apc, &0x1234_5678u32.to_be_bytes());
    let failed = build_datagram(addrs(), b"payload", &[bad_apc]).unwrap();
    assert_eq!(
        decode_datagram(&failed, &mut ReassemblyCache::new(), Instant::now(), &policy).unwrap(),
        ApiDelivery::Filtered
    );
}

#[test]
fn drop_all_option_bearing_filters_even_discarded_options() {
    let mut datagram = build_datagram(addrs(), b"payload", &[raw(OptionKind::Req, &[1, 2, 3, 4])]).unwrap();
    let (ip, udp_at) = IpRepr::parse(&datagram).unwrap();
    let udp = UdpHeader::parse(&datagram[udp_at..]).unwrap();
    let layout = locate_surplus(&ip, &udp).unwrap();
    datagram[layout.ocs_at()..layout.ocs_at() + usize::from(length::OCS)].fill(0);

    let policy = ReceivePolicy::new().drop_all_option_bearing(true);
    assert_eq!(
        decode_datagram(&datagram, &mut ReassemblyCache::new(), Instant::now(), &policy).unwrap(),
        ApiDelivery::Filtered
    );
}

#[test]
fn drop_all_option_bearing_filters_fragments_before_buffering() {
    let config = SendConfig {
        max_datagram_len: 64,
        peer: PeerFragmentLimits {
            max_reassembled_size: 256,
            max_segments: 8,
        },
        identification: 0x0102_0304,
        ..SendConfig::default()
    };
    let datagrams = build_outgoing_datagrams(addrs(), &[0x5a; 80], SendOptions::new(), config).unwrap();
    let mut cache = ReassemblyCache::new();
    let policy = ReceivePolicy::new().drop_all_option_bearing(true);

    assert_eq!(
        decode_datagram(&datagrams[0], &mut cache, Instant::now(), &policy).unwrap(),
        ApiDelivery::Filtered
    );
    assert!(cache.is_empty());
}

#[test]
fn required_policy_rejects_internal_or_unreportable_options() {
    assert!(matches!(
        ReceivePolicy::new().require_option(OptionKind::Frag),
        Err(ReceivePolicyError::UnsupportedRequiredOption { kind: 3 })
    ));
}

#[test]
fn high_level_send_rejects_raw_frag_and_duplicate_apc() {
    let mut with_frag = SendOptions::new();
    with_frag.push_raw(raw(OptionKind::Frag, &[0; 8]));
    assert!(matches!(
        build_outgoing_datagrams(addrs(), b"payload", with_frag, SendConfig::default()),
        Err(SendError::InvalidConfig { .. })
    ));

    let mut with_raw_apc = SendOptions::new().with_apc();
    with_raw_apc.push_raw(raw(OptionKind::Apc, &0u32.to_be_bytes()));
    assert!(matches!(
        build_outgoing_datagrams(addrs(), b"payload", with_raw_apc, SendConfig::default()),
        Err(SendError::InvalidConfig { .. })
    ));
}

#[test]
fn disabled_fragmentation_rejects_oversized_payload() {
    let config = SendConfig {
        max_datagram_len: 64,
        fragmentation: FragmentationMode::Disabled,
        ..SendConfig::default()
    };
    assert!(matches!(
        build_outgoing_datagrams(addrs(), &[0xaa; 80], SendOptions::new(), config),
        Err(SendError::DatagramTooLarge { .. })
    ));
}

#[test]
fn auto_fragmentation_reassembles_within_mrds() {
    let config = SendConfig {
        max_datagram_len: 64,
        peer: PeerFragmentLimits {
            max_reassembled_size: 256,
            max_segments: 8,
        },
        identification: 0x0102_0304,
        ..SendConfig::default()
    };
    let datagrams = build_outgoing_datagrams(addrs(), &[0x5a; 80], SendOptions::new(), config).unwrap();
    assert!(datagrams.len() > 1);

    let mut cache = ReassemblyCache::with_limits(ReassemblyLimits {
        max_reassembled_size: 256,
        max_segments: 8,
        max_pending_partials: 8,
        timeout: udp_transport_options::model::limits::REASSEMBLY_TIMEOUT_MAX,
    });
    let mut last = ApiDelivery::Buffered;
    for datagram in &datagrams {
        last = decode_datagram(datagram, &mut cache, Instant::now(), &ReceivePolicy::default()).unwrap();
    }

    let ApiDelivery::Received(received) = last else {
        panic!("last fragment should complete reassembly");
    };
    assert_eq!(received.data, vec![0x5a; 80]);
}

#[test]
fn over_mrds_send_fails_before_emitting_fragments() {
    let config = SendConfig {
        max_datagram_len: 64,
        peer: PeerFragmentLimits {
            max_reassembled_size: 40,
            max_segments: 8,
        },
        identification: 0x0102_0304,
        ..SendConfig::default()
    };
    assert!(matches!(
        build_outgoing_datagrams(addrs(), &[0x5a; 80], SendOptions::new(), config),
        Err(SendError::Split(SplitError::ReassembledDatagramTooLarge { .. }))
    ));
}
