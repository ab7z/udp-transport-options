use std::net::Ipv4Addr;
use std::time::Instant;

use udp_transport_options::api::{
    ApiDelivery, DatagramAddrs, FragmentationMode, OptionSource, OptionStatus, ReceivePolicy, SendConfig, SendOptions,
    build_datagram, build_outgoing_datagrams, decode_datagram,
};
use udp_transport_options::error::{ReceivePolicyError, RecvError, SendError, SplitError};
use udp_transport_options::frag::reassembly::{ReassemblyCache, ReassemblyLimits};
use udp_transport_options::frag::split::PeerFragmentLimits;
use udp_transport_options::model::{kind, length};
use udp_transport_options::options::RawOption;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::typed::{Apc, Frag, Mds, Req, TypedOption};
use udp_transport_options::socket::send::assemble_datagram;
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

fn encode<T: TypedOption>(option: T) -> Vec<u8> {
    let mut out = Vec::new();
    option.encode(&mut out);
    out
}

fn option_body(option_bytes: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(option_bytes);
    body
}

fn fragment_datagram(frag: Frag, fragment_options: &[u8], data: &[u8]) -> Vec<u8> {
    let mut options = encode(frag);
    options.extend_from_slice(fragment_options);
    options.extend_from_slice(data);
    assemble_datagram(SRC, DST, SRC_PORT, DST_PORT, b"", &option_body(&options))
}

fn datagram_with_raw_surplus(user_data: &[u8], raw_surplus: &[u8]) -> Vec<u8> {
    let udp_len = usize::from(length::UDP_HEADER) + user_data.len();
    let total_len = 20 + udp_len + raw_surplus.len();
    let ip = IpRepr {
        src: SRC,
        dst: DST,
        ihl: 5,
        total_len: total_len.try_into().expect("test datagram fits IPv4 length"),
    };
    let mut datagram = vec![0; total_len];
    ip.write(&mut datagram[..20]);

    let mut udp = UdpHeader {
        src_port: SRC_PORT,
        dst_port: DST_PORT,
        length: udp_len.try_into().expect("test UDP length fits"),
        checksum: 0,
    };
    udp.checksum = udp.compute_checksum(&ip, user_data);
    udp.write(&mut datagram[20..20 + usize::from(length::UDP_HEADER)]);
    datagram[20 + usize::from(length::UDP_HEADER)..20 + udp_len].copy_from_slice(user_data);
    datagram[20 + udp_len..].copy_from_slice(raw_surplus);
    datagram
}

fn frag_start(fragment_option_area_len: usize) -> u16 {
    (usize::from(length::UDP_HEADER) + usize::from(length::OCS) + fragment_option_area_len)
        .try_into()
        .expect("test fragment option area fits u16")
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
fn empty_options_emit_plain_datagram() {
    let datagram = build_outgoing_datagrams(addrs(), b"plain", SendOptions::new(), SendConfig::default()).unwrap();
    assert_eq!(datagram.len(), 1);
    let (ip, udp_at) = IpRepr::parse(&datagram[0]).unwrap();
    let udp = UdpHeader::parse(&datagram[0][udp_at..]).unwrap();
    assert_eq!(usize::from(ip.total_len), 20 + usize::from(udp.length));
    assert!(locate_surplus(&ip, &udp).is_none());

    let ApiDelivery::Received(received) = decode_one(&datagram[0]) else {
        panic!("plain datagram should be delivered");
    };
    assert_eq!(received.data, b"plain");
    assert!(received.options.is_empty());
    assert!(received.reports.is_empty());

    let min_config = SendConfig {
        max_datagram_len: 20 + usize::from(length::UDP_HEADER),
        ..SendConfig::default()
    };
    let min_datagram = build_outgoing_datagrams(addrs(), b"", SendOptions::new(), min_config).unwrap();
    assert_eq!(min_datagram[0].len(), 20 + usize::from(length::UDP_HEADER));
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
fn low_level_rejects_frag_wire_kind_alias_with_user_data() {
    let frag = raw(OptionKind::Other(kind::FRAG), &[0; 8]);
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

    let good_apc = raw(OptionKind::Apc, &Apc::compute(b"payload").crc32c.to_be_bytes());
    let good = build_datagram(addrs(), b"payload", &[good_apc]).unwrap();
    let ApiDelivery::Received(received) =
        decode_datagram(&good, &mut ReassemblyCache::new(), Instant::now(), &policy).unwrap()
    else {
        panic!("successful datagram-level APC should satisfy required option policy");
    };
    assert_eq!(received.data, b"payload");
}

#[test]
fn required_policy_filters_fragment_option_if_any_fragment_failed() {
    let good_mds = encode(Mds {
        max_datagram_size: 1500,
    });
    let bad_mds = [kind::MDS, length::MDS + 1, 0, 0, 0];
    let first = Frag {
        frag_start: frag_start(usize::from(length::FRAG_NON_TERMINAL) + good_mds.len()),
        identification: 0x0102_0304,
        frag_offset: u16::from(length::UDP_HEADER),
        rdos: None,
    };
    let second = Frag {
        frag_start: frag_start(usize::from(length::FRAG_TERMINAL) + bad_mds.len()),
        identification: 0x0102_0304,
        frag_offset: u16::from(length::UDP_HEADER) + 3,
        rdos: Some(u16::from(length::UDP_HEADER) + 6),
    };
    let policy = ReceivePolicy::new().require_option(OptionKind::Mds).unwrap();
    let first_datagram = fragment_datagram(first, &good_mds, b"abc");
    let second_datagram = fragment_datagram(second, &bad_mds, b"def");
    let mut default_cache = ReassemblyCache::new();
    let mut cache = ReassemblyCache::new();
    let now = Instant::now();

    assert_eq!(
        decode_datagram(&first_datagram, &mut default_cache, now, &ReceivePolicy::default()).unwrap(),
        ApiDelivery::Buffered
    );
    let ApiDelivery::Received(received) =
        decode_datagram(&second_datagram, &mut default_cache, now, &ReceivePolicy::default()).unwrap()
    else {
        panic!("failed fragment option should not drop reassembled payload by default");
    };
    assert_eq!(received.data, b"abcdef");
    assert!(!received.options.iter().any(|option| option.kind == OptionKind::Mds));
    assert!(received.reports.iter().any(|report| {
        report.kind == OptionKind::Mds
            && report.status == OptionStatus::Failed
            && report.source == OptionSource::FragmentSet
    }));

    assert_eq!(
        decode_datagram(&first_datagram, &mut cache, now, &policy).unwrap(),
        ApiDelivery::Buffered
    );
    assert_eq!(
        decode_datagram(&second_datagram, &mut cache, now, &policy).unwrap(),
        ApiDelivery::Filtered
    );

    let first = Frag {
        frag_start: frag_start(usize::from(length::FRAG_NON_TERMINAL) + bad_mds.len()),
        identification: 0x0506_0708,
        frag_offset: u16::from(length::UDP_HEADER),
        rdos: None,
    };
    let second = Frag {
        frag_start: frag_start(usize::from(length::FRAG_TERMINAL)),
        identification: 0x0506_0708,
        frag_offset: u16::from(length::UDP_HEADER) + 3,
        rdos: Some(u16::from(length::UDP_HEADER) + 6),
    };
    let mut terminal_data = b"def".to_vec();
    terminal_data.extend_from_slice(&option_body(&good_mds));
    let first_datagram = fragment_datagram(first, &bad_mds, b"abc");
    let second_datagram = fragment_datagram(second, &[], &terminal_data);
    let mut default_cache = ReassemblyCache::new();
    let mut cache = ReassemblyCache::new();

    assert_eq!(
        decode_datagram(&first_datagram, &mut default_cache, now, &ReceivePolicy::default()).unwrap(),
        ApiDelivery::Buffered
    );
    let ApiDelivery::Received(received) =
        decode_datagram(&second_datagram, &mut default_cache, now, &ReceivePolicy::default()).unwrap()
    else {
        panic!("fragment failure plus datagram success should still deliver by default");
    };
    assert!(received.reports.iter().any(|report| {
        report.kind == OptionKind::Mds
            && report.status == OptionStatus::Failed
            && report.source == OptionSource::FragmentSet
    }));
    assert!(received.reports.iter().any(|report| {
        report.kind == OptionKind::Mds
            && report.status == OptionStatus::Success
            && report.source == OptionSource::Datagram
    }));

    assert_eq!(
        decode_datagram(&first_datagram, &mut cache, now, &policy).unwrap(),
        ApiDelivery::Buffered
    );
    assert_eq!(
        decode_datagram(&second_datagram, &mut cache, now, &policy).unwrap(),
        ApiDelivery::Filtered
    );
}

#[test]
fn fragment_local_apc_is_ignored() {
    let bad_apc = encode(Apc { crc32c: 0x1234_5678 });
    let first = Frag {
        frag_start: frag_start(usize::from(length::FRAG_NON_TERMINAL) + bad_apc.len()),
        identification: 0x0102_0304,
        frag_offset: u16::from(length::UDP_HEADER),
        rdos: None,
    };
    let second = Frag {
        frag_start: frag_start(usize::from(length::FRAG_TERMINAL)),
        identification: 0x0102_0304,
        frag_offset: u16::from(length::UDP_HEADER) + 3,
        rdos: Some(u16::from(length::UDP_HEADER) + 6),
    };
    let first_datagram = fragment_datagram(first, &bad_apc, b"abc");
    let second_datagram = fragment_datagram(second, &[], b"def");
    let mut cache = ReassemblyCache::new();
    let now = Instant::now();

    assert_eq!(
        decode_datagram(&first_datagram, &mut cache, now, &ReceivePolicy::default()).unwrap(),
        ApiDelivery::Buffered
    );
    let ApiDelivery::Received(received) =
        decode_datagram(&second_datagram, &mut cache, now, &ReceivePolicy::default()).unwrap()
    else {
        panic!("fragment-local APC must not drop the reassembled payload");
    };
    assert_eq!(received.data, b"abcdef");
    assert!(!received.options.iter().any(|option| option.kind == OptionKind::Apc));
    assert!(
        !received
            .reports
            .iter()
            .any(|report| report.kind == OptionKind::Apc && report.source == OptionSource::FragmentSet)
    );
}

#[test]
fn required_policy_accepts_fragment_set_success() {
    let mds = encode(Mds {
        max_datagram_size: 1500,
    });
    let first = Frag {
        frag_start: frag_start(usize::from(length::FRAG_NON_TERMINAL) + mds.len()),
        identification: 0x0102_0304,
        frag_offset: u16::from(length::UDP_HEADER),
        rdos: None,
    };
    let second = Frag {
        frag_start: frag_start(usize::from(length::FRAG_TERMINAL) + mds.len()),
        identification: 0x0102_0304,
        frag_offset: u16::from(length::UDP_HEADER) + 3,
        rdos: Some(u16::from(length::UDP_HEADER) + 6),
    };
    let first_datagram = fragment_datagram(first, &mds, b"abc");
    let second_datagram = fragment_datagram(second, &mds, b"def");
    let mut default_cache = ReassemblyCache::new();
    let mut cache = ReassemblyCache::new();
    let policy = ReceivePolicy::new().require_option(OptionKind::Mds).unwrap();
    let now = Instant::now();

    assert_eq!(
        decode_datagram(&first_datagram, &mut default_cache, now, &ReceivePolicy::default()).unwrap(),
        ApiDelivery::Buffered
    );
    let ApiDelivery::Received(received) =
        decode_datagram(&second_datagram, &mut default_cache, now, &ReceivePolicy::default()).unwrap()
    else {
        panic!("fragment-set success should deliver with default policy");
    };
    assert!(received.reports.iter().any(|report| {
        report.kind == OptionKind::Mds
            && report.status == OptionStatus::Success
            && report.source == OptionSource::FragmentSet
    }));

    assert_eq!(
        decode_datagram(&first_datagram, &mut cache, now, &policy).unwrap(),
        ApiDelivery::Buffered
    );
    let ApiDelivery::Received(received) = decode_datagram(&second_datagram, &mut cache, now, &policy).unwrap() else {
        panic!("fragment-set success should satisfy required option policy");
    };
    assert_eq!(received.data, b"abcdef");
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
fn drop_all_option_bearing_preserves_udp_checksum_errors() {
    let mut datagram = build_datagram(addrs(), b"payload", &[raw(OptionKind::Req, &[1, 2, 3, 4])]).unwrap();
    datagram[20 + 6] ^= 0xff;
    let policy = ReceivePolicy::new().drop_all_option_bearing(true);

    assert!(matches!(
        decode_datagram(&datagram, &mut ReassemblyCache::new(), Instant::now(), &policy),
        Err(RecvError::UdpChecksumMismatch { .. })
    ));
}

#[test]
fn drop_all_option_bearing_delivers_unusable_surplus() {
    let datagram = datagram_with_raw_surplus(b"hi", &[0]);
    let (ip, udp_at) = IpRepr::parse(&datagram).unwrap();
    let udp = UdpHeader::parse(&datagram[udp_at..]).unwrap();
    assert!(locate_surplus(&ip, &udp).is_none());

    let policy = ReceivePolicy::new().drop_all_option_bearing(true);
    let ApiDelivery::Received(received) =
        decode_datagram(&datagram, &mut ReassemblyCache::new(), Instant::now(), &policy).unwrap()
    else {
        panic!("unusable surplus is not an option-bearing datagram");
    };
    assert_eq!(received.data, b"hi");
    assert!(received.options.is_empty());
    assert!(received.reports.is_empty());
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
    let policy = ReceivePolicy::new()
        .require_option(OptionKind::Other(kind::APC))
        .unwrap();
    assert_eq!(policy.required_options(), &[OptionKind::Apc]);

    assert!(matches!(
        ReceivePolicy::new().require_option(OptionKind::Frag),
        Err(ReceivePolicyError::UnsupportedRequiredOption { kind: 3 })
    ));
}

#[test]
fn high_level_send_rejects_raw_frag_and_duplicate_reportable_options() {
    let mut with_frag = SendOptions::new();
    with_frag.push_raw(raw(OptionKind::Frag, &[0; 8]));
    assert!(matches!(
        build_outgoing_datagrams(addrs(), b"payload", with_frag, SendConfig::default()),
        Err(SendError::InvalidConfig { .. })
    ));

    let mut with_frag_alias = SendOptions::new();
    with_frag_alias.push_raw(raw(OptionKind::Other(kind::FRAG), &[0; 8]));
    assert!(matches!(
        build_outgoing_datagrams(addrs(), b"payload", with_frag_alias, SendConfig::default()),
        Err(SendError::InvalidConfig { .. })
    ));

    let mut with_raw_apc = SendOptions::new().with_apc();
    with_raw_apc.push_raw(raw(OptionKind::Apc, &0u32.to_be_bytes()));
    assert!(matches!(
        build_outgoing_datagrams(addrs(), b"payload", with_raw_apc, SendConfig::default()),
        Err(SendError::InvalidConfig { .. })
    ));

    let mut with_raw_apc_alias = SendOptions::new().with_apc();
    with_raw_apc_alias.push_raw(raw(OptionKind::Other(kind::APC), &0u32.to_be_bytes()));
    assert!(matches!(
        build_outgoing_datagrams(addrs(), b"payload", with_raw_apc_alias, SendConfig::default()),
        Err(SendError::InvalidConfig { .. })
    ));

    let duplicate_cases = [
        (OptionKind::Apc, OptionKind::Other(kind::APC), vec![0, 0, 0, 0]),
        (OptionKind::Mds, OptionKind::Other(kind::MDS), vec![0, 64]),
        (OptionKind::Mrds, OptionKind::Other(kind::MRDS), vec![0, 64, 2]),
        (OptionKind::Req, OptionKind::Other(kind::REQ), vec![1, 2, 3, 4]),
        (OptionKind::Res, OptionKind::Other(kind::RES), vec![5, 6, 7, 8]),
    ];
    for (first, second, value) in duplicate_cases {
        let mut duplicate = SendOptions::new();
        duplicate.push_raw(raw(first, &value));
        duplicate.push_raw(raw(second, &value));
        assert!(matches!(
            build_outgoing_datagrams(addrs(), b"payload", duplicate, SendConfig::default()),
            Err(SendError::InvalidConfig { .. })
        ));
    }
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
fn auto_fragmentation_without_options_uses_full_default_mrds() {
    let payload = vec![0x5a; 2918];
    let datagrams = build_outgoing_datagrams(addrs(), &payload, SendOptions::new(), SendConfig::default()).unwrap();
    assert_eq!(datagrams.len(), 2);

    let mut cache = ReassemblyCache::new();
    let mut last = ApiDelivery::Buffered;
    for datagram in &datagrams {
        last = decode_datagram(datagram, &mut cache, Instant::now(), &ReceivePolicy::default()).unwrap();
    }
    let ApiDelivery::Received(received) = last else {
        panic!("default MRDS payload should reassemble");
    };
    assert_eq!(received.data, payload);
    assert!(received.options.is_empty());
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
