// Shared receive-pipeline invariant oracle.
//
// Used by `mod common_pipeline;` from property tests and spliced into the `process_datagram` fuzz
// target via `include!`. Keep this file free of inner attributes so both contexts compile the same
// assertions.

use std::time::Instant;
use udp_transport_options::frag::reassembly::{FragKey, ReassemblyCache, ReassemblyOutcome};
use udp_transport_options::model::{kind, length};
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::ocs::{self, OcsCheck};
use udp_transport_options::options::parse::{OptionRef, OptionsIter};
use udp_transport_options::options::typed::{Apc, Frag, Mds, Mrds, Req, Res, TypedOption};
use udp_transport_options::recv::pipeline::{Delivery, process_datagram};
use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::surplus::locate_surplus;
use udp_transport_options::wire::udp::{self, UdpHeader};

const TLV_HEADER_LEN: usize = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedDisposition {
    DeliverWithoutOptions,
    ZeroPayload,
    Buffered,
    Dropped,
    ReassembledComplete,
    Continue,
}

pub fn check_pipeline_invariants(buf: &[u8]) {
    let mut cache = ReassemblyCache::new();
    let now = Instant::now();
    let result = process_datagram(buf, &mut cache, now);

    let Ok((ip, udp_at)) = IpRepr::parse(buf) else {
        assert!(result.is_err());
        return;
    };
    let ip_end = ip.header_len() + ip.transport_payload_len();
    let datagram = &buf[..ip_end];
    let Ok(udp) = UdpHeader::parse(&datagram[udp_at..]) else {
        assert!(result.is_err());
        return;
    };
    if usize::from(udp.length) > ip.transport_payload_len() {
        assert!(result.is_err());
        return;
    }

    let user_data = &datagram[udp_at + udp::HEADER_LEN..udp_at + usize::from(udp.length)];
    if udp.checksum != 0 {
        let expected = UdpHeader { checksum: 0, ..udp }.compute_checksum(&ip, user_data);
        if expected != udp.checksum {
            assert!(result.is_err());
            return;
        }
    }

    let delivery = result.expect("valid header and checksum should not be dropped");
    if let Some(expected) = expected_options_disposition(datagram, &ip, &udp, user_data, now) {
        match expected {
            ExpectedDisposition::DeliverWithoutOptions => {
                assert_eq!(
                    delivery,
                    Delivery::Payload {
                        data: user_data.to_vec(),
                        options: Vec::new()
                    }
                );
                return;
            }
            ExpectedDisposition::ZeroPayload => {
                assert_eq!(
                    delivery,
                    Delivery::Payload {
                        data: Vec::new(),
                        options: Vec::new()
                    }
                );
                return;
            }
            ExpectedDisposition::Buffered => {
                assert_eq!(delivery, Delivery::Buffered);
                return;
            }
            ExpectedDisposition::Dropped => {
                assert_eq!(delivery, Delivery::Dropped);
                return;
            }
            ExpectedDisposition::ReassembledComplete => {
                assert_ne!(delivery, Delivery::Buffered);
                return;
            }
            ExpectedDisposition::Continue => {}
        }
    }

    match delivery {
        Delivery::Payload { data, options } => {
            assert_eq!(data, user_data);
            for option in options {
                assert!(matches!(
                    option.kind,
                    OptionKind::Apc | OptionKind::Mds | OptionKind::Mrds | OptionKind::Req | OptionKind::Res
                ));
                match option.kind {
                    OptionKind::Apc => assert_eq!(Apc::decode(&option.value), Ok(Apc::compute(user_data))),
                    OptionKind::Mds => assert!(Mds::decode(&option.value).is_ok()),
                    OptionKind::Mrds => assert!(Mrds::decode(&option.value).is_ok()),
                    OptionKind::Req => assert!(Req::decode(&option.value).is_ok()),
                    OptionKind::Res => assert!(Res::decode(&option.value).is_ok()),
                    _ => unreachable!("option kind was constrained above"),
                }
            }
        }
        Delivery::Buffered => {}
        Delivery::Dropped => panic!("unexpected fragment drop without an expected drop disposition"),
    }
}

fn expected_options_disposition(
    datagram: &[u8],
    ip: &IpRepr,
    udp: &UdpHeader,
    user_data: &[u8],
    now: Instant,
) -> Option<ExpectedDisposition> {
    let layout = locate_surplus(ip, udp)?;
    if ocs::check_pad(datagram[layout.starts_at], layout.needs_pad).is_err() {
        return Some(ExpectedDisposition::DeliverWithoutOptions);
    }

    let ip_end = ip.header_len() + ip.transport_payload_len();
    let body = &datagram[layout.ocs_at()..ip_end];
    match ocs::validate(body, layout.len as u16, udp.checksum) {
        OcsCheck::Valid | OcsCheck::Unused => {}
        OcsCheck::IgnoreOptions | OcsCheck::Error(_) => return Some(ExpectedDisposition::DeliverWithoutOptions),
    }

    Some(classify_trusted_options(
        ip,
        udp,
        &body[usize::from(length::OCS)..],
        user_data.is_empty(),
        layout.ocs_at() + usize::from(length::OCS) - ip.header_len(),
        now,
    ))
}

fn classify_trusted_options(
    ip: &IpRepr,
    udp: &UdpHeader,
    options_bytes: &[u8],
    user_data_empty: bool,
    options_offset_from_udp_header: usize,
    now: Instant,
) -> ExpectedDisposition {
    let full_options_bytes = options_bytes;
    let (options_bytes, fragment_data) =
        match fragment_option_limit(options_bytes, user_data_empty, options_offset_from_udp_header) {
            FragmentOptionLimit::Full => (options_bytes, &[][..]),
            FragmentOptionLimit::End(end) => (&options_bytes[..end], &full_options_bytes[end..]),
            FragmentOptionLimit::MalformedFrag => return ExpectedDisposition::Dropped,
            FragmentOptionLimit::UnsupportedUnsafeBeforeFrag => return ExpectedDisposition::Dropped,
        };
    let mut iter = OptionsIter::new(options_bytes);
    let mut seen = [false; 256];
    let mut valid_frag_seen = None;

    for item in iter.by_ref() {
        let Ok(option) = item else {
            if valid_frag_seen.is_some() && user_data_empty {
                return ExpectedDisposition::Dropped;
            }
            return ExpectedDisposition::DeliverWithoutOptions;
        };
        let raw_kind = option.kind.to_byte();

        match option.kind {
            OptionKind::Eol | OptionKind::Nop => {}
            OptionKind::Frag => {
                if is_sub_minimum_known_option(option) {
                    return ExpectedDisposition::DeliverWithoutOptions;
                }
                let seen_frag = &mut seen[usize::from(raw_kind)];
                if *seen_frag {
                    return if valid_frag_seen.is_some() && user_data_empty {
                        ExpectedDisposition::Dropped
                    } else {
                        ExpectedDisposition::DeliverWithoutOptions
                    };
                }
                *seen_frag = true;
                if let Ok(frag) = Frag::decode(option.value) {
                    valid_frag_seen = Some(frag);
                } else {
                    return ExpectedDisposition::ZeroPayload;
                }
            }
            OptionKind::Apc | OptionKind::Mds | OptionKind::Mrds | OptionKind::Req | OptionKind::Res => {
                if is_sub_minimum_known_option(option) {
                    return ExpectedDisposition::DeliverWithoutOptions;
                }
                let slot = &mut seen[usize::from(raw_kind)];
                if !*slot {
                    *slot = true;
                }
            }
            OptionKind::Other(_) if option.kind.is_safe() => {
                if is_sub_minimum_known_option(option) {
                    return ExpectedDisposition::DeliverWithoutOptions;
                }
            }
            OptionKind::Other(_) => {
                if valid_frag_seen.is_some() {
                    return if user_data_empty {
                        ExpectedDisposition::Dropped
                    } else {
                        ExpectedDisposition::DeliverWithoutOptions
                    };
                }
                return ExpectedDisposition::ZeroPayload;
            }
        }
    }

    if let Some(frag) = valid_frag_seen {
        if user_data_empty {
            classify_reassembly_fragment(ip, udp, frag, fragment_data, now)
        } else {
            ExpectedDisposition::DeliverWithoutOptions
        }
    } else {
        ExpectedDisposition::Continue
    }
}

fn classify_reassembly_fragment(
    ip: &IpRepr,
    udp: &UdpHeader,
    frag: Frag,
    fragment_data: &[u8],
    now: Instant,
) -> ExpectedDisposition {
    let mut cache = ReassemblyCache::new();
    let key = FragKey {
        src: ip.src,
        dst: ip.dst,
        src_port: udp.src_port,
        dst_port: udp.dst_port,
        identification: frag.identification,
    };
    match cache.insert(key, frag, fragment_data, now) {
        ReassemblyOutcome::Incomplete => ExpectedDisposition::Buffered,
        ReassemblyOutcome::Abort(_) => ExpectedDisposition::Dropped,
        ReassemblyOutcome::Complete { .. } => ExpectedDisposition::ReassembledComplete,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FragmentOptionLimit {
    Full,
    End(usize),
    MalformedFrag,
    UnsupportedUnsafeBeforeFrag,
}

fn fragment_option_limit(
    options_bytes: &[u8],
    user_data_empty: bool,
    options_offset_from_udp_header: usize,
) -> FragmentOptionLimit {
    if !user_data_empty {
        return FragmentOptionLimit::Full;
    }

    let mut iter = OptionsIter::new(options_bytes);
    let mut unsupported_unsafe_before_frag = false;
    for item in iter.by_ref() {
        let Ok(option) = item else {
            return FragmentOptionLimit::Full;
        };

        match option.kind {
            OptionKind::Frag => {
                let Ok(frag) = Frag::decode(option.value) else {
                    return FragmentOptionLimit::Full;
                };
                let Some(end) = usize::from(frag.frag_start).checked_sub(options_offset_from_udp_header) else {
                    return FragmentOptionLimit::MalformedFrag;
                };
                if end > options_bytes.len() || end < option_end_offset(options_bytes, option) {
                    return FragmentOptionLimit::MalformedFrag;
                }
                if unsupported_unsafe_before_frag {
                    return FragmentOptionLimit::UnsupportedUnsafeBeforeFrag;
                }
                return FragmentOptionLimit::End(end);
            }
            OptionKind::Other(_) if option.kind.is_unsafe() => {
                unsupported_unsafe_before_frag = true;
            }
            OptionKind::Eol => return FragmentOptionLimit::Full,
            _ => {}
        }
    }

    FragmentOptionLimit::Full
}

fn option_end_offset(options_bytes: &[u8], option: OptionRef<'_>) -> usize {
    let base = options_bytes.as_ptr() as usize;
    let value_start = option.value.as_ptr() as usize - base;
    value_start + option.value.len()
}

fn is_sub_minimum_known_option(option: OptionRef<'_>) -> bool {
    let Some(min_len) = minimum_known_tlv_len(option.kind) else {
        return false;
    };
    option.value.len() + TLV_HEADER_LEN < min_len
}

fn minimum_known_tlv_len(option_kind: OptionKind) -> Option<usize> {
    match option_kind.to_byte() {
        kind::TIME => Some(usize::from(length::TIME)),
        kind::EXP => Some(usize::from(length::EXP_MIN)),
        _ => option_kind.fixed_tlv_lengths().iter().copied().map(usize::from).min(),
    }
}
