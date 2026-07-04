// Shared receive-pipeline invariant oracle.
//
// Used by `mod common_pipeline;` from property tests and spliced into the `process_datagram` fuzz
// target via `include!`. Keep this file free of inner attributes so both contexts compile the same
// assertions.

use udp_transport_options::frag::reassembly::ReassemblyCache;
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
    Continue,
}

pub fn check_pipeline_invariants(buf: &[u8]) {
    let mut cache = ReassemblyCache::new();
    let result = process_datagram(buf, &mut cache);

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
    if let Some(expected) = expected_options_disposition(datagram, &ip, &udp, user_data) {
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
        &body[usize::from(length::OCS)..],
        user_data.is_empty(),
        layout.ocs_at() + usize::from(length::OCS) - ip.header_len(),
    ))
}

fn classify_trusted_options(
    options_bytes: &[u8],
    user_data_empty: bool,
    options_offset_from_udp_header: usize,
) -> ExpectedDisposition {
    let options_bytes = match fragment_option_limit(options_bytes, user_data_empty, options_offset_from_udp_header) {
        FragmentOptionLimit::Full => options_bytes,
        FragmentOptionLimit::End(end) => &options_bytes[..end],
        FragmentOptionLimit::MalformedFrag => return ExpectedDisposition::ZeroPayload,
    };
    let mut iter = OptionsIter::new(options_bytes);
    let mut seen = [false; 256];
    let mut valid_frag_seen = false;

    for item in iter.by_ref() {
        let Ok(option) = item else {
            if valid_frag_seen && user_data_empty {
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
                    return if valid_frag_seen && user_data_empty {
                        ExpectedDisposition::Dropped
                    } else {
                        ExpectedDisposition::DeliverWithoutOptions
                    };
                }
                *seen_frag = true;
                if Frag::decode(option.value).is_ok() {
                    valid_frag_seen = true;
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
                if valid_frag_seen {
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

    if valid_frag_seen {
        if user_data_empty {
            ExpectedDisposition::Buffered
        } else {
            ExpectedDisposition::DeliverWithoutOptions
        }
    } else {
        ExpectedDisposition::Continue
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FragmentOptionLimit {
    Full,
    End(usize),
    MalformedFrag,
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
                return FragmentOptionLimit::End(end);
            }
            OptionKind::Other(_) if option.kind.is_unsafe() => return FragmentOptionLimit::Full,
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
