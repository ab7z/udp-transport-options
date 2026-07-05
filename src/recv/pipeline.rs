//! The pure receive pipeline.
//!
//! This module is deliberately free of I/O so it can be unit-tested without `CAP_NET_RAW`. It holds
//! the bulk of the receive-side correctness: the RFC 9868 processing order (verify the UDP checksum,
//! locate and validate the surplus area, validate the OCS, parse the options, then either buffer a
//! Step-12 fragment or deliver the payload).

use crate::error::{HeaderError, ParseError, RecvError};
use crate::frag::reassembly::ReassemblyCache;
use crate::model::{kind, length, limits};
use crate::options::RawOption;
use crate::options::kind::OptionKind;
use crate::options::ocs::{self, OcsCheck};
use crate::options::parse::{OptionRef, OptionsIter};
use crate::options::typed::{Apc, Frag, Mds, Mrds, Req, Res, TypedOption};
use crate::wire::ip::IpRepr;
use crate::wire::surplus::locate_surplus;
use crate::wire::udp::{self, UdpHeader};

use std::sync::atomic::{AtomicU64, Ordering};

const TLV_HEADER_LEN: usize = 2;
const WARN_SAMPLE_INTERVAL: u64 = 64;

macro_rules! warn_sampled {
    ($counter:ident, $($arg:tt)+) => {{
        static $counter: ::std::sync::atomic::AtomicU64 = ::std::sync::atomic::AtomicU64::new(0);
        if let Some(sample) = should_log_sampled(&$counter) {
            if sample == 1 {
                log::warn!($($arg)+);
            } else {
                log::warn!(
                    "{} (sample #{sample}; repeated warnings in this category are sampled)",
                    format_args!($($arg)+)
                );
            }
        }
    }};
}

fn should_log_sampled(counter: &AtomicU64) -> Option<u64> {
    let sample = counter.fetch_add(1, Ordering::Relaxed) + 1;
    (sample == 1 || sample.is_multiple_of(WARN_SAMPLE_INTERVAL)).then_some(sample)
}

/// The outcome of processing one received datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Delivery {
    /// The payload to hand to the application, with any successfully parsed options.
    Payload {
        /// The UDP user data.
        data: Vec<u8>,
        /// Parsed options (empty if the surplus area was absent or its options were discarded).
        options: Vec<RawOption>,
    },
    /// The datagram was a fragment; it was buffered and there is nothing to deliver yet.
    Buffered,
    /// The datagram carried a fragment-local failure and produced no user delivery.
    Dropped,
}

#[derive(Debug)]
struct ParsedOptions {
    options: Vec<RawOption>,
    valid_frag_seen: bool,
    unsupported_unsafe_seen: bool,
    fragment_failed: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum FragmentOptionLimit {
    Full,
    End(usize),
    MalformedFrag,
}

/// Processes one received IPv4 datagram according to the RFC 9868 receive order.
///
/// This function is deliberately pure: malformed IP/UDP input returns a drop error, malformed or
/// untrusted surplus contents discard only the options, and no socket or clock state is touched.
pub fn process_datagram(ip_datagram: &[u8], _cache: &mut ReassemblyCache) -> Result<Delivery, RecvError> {
    let (ip, udp_at) = IpRepr::parse(ip_datagram)?;
    let ip_end = ip.header_len() + ip.transport_payload_len();
    let datagram = &ip_datagram[..ip_end];
    let udp = match UdpHeader::parse(&datagram[udp_at..]) {
        Ok(udp) => udp,
        Err(HeaderError::UdpLengthInvalid { length }) => {
            warn_sampled!(
                UDP_LENGTH_BELOW_MIN_WARNINGS,
                "dropping UDP-options datagram: UDP Length {length} is below the 8-byte minimum"
            );
            return Err(HeaderError::UdpLengthInvalid { length }.into());
        }
        Err(error) => return Err(error.into()),
    };
    let udp_len = usize::from(udp.length);

    if udp_len > ip.transport_payload_len() {
        warn_sampled!(
            UDP_LENGTH_EXCEEDS_IP_WARNINGS,
            "dropping UDP-options datagram: UDP Length {} exceeds IP transport payload {}",
            udp.length,
            ip.transport_payload_len()
        );
        return Err(RecvError::UdpLengthExceedsIpPayload {
            udp_len: udp.length,
            transport_payload_len: ip.transport_payload_len(),
        });
    }

    let user_data_at = udp_at + udp::HEADER_LEN;
    let surplus_start = udp_at + udp_len;
    let user_data = &datagram[user_data_at..surplus_start];
    if udp.checksum != 0 {
        let expected = UdpHeader { checksum: 0, ..udp }.compute_checksum(&ip, user_data);
        if expected != udp.checksum {
            warn_sampled!(
                UDP_CHECKSUM_WARNINGS,
                "dropping UDP-options datagram: UDP checksum mismatch expected={:#06x} actual={:#06x}",
                expected,
                udp.checksum
            );
            return Err(RecvError::UdpChecksumMismatch {
                expected,
                actual: udp.checksum,
            });
        }
    }

    let deliver_without_options = || {
        Ok(Delivery::Payload {
            data: user_data.to_vec(),
            options: Vec::new(),
        })
    };

    let Some(layout) = locate_surplus(&ip, &udp) else {
        return deliver_without_options();
    };

    let pad = datagram[layout.starts_at];
    if let Err(error) = ocs::check_pad(pad, layout.needs_pad) {
        warn_sampled!(PAD_WARNINGS, "discarding UDP options: {error}");
        return deliver_without_options();
    }

    let body = &datagram[layout.ocs_at()..ip_end];
    match ocs::validate(body, layout.len as u16, udp.checksum) {
        OcsCheck::Valid | OcsCheck::Unused => {}
        OcsCheck::IgnoreOptions => {
            warn_sampled!(
                OCS_ZERO_WITH_UDP_CHECKSUM_WARNINGS,
                "discarding UDP options: OCS is zero while UDP checksum is non-zero"
            );
            return deliver_without_options();
        }
        OcsCheck::Error(error) => {
            warn_sampled!(OCS_MISMATCH_WARNINGS, "discarding UDP options: {error}");
            return deliver_without_options();
        }
    }

    let options_offset_from_udp_header = layout.ocs_at() + usize::from(length::OCS) - udp_at;
    let ParsedOptions {
        options,
        valid_frag_seen,
        unsupported_unsafe_seen,
        fragment_failed,
    } = match parse_options(
        &body[usize::from(length::OCS)..],
        user_data,
        options_offset_from_udp_header,
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            warn_sampled!(TLV_PARSE_WARNINGS, "discarding UDP options: {error}");
            return deliver_without_options();
        }
    };

    if valid_frag_seen && !user_data.is_empty() {
        return deliver_without_options();
    }
    if fragment_failed || (valid_frag_seen && user_data.is_empty() && unsupported_unsafe_seen) {
        return Ok(Delivery::Dropped);
    }
    if unsupported_unsafe_seen {
        return Ok(Delivery::Payload {
            data: Vec::new(),
            options: Vec::new(),
        });
    }
    if valid_frag_seen && user_data.is_empty() {
        return Ok(Delivery::Buffered);
    }

    Ok(Delivery::Payload {
        data: user_data.to_vec(),
        options,
    })
}

fn parse_options(
    options_bytes: &[u8],
    user_data: &[u8],
    options_offset_from_udp_header: usize,
) -> Result<ParsedOptions, crate::error::ParseError> {
    let options_bytes = match fragment_option_limit(options_bytes, user_data.is_empty(), options_offset_from_udp_header)
    {
        FragmentOptionLimit::Full => options_bytes,
        FragmentOptionLimit::End(end) => &options_bytes[..end],
        FragmentOptionLimit::MalformedFrag => {
            return Ok(ParsedOptions {
                options: Vec::new(),
                valid_frag_seen: false,
                unsupported_unsafe_seen: true,
                fragment_failed: false,
            });
        }
    };
    let mut iter = OptionsIter::new(options_bytes);
    let mut options = Vec::new();
    let mut seen = [false; 256];
    let mut seen_non_must_support_safe = false;
    let mut valid_frag_seen = false;
    let mut unsupported_unsafe_seen = false;

    for item in iter.by_ref() {
        let option = match item {
            Ok(option) => option,
            Err(error) => {
                return if unsupported_unsafe_seen {
                    Ok(ParsedOptions {
                        options: Vec::new(),
                        valid_frag_seen,
                        unsupported_unsafe_seen,
                        fragment_failed: false,
                    })
                } else if valid_frag_seen && user_data.is_empty() {
                    Ok(ParsedOptions {
                        options: Vec::new(),
                        valid_frag_seen,
                        unsupported_unsafe_seen: false,
                        fragment_failed: true,
                    })
                } else {
                    Err(error)
                };
            }
        };
        let raw_kind = option.kind.to_byte();

        if option.kind.is_safe() && !option.kind.is_must_support() {
            seen_non_must_support_safe = true;
        } else if seen_non_must_support_safe
            && option.kind.is_must_support()
            && !matches!(option.kind, OptionKind::Eol | OptionKind::Nop)
        {
            warn_sampled!(
                MUST_SUPPORT_ORDER_WARNINGS,
                "received must-support UDP option after another SAFE option"
            );
        }

        match option.kind {
            OptionKind::Eol | OptionKind::Nop => {}
            OptionKind::Frag => {
                reject_sub_minimum(option)?;
                if seen[usize::from(raw_kind)] {
                    if valid_frag_seen && user_data.is_empty() {
                        return Ok(ParsedOptions {
                            options: Vec::new(),
                            valid_frag_seen,
                            unsupported_unsafe_seen: false,
                            fragment_failed: true,
                        });
                    }
                    return Err(ParseError::DuplicateFrag);
                }
                seen[usize::from(raw_kind)] = true;
                if Frag::decode(option.value).is_ok() {
                    valid_frag_seen = true;
                } else {
                    unsupported_unsafe_seen = true;
                    break;
                }
            }
            OptionKind::Apc => {
                reject_sub_minimum(option)?;
                if mark_seen_once(&mut seen, raw_kind) && accepts_apc(option, user_data) {
                    options.push(option.into());
                }
            }
            OptionKind::Mds => {
                reject_sub_minimum(option)?;
                if mark_seen_once(&mut seen, raw_kind) && Mds::decode(option.value).is_ok() {
                    options.push(option.into());
                }
            }
            OptionKind::Mrds => {
                reject_sub_minimum(option)?;
                if mark_seen_once(&mut seen, raw_kind) && Mrds::decode(option.value).is_ok() {
                    options.push(option.into());
                }
            }
            OptionKind::Req => {
                reject_sub_minimum(option)?;
                if mark_seen_once(&mut seen, raw_kind) && Req::decode(option.value).is_ok() {
                    options.push(option.into());
                }
            }
            OptionKind::Res => {
                reject_sub_minimum(option)?;
                if mark_seen_once(&mut seen, raw_kind) && Res::decode(option.value).is_ok() {
                    options.push(option.into());
                }
            }
            OptionKind::Other(_) if option.kind.is_safe() => {
                reject_sub_minimum(option)?;
            }
            OptionKind::Other(_) => {
                unsupported_unsafe_seen = true;
                break;
            }
        }
    }

    if iter.max_nop_run() > limits::NOP_RUN_DOS_THRESHOLD {
        warn_sampled!(
            NOP_FLOOD_WARNINGS,
            "received {} consecutive UDP NOP options; threshold is {}",
            iter.max_nop_run(),
            limits::NOP_RUN_DOS_THRESHOLD
        );
    }

    Ok(ParsedOptions {
        options,
        valid_frag_seen,
        unsupported_unsafe_seen,
        fragment_failed: false,
    })
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

fn reject_sub_minimum(option: OptionRef<'_>) -> Result<(), ParseError> {
    let Some(min_len) = minimum_known_tlv_len(option.kind) else {
        return Ok(());
    };
    let total_len = option.value.len() + TLV_HEADER_LEN;
    if total_len < min_len {
        Err(ParseError::InvalidLength {
            kind: option.kind.to_byte(),
            len: total_len,
        })
    } else {
        Ok(())
    }
}

fn minimum_known_tlv_len(option_kind: OptionKind) -> Option<usize> {
    match option_kind.to_byte() {
        kind::TIME => Some(usize::from(length::TIME)),
        kind::EXP => Some(usize::from(length::EXP_MIN)),
        _ => option_kind.fixed_tlv_lengths().iter().copied().map(usize::from).min(),
    }
}

fn mark_seen_once(seen: &mut [bool; 256], raw_kind: u8) -> bool {
    let slot = &mut seen[usize::from(raw_kind)];
    if *slot {
        false
    } else {
        *slot = true;
        true
    }
}

fn accepts_apc(option: OptionRef<'_>, user_data: &[u8]) -> bool {
    match Apc::decode(option.value) {
        Ok(apc) if apc == Apc::compute(user_data) => true,
        Ok(_) => {
            warn_sampled!(APC_MISMATCH_WARNINGS, "received APC option with a checksum mismatch");
            false
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Once;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    use log::{LevelFilter, Log, Metadata, Record};

    use super::{Delivery, WARN_SAMPLE_INTERVAL, process_datagram, should_log_sampled};
    use crate::error::{HeaderError, RecvError};
    use crate::frag::reassembly::ReassemblyCache;
    use crate::model::{kind, length, limits};
    use crate::options::RawOption;
    use crate::options::kind::OptionKind;
    use crate::options::typed::{Apc, Frag, Mds, Req, TypedOption};
    use crate::socket::send::assemble_datagram;
    use crate::wire::ip::IpRepr;
    use crate::wire::surplus::locate_surplus;
    use crate::wire::udp::{self, UdpHeader};

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
    const SRC_PORT: u16 = 12345;
    const DST_PORT: u16 = 54321;

    static INIT_LOGGER: Once = Once::new();
    static NOP_FLOOD_LOGS: AtomicUsize = AtomicUsize::new(0);
    static UDP_LENGTH_LOGS: AtomicUsize = AtomicUsize::new(0);
    static MUST_SUPPORT_ORDER_LOGS: AtomicUsize = AtomicUsize::new(0);

    struct TestLogger;

    impl Log for TestLogger {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &Record<'_>) {
            let message = record.args().to_string();
            if message.contains("consecutive UDP NOP options") {
                NOP_FLOOD_LOGS.fetch_add(1, Ordering::SeqCst);
            }
            if message.contains("below the 8-byte minimum") {
                UDP_LENGTH_LOGS.fetch_add(1, Ordering::SeqCst);
            }
            if message.contains("must-support UDP option after another SAFE option") {
                MUST_SUPPORT_ORDER_LOGS.fetch_add(1, Ordering::SeqCst);
            }
        }

        fn flush(&self) {}
    }

    static LOGGER: TestLogger = TestLogger;

    fn init_logger() {
        INIT_LOGGER.call_once(|| {
            log::set_logger(&LOGGER).expect("test logger installs once");
            log::set_max_level(LevelFilter::Warn);
        });
    }

    fn option_body(option_bytes: &[u8]) -> Vec<u8> {
        let mut body = vec![0, 0];
        body.extend_from_slice(option_bytes);
        body
    }

    fn encode<T: TypedOption>(option: T) -> Vec<u8> {
        let mut out = Vec::new();
        option.encode(&mut out);
        out
    }

    fn datagram(user_data: &[u8], option_bytes: &[u8]) -> Vec<u8> {
        assemble_datagram(SRC, DST, SRC_PORT, DST_PORT, user_data, &option_body(option_bytes))
    }

    fn datagram_with_raw_surplus(user_data: &[u8], raw_surplus: &[u8], checksum_zero: bool) -> Vec<u8> {
        let udp_len = udp::HEADER_LEN + user_data.len();
        let total_len = 20 + udp_len + raw_surplus.len();
        let ip = IpRepr {
            src: SRC,
            dst: DST,
            ihl: 5,
            total_len: total_len.try_into().expect("test datagram fits IPv4 length"),
        };
        let mut datagram = vec![0; total_len];
        ip.write(&mut datagram[..20]);

        let mut udp_header = UdpHeader {
            src_port: SRC_PORT,
            dst_port: DST_PORT,
            length: udp_len.try_into().expect("test UDP length fits"),
            checksum: 0,
        };
        if !checksum_zero {
            udp_header.checksum = udp_header.compute_checksum(&ip, user_data);
        }
        udp_header.write(&mut datagram[20..20 + udp::HEADER_LEN]);
        datagram[20 + udp::HEADER_LEN..20 + udp_len].copy_from_slice(user_data);
        datagram[20 + udp_len..].copy_from_slice(raw_surplus);
        datagram
    }

    fn process(datagram: &[u8]) -> Result<Delivery, RecvError> {
        process_datagram(datagram, &mut ReassemblyCache::new())
    }

    fn payload(data: &[u8], options: Vec<RawOption>) -> Delivery {
        Delivery::Payload {
            data: data.to_vec(),
            options,
        }
    }

    fn raw(kind: OptionKind, value: &[u8]) -> RawOption {
        RawOption {
            kind,
            value: value.to_vec(),
        }
    }

    fn frag_start_for(user_data: &[u8], fragment_options_len: usize) -> u16 {
        let udp_len = udp::HEADER_LEN + user_data.len();
        let natural_start = 20 + udp_len;
        let needs_pad = natural_start % 2 == 1;
        (udp_len + usize::from(needs_pad) + usize::from(length::OCS) + fragment_options_len)
            .try_into()
            .expect("test fragment option area fits u16")
    }

    #[test]
    fn warn_sampler_logs_first_then_every_interval() {
        let counter = AtomicU64::new(0);
        assert_eq!(should_log_sampled(&counter), Some(1));
        for _ in 2..WARN_SAMPLE_INTERVAL {
            assert_eq!(should_log_sampled(&counter), None);
        }
        assert_eq!(should_log_sampled(&counter), Some(WARN_SAMPLE_INTERVAL));
    }

    #[test]
    fn delivers_valid_payload_and_supported_options() {
        let user_data = b"hello";
        let mut options = Vec::new();
        options.extend(encode(Apc::compute(user_data)));
        options.extend(encode(Mds {
            max_datagram_size: 1500,
        }));
        options.extend(encode(Req { token: [1, 2, 3, 4] }));
        options.push(kind::EOL);

        assert_eq!(
            process(&datagram(user_data, &options)).unwrap(),
            payload(
                user_data,
                vec![
                    raw(OptionKind::Apc, &Apc::compute(user_data).crc32c.to_be_bytes()),
                    raw(OptionKind::Mds, &1500u16.to_be_bytes()),
                    raw(OptionKind::Req, &[1, 2, 3, 4]),
                ],
            )
        );
    }

    #[test]
    fn drops_invalid_udp_lengths() {
        init_logger();
        UDP_LENGTH_LOGS.store(0, Ordering::SeqCst);

        let mut too_short = datagram_with_raw_surplus(b"hi", &[], false);
        too_short[24..26].copy_from_slice(&7u16.to_be_bytes());
        for _ in 0..WARN_SAMPLE_INTERVAL {
            assert!(matches!(
                process(&too_short),
                Err(RecvError::Header(HeaderError::UdpLengthInvalid { length: 7 }))
            ));
        }
        assert!(UDP_LENGTH_LOGS.load(Ordering::SeqCst) >= 1);

        let mut too_long = datagram_with_raw_surplus(b"hi", &[], false);
        too_long[24..26].copy_from_slice(&11u16.to_be_bytes());
        assert!(matches!(
            process(&too_long),
            Err(RecvError::UdpLengthExceedsIpPayload {
                udp_len: 11,
                transport_payload_len: 10
            })
        ));
    }

    #[test]
    fn drops_bad_udp_checksum() {
        let mut bytes = datagram(b"hello", &[]);
        bytes[26] ^= 0x01;
        assert!(matches!(process(&bytes), Err(RecvError::UdpChecksumMismatch { .. })));
    }

    #[test]
    fn delivers_without_options_when_surplus_is_absent_or_unusable() {
        assert_eq!(
            process(&datagram_with_raw_surplus(b"hello", &[], false)).unwrap(),
            payload(b"hello", Vec::new())
        );
        assert_eq!(
            process(&datagram_with_raw_surplus(b"hi", &[0], false)).unwrap(),
            payload(b"hi", Vec::new())
        );
    }

    #[test]
    fn odd_surplus_pad_must_be_zero() {
        let user_data = b"abc";
        let options = encode(Req { token: [9, 8, 7, 6] });
        let good = datagram(user_data, &options);
        assert_eq!(
            process(&good).unwrap(),
            payload(user_data, vec![raw(OptionKind::Req, &[9, 8, 7, 6])])
        );

        let mut bad = good;
        let (ip, udp_at) = IpRepr::parse(&bad).unwrap();
        let udp = UdpHeader::parse(&bad[udp_at..]).unwrap();
        let layout = locate_surplus(&ip, &udp).unwrap();
        assert!(layout.needs_pad);
        bad[layout.starts_at] = 0x7f;
        assert_eq!(process(&bad).unwrap(), payload(user_data, Vec::new()));
    }

    #[test]
    fn applies_udp_checksum_and_ocs_matrix() {
        let user_data = b"matrix";
        let req = encode(Req {
            token: [0xaa, 0xbb, 0xcc, 0xdd],
        });
        let valid = datagram(user_data, &req);
        assert_eq!(
            process(&valid).unwrap(),
            payload(user_data, vec![raw(OptionKind::Req, &[0xaa, 0xbb, 0xcc, 0xdd])])
        );

        let mut zero_udp_zero_ocs = valid.clone();
        zero_udp_zero_ocs[26..28].fill(0);
        let (ip, udp_at) = IpRepr::parse(&zero_udp_zero_ocs).unwrap();
        let udp = UdpHeader::parse(&zero_udp_zero_ocs[udp_at..]).unwrap();
        let layout = locate_surplus(&ip, &udp).unwrap();
        zero_udp_zero_ocs[layout.ocs_at()..layout.ocs_at() + usize::from(length::OCS)].fill(0);
        assert_eq!(
            process(&zero_udp_zero_ocs).unwrap(),
            payload(user_data, vec![raw(OptionKind::Req, &[0xaa, 0xbb, 0xcc, 0xdd])])
        );

        let mut nonzero_udp_zero_ocs = valid.clone();
        let (ip, udp_at) = IpRepr::parse(&nonzero_udp_zero_ocs).unwrap();
        let udp = UdpHeader::parse(&nonzero_udp_zero_ocs[udp_at..]).unwrap();
        let layout = locate_surplus(&ip, &udp).unwrap();
        nonzero_udp_zero_ocs[layout.ocs_at()..layout.ocs_at() + usize::from(length::OCS)].fill(0);
        assert_eq!(process(&nonzero_udp_zero_ocs).unwrap(), payload(user_data, Vec::new()));

        let mut bad_ocs = valid;
        let last = bad_ocs.len() - 1;
        bad_ocs[last] ^= 0x01;
        assert_eq!(process(&bad_ocs).unwrap(), payload(user_data, Vec::new()));
    }

    #[test]
    fn malformed_tlv_discards_all_options_but_not_payload() {
        let bytes = datagram(b"hello", &[kind::APC, 1, kind::REQ, 6, 1, 2, 3, 4]);
        assert_eq!(process(&bytes).unwrap(), payload(b"hello", Vec::new()));
    }

    #[test]
    fn known_safe_over_minimum_length_is_ignored_locally() {
        let bytes = datagram(b"hello", &[kind::MDS, 5, 0, 1, 2, kind::REQ, 6, 4, 3, 2, 1]);
        assert_eq!(
            process(&bytes).unwrap(),
            payload(b"hello", vec![raw(OptionKind::Req, &[4, 3, 2, 1])])
        );
    }

    #[test]
    fn known_safe_sub_minimum_length_discards_all_options() {
        let bytes = datagram(b"hello", &[kind::MDS, 3, 0, kind::REQ, 6, 4, 3, 2, 1]);
        assert_eq!(process(&bytes).unwrap(), payload(b"hello", Vec::new()));
    }

    #[test]
    fn duplicate_known_safe_sub_minimum_length_discards_all_options() {
        let bytes = datagram(b"hello", &[kind::REQ, 6, 1, 2, 3, 4, kind::REQ, 3, 9]);
        assert_eq!(process(&bytes).unwrap(), payload(b"hello", Vec::new()));
    }

    #[test]
    fn assigned_safe_sub_minimum_length_discards_all_options() {
        let time = datagram(
            b"hello",
            &[kind::REQ, 6, 1, 2, 3, 4, kind::TIME, 9, 0, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(process(&time).unwrap(), payload(b"hello", Vec::new()));

        let exp = datagram(b"hello", &[kind::REQ, 6, 1, 2, 3, 4, kind::EXP, 3, 0]);
        assert_eq!(process(&exp).unwrap(), payload(b"hello", Vec::new()));
    }

    #[test]
    fn unknown_safe_is_ignored_but_unknown_unsafe_drops_data() {
        let safe = datagram(b"hello", &[10, 2, kind::REQ, 6, 1, 1, 2, 2]);
        assert_eq!(
            process(&safe).unwrap(),
            payload(b"hello", vec![raw(OptionKind::Req, &[1, 1, 2, 2])])
        );

        let unsafe_option = datagram(b"hello", &[kind::UNSAFE_MIN, 2]);
        assert_eq!(process(&unsafe_option).unwrap(), payload(b"", Vec::new()));
    }

    #[test]
    fn unknown_unsafe_precedence_survives_later_malformed_tlv() {
        let bytes = datagram(b"hello", &[kind::UNSAFE_MIN, 2, kind::APC, 6]);
        assert_eq!(process(&bytes).unwrap(), payload(b"", Vec::new()));
    }

    #[test]
    fn duplicate_non_frag_option_keeps_first_instance() {
        let bytes = datagram(b"hello", &[kind::REQ, 6, 1, 2, 3, 4, kind::REQ, 6, 9, 8, 7, 6]);
        assert_eq!(
            process(&bytes).unwrap(),
            payload(b"hello", vec![raw(OptionKind::Req, &[1, 2, 3, 4])])
        );
    }

    #[test]
    fn frag_with_non_empty_payload_ignores_all_options() {
        let user_data = b"hello";
        let frag = Frag {
            frag_start: frag_start_for(user_data, usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: 0,
            rdos: None,
        };
        assert_eq!(
            process(&datagram(user_data, &encode(frag))).unwrap(),
            payload(user_data, Vec::new())
        );
    }

    #[test]
    fn valid_empty_payload_frag_buffers_until_step_12() {
        let frag = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: 0,
            rdos: Some(32),
        };
        assert_eq!(process(&datagram(b"", &encode(frag))).unwrap(), Delivery::Buffered);
    }

    #[test]
    fn valid_empty_payload_frag_with_unknown_unsafe_drops_fragment() {
        let frag = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL) + 2),
            identification: 0x0102_0304,
            frag_offset: 0,
            rdos: Some(32),
        };
        let mut options = encode(frag);
        options.extend_from_slice(&[kind::UNSAFE_MIN, 2]);
        assert_eq!(process(&datagram(b"", &options)).unwrap(), Delivery::Dropped);
    }

    #[test]
    fn empty_payload_frag_does_not_parse_fragment_data_as_options() {
        let frag = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: 0,
            rdos: Some(32),
        };
        let mut options = encode(frag);
        options.extend(encode(frag));

        assert_eq!(process(&datagram(b"", &options)).unwrap(), Delivery::Buffered);
    }

    #[test]
    fn empty_payload_frag_malformed_per_fragment_option_drops_fragment() {
        let frag = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL) + 4),
            identification: 0x0102_0304,
            frag_offset: 0,
            rdos: Some(32),
        };
        let mut options = encode(frag);
        options.extend_from_slice(&[kind::MDS, 5, 0, 1]);

        assert_eq!(process(&datagram(b"", &options)).unwrap(), Delivery::Dropped);
    }

    #[test]
    fn malformed_frag_is_unsupported_unsafe() {
        let bytes = datagram(b"", &[kind::FRAG, 11, 0, 20, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(process(&bytes).unwrap(), payload(b"", Vec::new()));

        let non_empty = datagram(b"hello", &[kind::FRAG, 11, 0, 20, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(process(&non_empty).unwrap(), payload(b"", Vec::new()));
    }

    #[test]
    fn sub_minimum_frag_discards_options_but_delivers_payload() {
        let options = [kind::FRAG, 9, 0, 20, 0, 0, 0, 1, 0, kind::REQ, 6, 1, 2, 3, 4];
        assert_eq!(
            process(&datagram(b"hello", &options)).unwrap(),
            payload(b"hello", Vec::new())
        );
    }

    #[test]
    fn duplicate_frag_discards_options_without_buffering() {
        let frag = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL) * 2),
            identification: 0x0102_0304,
            frag_offset: 0,
            rdos: Some(32),
        };
        let mut options = encode(frag);
        options.extend(encode(frag));

        assert_eq!(process(&datagram(b"", &options)).unwrap(), Delivery::Dropped);
    }

    #[test]
    fn nop_flood_logs_and_continues() {
        init_logger();
        NOP_FLOOD_LOGS.store(0, Ordering::SeqCst);
        let mut options = vec![kind::NOP; limits::NOP_RUN_DOS_THRESHOLD + 1];
        options.extend(encode(Req { token: [1, 3, 5, 7] }));

        assert_eq!(
            process(&datagram(b"hello", &options)).unwrap(),
            payload(b"hello", vec![raw(OptionKind::Req, &[1, 3, 5, 7])])
        );
        for _ in 0..WARN_SAMPLE_INTERVAL {
            let _ = process(&datagram(b"hello", &options));
        }
        assert!(NOP_FLOOD_LOGS.load(Ordering::SeqCst) >= 1);
    }

    #[test]
    fn must_support_order_violation_logs_and_continues() {
        init_logger();
        MUST_SUPPORT_ORDER_LOGS.store(0, Ordering::SeqCst);

        let bytes = datagram(b"hello", &[10, 2, kind::REQ, 6, 1, 3, 5, 7]);
        assert_eq!(
            process(&bytes).unwrap(),
            payload(b"hello", vec![raw(OptionKind::Req, &[1, 3, 5, 7])])
        );
        for _ in 0..WARN_SAMPLE_INTERVAL {
            let _ = process(&bytes);
        }
        assert!(MUST_SUPPORT_ORDER_LOGS.load(Ordering::SeqCst) >= 1);
    }
}
