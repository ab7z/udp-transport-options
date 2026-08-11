//! The pure receive pipeline.
//!
//! This module is deliberately free of I/O so it can be unit-tested without `CAP_NET_RAW`. It holds
//! the bulk of the receive-side correctness: the RFC 9868 processing order (verify the UDP checksum,
//! locate and validate the surplus area, validate the OCS, parse the options, then either buffer a
//! Step-12 fragment or deliver the payload).

use crate::error::{HeaderError, ParseError, RecvError};
use crate::frag::reassembly::{FragKey, FragmentProcessing, ReassemblyCache, ReassemblyOutcome};
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
use std::time::Instant;

const TLV_HEADER_LEN: usize = 2;
const WARN_SAMPLE_INTERVAL: u64 = 64;
static UDP_LENGTH_BELOW_MIN_WARNINGS: AtomicU64 = AtomicU64::new(0);
static UDP_LENGTH_EXCEEDS_IP_WARNINGS: AtomicU64 = AtomicU64::new(0);

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

/// Emits the RFC 9868 Section 10 diagnostic for a UDP Length below the fixed header size.
///
/// Raw-socket demultiplexing and API prefilters call this helper before the pure pipeline can see
/// the datagram, so all receive entry points share the same rate-limited diagnostic.
pub(crate) fn warn_udp_length_below_min(length: u16) {
    if let Some(sample) = should_log_sampled(&UDP_LENGTH_BELOW_MIN_WARNINGS) {
        if sample == 1 {
            log::warn!("dropping UDP-options datagram: UDP Length {length} is below the 8-byte minimum");
        } else {
            log::warn!(
                "dropping UDP-options datagram: UDP Length {length} is below the 8-byte minimum \
                 (sample #{sample}; repeated warnings in this category are sampled)"
            );
        }
    }
}

/// Emits the RFC 9868 Section 10 diagnostic for a UDP Length beyond the IP transport payload.
///
/// The API's option-bearing prefilter performs this check before the pure pipeline, so both paths
/// use the same rate-limited diagnostic.
pub(crate) fn warn_udp_length_exceeds_ip(length: u16, transport_payload_len: usize) {
    if let Some(sample) = should_log_sampled(&UDP_LENGTH_EXCEEDS_IP_WARNINGS) {
        if sample == 1 {
            log::warn!(
                "dropping UDP-options datagram: UDP Length {length} exceeds IP transport payload {transport_payload_len}"
            );
        } else {
            log::warn!(
                "dropping UDP-options datagram: UDP Length {length} exceeds IP transport payload \
                 {transport_payload_len} (sample #{sample}; repeated warnings in this category are sampled)"
            );
        }
    }
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
        /// Whether the datagram carried a usable UDP-options surplus area, even if those options
        /// were later discarded by pad, OCS, or TLV validation.
        option_bearing: bool,
        /// Per-option processing status for API consumers.
        reports: Vec<OptionReport>,
        /// Separate OCS processing confirmations required by RFC 9868 Section 15.
        ocs_reports: Vec<OcsReport>,
    },
    /// The datagram was a fragment; it was buffered and there is nothing to deliver yet.
    Buffered,
    /// The datagram carried a fragment-local failure and produced no user delivery.
    Dropped,
}

/// User-visible processing status for a UDP option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionStatus {
    /// The option was recognized and processed successfully.
    Success,
    /// The option was recognized but failed validation or processing.
    Failed,
    /// The option was intentionally ignored.
    Ignored,
}

/// Where a reported option or OCS was observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionSource {
    /// The option applies to the reassembled or unfragmented UDP datagram.
    Datagram,
    /// The option was accumulated from one or more UDP fragments.
    FragmentSet,
}

/// User-visible processing status for the Option Checksum (OCS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcsStatus {
    /// No surplus area, and therefore no OCS, was present.
    Absent,
    /// A non-zero OCS validated successfully.
    ///
    /// For a coalesced fragment-set report, at least one fragment used a validated non-zero OCS;
    /// any other accepted fragments may have used the RFC-permitted zero OCS.
    Valid,
    /// A zero OCS was permitted because the UDP checksum was also zero.
    ///
    /// For a coalesced fragment-set report, every accepted fragment used this unused form.
    Unused,
    /// A non-zero OCS or its alignment pad failed validation.
    Failed,
    /// A zero OCS was invalid because the UDP checksum was non-zero.
    InvalidZero,
    /// The fragment-set OCS state was not observed by the receive pipeline.
    ///
    /// Reported only with [`OptionSource::FragmentSet`] when at least one fragment entered the
    /// shared [`ReassemblyCache`] through its public
    /// insertion methods, which carry no OCS observation. It never satisfies a required-OCS
    /// receive policy.
    Unobserved,
}

/// One OCS processing confirmation visible at the API boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OcsReport {
    /// OCS processing disposition.
    pub status: OcsStatus,
    /// Whether the confirmation applies to the datagram or its fragment set.
    pub source: OptionSource,
}

/// Processing status for one option visible at the API boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionReport {
    /// The option Kind.
    pub kind: OptionKind,
    /// The processing disposition.
    pub status: OptionStatus,
    /// The source level at which the option was observed.
    pub source: OptionSource,
}

#[derive(Debug)]
struct ParsedOptions {
    options: Vec<RawOption>,
    reports: Vec<OptionReport>,
    frag: Option<Frag>,
    unsupported_unsafe_seen: bool,
    fragment_failed: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum FragmentOptionLimit {
    Full,
    End { end: usize },
    MalformedFrag { frag: Frag },
}

/// Processes one received IPv4 datagram according to the RFC 9868 receive order.
///
/// This function is deliberately pure: malformed IP/UDP input returns a drop error, malformed or
/// untrusted surplus contents discard only the options, and time-dependent reassembly state is driven
/// by the caller-provided `now`.
///
/// `cache` must be scoped to this UDP source/destination address-and-port pair. A caller serving
/// multiple socket pairs must keep separate caches so that the per-pair RFC limits remain separate.
pub fn process_datagram(ip_datagram: &[u8], cache: &mut ReassemblyCache, now: Instant) -> Result<Delivery, RecvError> {
    process_datagram_inner(ip_datagram, cache, now, true)
}

fn process_datagram_inner(
    ip_datagram: &[u8],
    cache: &mut ReassemblyCache,
    now: Instant,
    reassembly_allowed: bool,
) -> Result<Delivery, RecvError> {
    let (ip, udp_at) = IpRepr::parse(ip_datagram)?;
    let ip_end = ip.header_len() + ip.transport_payload_len();
    let datagram = &ip_datagram[..ip_end];
    let udp = match UdpHeader::parse(&datagram[udp_at..]) {
        Ok(udp) => udp,
        Err(HeaderError::UdpLengthInvalid { length }) => {
            warn_udp_length_below_min(length);
            return Err(HeaderError::UdpLengthInvalid { length }.into());
        }
        Err(error) => return Err(error.into()),
    };
    let udp_len = usize::from(udp.length);

    if udp_len > ip.transport_payload_len() {
        warn_udp_length_exceeds_ip(udp.length, ip.transport_payload_len());
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

    let deliver_without_options = |option_bearing, ocs_status| {
        Ok(Delivery::Payload {
            data: user_data.to_vec(),
            options: Vec::new(),
            option_bearing,
            reports: Vec::new(),
            ocs_reports: vec![OcsReport {
                status: ocs_status,
                source: OptionSource::Datagram,
            }],
        })
    };

    let Some(layout) = locate_surplus(&ip, &udp) else {
        return deliver_without_options(false, OcsStatus::Absent);
    };

    let pad = datagram[layout.starts_at];
    if let Err(error) = ocs::check_pad(pad, layout.needs_pad) {
        warn_sampled!(PAD_WARNINGS, "discarding UDP options: {error}");
        return deliver_without_options(true, OcsStatus::Failed);
    }

    let body = &datagram[layout.ocs_at()..ip_end];
    let ocs_status = match ocs::validate(body, layout.len as u16, udp.checksum) {
        OcsCheck::Valid => OcsStatus::Valid,
        OcsCheck::Unused => OcsStatus::Unused,
        OcsCheck::IgnoreOptions => {
            warn_sampled!(
                OCS_ZERO_WITH_UDP_CHECKSUM_WARNINGS,
                "discarding UDP options: OCS is zero while UDP checksum is non-zero"
            );
            return deliver_without_options(true, OcsStatus::InvalidZero);
        }
        OcsCheck::Error(error) => {
            warn_sampled!(OCS_MISMATCH_WARNINGS, "discarding UDP options: {error}");
            return deliver_without_options(true, OcsStatus::Failed);
        }
    };

    let options_offset_from_udp_header = layout.ocs_at() + usize::from(length::OCS) - udp_at;
    let ParsedOptions {
        options,
        reports,
        frag,
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
            return deliver_without_options(true, ocs_status);
        }
    };
    let valid_frag_seen = frag.is_some();

    if valid_frag_seen && !user_data.is_empty() {
        return deliver_without_options(true, ocs_status);
    }
    let fragment_key = frag
        .filter(|_| user_data.is_empty())
        .map(|frag| frag_key(&ip, &udp, frag));
    if fragment_failed || (fragment_key.is_some() && unsupported_unsafe_seen) {
        if let Some(key) = fragment_key {
            cache.discard(key);
        }
        return Ok(Delivery::Dropped);
    }
    if unsupported_unsafe_seen {
        return Ok(Delivery::Payload {
            data: Vec::new(),
            options: Vec::new(),
            option_bearing: true,
            reports,
            ocs_reports: vec![OcsReport {
                status: ocs_status,
                source: OptionSource::Datagram,
            }],
        });
    }
    if let Some(frag) = frag.filter(|_| user_data.is_empty()) {
        if !reassembly_allowed {
            return Ok(Delivery::Dropped);
        }
        let key = fragment_key.expect("fragment key exists for empty-payload FRAG");
        let fragment_data_at = udp_at + usize::from(frag.frag_start);
        let Some(fragment_data) = datagram.get(fragment_data_at..ip_end) else {
            cache.discard(key);
            return Ok(Delivery::Dropped);
        };
        let fragment_option_failures = fragment_option_failures(&reports);
        return match cache.insert_with_options_and_failures(
            key,
            frag,
            fragment_data,
            FragmentProcessing {
                options: &options,
                option_failures: &fragment_option_failures,
                ocs_nonzero: Some(ocs_status == OcsStatus::Valid),
            },
            now,
        ) {
            ReassemblyOutcome::Incomplete => Ok(Delivery::Buffered),
            ReassemblyOutcome::Abort(_) => Ok(Delivery::Dropped),
            ReassemblyOutcome::Complete {
                tail,
                udp_length,
                fragment_options,
                fragment_option_failures,
                fragment_ocs_nonzero,
            } => {
                let Some(reassembled) = reassembled_datagram(&ip, &udp, udp_length, &tail) else {
                    return Ok(Delivery::Dropped);
                };
                match process_datagram_inner(&reassembled, cache, now, false)? {
                    Delivery::Payload {
                        data,
                        options,
                        option_bearing,
                        reports,
                        mut ocs_reports,
                    } => Ok(Delivery::Payload {
                        data,
                        options: merge_fragment_options(fragment_options.clone(), &fragment_option_failures, options),
                        option_bearing,
                        reports: merge_fragment_reports(fragment_options, fragment_option_failures, reports),
                        ocs_reports: {
                            ocs_reports.insert(
                                0,
                                OcsReport {
                                    status: match fragment_ocs_nonzero {
                                        Some(true) => OcsStatus::Valid,
                                        Some(false) => OcsStatus::Unused,
                                        None => OcsStatus::Unobserved,
                                    },
                                    source: OptionSource::FragmentSet,
                                },
                            );
                            ocs_reports
                        },
                    }),
                    delivery => Ok(delivery),
                }
            }
        };
    }

    Ok(Delivery::Payload {
        data: user_data.to_vec(),
        options,
        option_bearing: true,
        reports,
        ocs_reports: vec![OcsReport {
            status: ocs_status,
            source: OptionSource::Datagram,
        }],
    })
}

fn frag_key(ip: &IpRepr, udp: &UdpHeader, frag: Frag) -> FragKey {
    FragKey {
        src: ip.src,
        dst: ip.dst,
        src_port: udp.src_port,
        dst_port: udp.dst_port,
        identification: frag.identification,
    }
}

fn merge_fragment_options(
    mut fragment_options: Vec<RawOption>,
    fragment_option_failures: &[OptionKind],
    datagram_options: Vec<RawOption>,
) -> Vec<RawOption> {
    fragment_options.retain(|option| !fragment_option_failures.contains(&option.kind));
    fragment_options.extend(datagram_options);
    fragment_options
}

fn merge_fragment_reports(
    fragment_options: Vec<RawOption>,
    fragment_option_failures: Vec<OptionKind>,
    datagram_reports: Vec<OptionReport>,
) -> Vec<OptionReport> {
    let mut reports: Vec<_> = fragment_option_failures
        .into_iter()
        .map(|kind| OptionReport {
            kind,
            status: OptionStatus::Failed,
            source: OptionSource::FragmentSet,
        })
        .collect();
    for option in fragment_options {
        if reports.iter().any(|report| report.kind == option.kind) {
            continue;
        }
        reports.push(OptionReport {
            kind: option.kind,
            status: OptionStatus::Success,
            source: OptionSource::FragmentSet,
        });
    }
    reports.extend(datagram_reports);
    reports
}

fn fragment_option_failures(reports: &[OptionReport]) -> Vec<OptionKind> {
    let mut failures = Vec::new();
    for report in reports {
        if report.status == OptionStatus::Failed && !failures.contains(&report.kind) {
            failures.push(report.kind);
        }
    }
    failures
}

fn reassembled_datagram(ip: &IpRepr, udp: &UdpHeader, udp_length: u16, tail: &[u8]) -> Option<Vec<u8>> {
    let udp_len = usize::from(udp_length);
    let user_len = udp_len.checked_sub(udp::HEADER_LEN)?;
    if tail.len() < user_len {
        return None;
    }

    let total_len = 20usize.checked_add(udp::HEADER_LEN)?.checked_add(tail.len())?;
    let total_len = u16::try_from(total_len).ok()?;
    let reassembled_ip = IpRepr {
        src: ip.src,
        dst: ip.dst,
        ihl: 5,
        total_len,
    };
    let reassembled_udp = UdpHeader {
        src_port: udp.src_port,
        dst_port: udp.dst_port,
        length: udp_length,
        checksum: 0,
    };

    let mut datagram = vec![0u8; usize::from(total_len)];
    reassembled_ip.write(&mut datagram[..20]);
    reassembled_udp.write(&mut datagram[20..20 + udp::HEADER_LEN]);
    datagram[20 + udp::HEADER_LEN..].copy_from_slice(tail);
    Some(datagram)
}

fn parse_options(
    options_bytes: &[u8],
    user_data: &[u8],
    options_offset_from_udp_header: usize,
) -> Result<ParsedOptions, crate::error::ParseError> {
    let option_limit = fragment_option_limit(options_bytes, user_data.is_empty(), options_offset_from_udp_header);
    let fragment_option_context = matches!(option_limit, FragmentOptionLimit::End { .. });
    let options_bytes = match option_limit {
        FragmentOptionLimit::Full => options_bytes,
        FragmentOptionLimit::End { end } => &options_bytes[..end],
        FragmentOptionLimit::MalformedFrag { frag } => {
            return Ok(ParsedOptions {
                options: Vec::new(),
                reports: Vec::new(),
                frag: Some(frag),
                unsupported_unsafe_seen: true,
                fragment_failed: true,
            });
        }
    };
    let mut iter = OptionsIter::new(options_bytes);
    let mut options = Vec::new();
    let mut reports = Vec::new();
    let mut seen = [false; 256];
    let mut seen_non_must_support_safe = false;
    let mut frag = None;
    let mut unsupported_unsafe_seen = false;

    for item in iter.by_ref() {
        let option = match item {
            Ok(option) => option,
            Err(error) => {
                return if unsupported_unsafe_seen {
                    Ok(ParsedOptions {
                        options: Vec::new(),
                        reports: Vec::new(),
                        frag,
                        unsupported_unsafe_seen,
                        fragment_failed: false,
                    })
                } else if frag.is_some() && user_data.is_empty() {
                    Ok(ParsedOptions {
                        options: Vec::new(),
                        reports: Vec::new(),
                        frag,
                        unsupported_unsafe_seen: false,
                        fragment_failed: true,
                    })
                } else {
                    Err(error)
                };
            }
        };
        let raw_kind = option.kind.to_byte();

        if !(fragment_option_context && option.kind == OptionKind::Apc)
            && let Err(error) = reject_sub_minimum(option)
        {
            if frag.is_some() && user_data.is_empty() {
                return Ok(ParsedOptions {
                    options: Vec::new(),
                    reports: Vec::new(),
                    frag,
                    unsupported_unsafe_seen: false,
                    fragment_failed: true,
                });
            }
            return Err(error);
        }

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
                if seen[usize::from(raw_kind)] {
                    if frag.is_some() && user_data.is_empty() {
                        return Ok(ParsedOptions {
                            options: Vec::new(),
                            reports: Vec::new(),
                            frag,
                            unsupported_unsafe_seen: false,
                            fragment_failed: true,
                        });
                    }
                    return Err(ParseError::DuplicateFrag);
                }
                seen[usize::from(raw_kind)] = true;
                if let Ok(parsed_frag) = Frag::decode(option.value) {
                    frag = Some(parsed_frag);
                } else {
                    unsupported_unsafe_seen = true;
                    break;
                }
            }
            OptionKind::Apc => {
                if fragment_option_context {
                    reports.push(report(option.kind, OptionStatus::Ignored));
                    continue;
                }
                if mark_seen_once(&mut seen, raw_kind) {
                    match accepts_apc(option, user_data) {
                        OptionStatus::Success => {
                            reports.push(report(option.kind, OptionStatus::Success));
                            options.push(option.into());
                        }
                        status => reports.push(report(option.kind, status)),
                    }
                } else {
                    reports.push(report(option.kind, OptionStatus::Ignored));
                }
            }
            OptionKind::Mds => {
                if mark_seen_once(&mut seen, raw_kind) {
                    if Mds::decode(option.value).is_ok() {
                        reports.push(report(option.kind, OptionStatus::Success));
                        options.push(option.into());
                    } else {
                        reports.push(report(option.kind, OptionStatus::Failed));
                    }
                } else {
                    reports.push(report(option.kind, OptionStatus::Ignored));
                }
            }
            OptionKind::Mrds => {
                if mark_seen_once(&mut seen, raw_kind) {
                    if Mrds::decode(option.value).is_ok() {
                        reports.push(report(option.kind, OptionStatus::Success));
                        options.push(option.into());
                    } else {
                        reports.push(report(option.kind, OptionStatus::Failed));
                    }
                } else {
                    reports.push(report(option.kind, OptionStatus::Ignored));
                }
            }
            OptionKind::Req => {
                if mark_seen_once(&mut seen, raw_kind) {
                    if Req::decode(option.value).is_ok() {
                        reports.push(report(option.kind, OptionStatus::Success));
                        options.push(option.into());
                    } else {
                        reports.push(report(option.kind, OptionStatus::Failed));
                    }
                } else {
                    reports.push(report(option.kind, OptionStatus::Ignored));
                }
            }
            OptionKind::Res => {
                if mark_seen_once(&mut seen, raw_kind) {
                    if Res::decode(option.value).is_ok() {
                        reports.push(report(option.kind, OptionStatus::Success));
                        options.push(option.into());
                    } else {
                        reports.push(report(option.kind, OptionStatus::Failed));
                    }
                } else {
                    reports.push(report(option.kind, OptionStatus::Ignored));
                }
            }
            OptionKind::Other(_) if option.kind.is_safe() => {
                reports.push(report(option.kind, OptionStatus::Ignored));
            }
            OptionKind::Other(_) => {
                unsupported_unsafe_seen = true;
                reports.push(report(option.kind, OptionStatus::Failed));
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
        reports,
        frag,
        unsupported_unsafe_seen,
        fragment_failed: false,
    })
}

fn report(kind: OptionKind, status: OptionStatus) -> OptionReport {
    OptionReport {
        kind,
        status,
        source: OptionSource::Datagram,
    }
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
                    return FragmentOptionLimit::MalformedFrag { frag };
                };
                if end > options_bytes.len() || end < option_end_offset(options_bytes, option) {
                    return FragmentOptionLimit::MalformedFrag { frag };
                }
                return FragmentOptionLimit::End { end };
            }
            OptionKind::Other(_) if option.kind.is_unsafe() => {
                return FragmentOptionLimit::Full;
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

fn accepts_apc(option: OptionRef<'_>, user_data: &[u8]) -> OptionStatus {
    match Apc::decode(option.value) {
        Ok(apc) if apc == Apc::compute(user_data) => OptionStatus::Success,
        Ok(_) => {
            warn_sampled!(APC_MISMATCH_WARNINGS, "received APC option with a checksum mismatch");
            OptionStatus::Failed
        }
        Err(_) => OptionStatus::Failed,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Once;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::time::Instant;

    use log::{LevelFilter, Log, Metadata, Record};

    use super::{
        Delivery, OcsReport, OcsStatus, OptionReport, OptionSource, OptionStatus, WARN_SAMPLE_INTERVAL,
        process_datagram, should_log_sampled,
    };
    use crate::error::{HeaderError, RecvError};
    use crate::frag::reassembly::{FragKey, ReassemblyCache, ReassemblyOutcome};
    use crate::frag::split::{PeerFragmentLimits, SplitConfig, split_datagram};
    use crate::model::{kind, length, limits};
    use crate::options::RawOption;
    use crate::options::kind::OptionKind;
    use crate::options::serialize::OptionsBuilder;
    use crate::options::typed::{Apc, Frag, Mds, Mrds, Req, Res, TypedOption};
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
            if message.contains("below the 8-byte minimum") || message.contains("exceeds IP transport payload") {
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

    fn fragment_datagram(frag: Frag, fragment_options: &[u8], data: &[u8]) -> Vec<u8> {
        let mut options = encode(frag);
        options.extend_from_slice(fragment_options);
        options.extend_from_slice(data);
        datagram(b"", &options)
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
        process_datagram(datagram, &mut ReassemblyCache::new(), Instant::now())
    }

    fn process_with_cache(datagram: &[u8], cache: &mut ReassemblyCache, now: Instant) -> Result<Delivery, RecvError> {
        process_datagram(datagram, cache, now)
    }

    fn payload(data: &[u8], options: Vec<RawOption>) -> Delivery {
        payload_with_bearing(data, options, true)
    }

    fn payload_with_bearing(data: &[u8], options: Vec<RawOption>, option_bearing: bool) -> Delivery {
        let reports = options
            .iter()
            .map(|option| report(option.kind, OptionStatus::Success, OptionSource::Datagram))
            .collect();
        payload_with_reports(data, options, option_bearing, reports)
    }

    fn payload_with_reports(
        data: &[u8],
        options: Vec<RawOption>,
        option_bearing: bool,
        reports: Vec<OptionReport>,
    ) -> Delivery {
        let ocs_status = if option_bearing {
            OcsStatus::Valid
        } else {
            OcsStatus::Absent
        };
        payload_with_reports_and_ocs(data, options, option_bearing, reports, ocs_status)
    }

    fn payload_with_reports_and_ocs(
        data: &[u8],
        options: Vec<RawOption>,
        option_bearing: bool,
        reports: Vec<OptionReport>,
        ocs_status: OcsStatus,
    ) -> Delivery {
        Delivery::Payload {
            data: data.to_vec(),
            options,
            option_bearing,
            reports,
            ocs_reports: vec![OcsReport {
                status: ocs_status,
                source: OptionSource::Datagram,
            }],
        }
    }

    fn report(kind: OptionKind, status: OptionStatus, source: OptionSource) -> OptionReport {
        OptionReport { kind, status, source }
    }

    fn with_fragment_ocs(mut delivery: Delivery) -> Delivery {
        with_fragment_ocs_status(&mut delivery, OcsStatus::Valid);
        delivery
    }

    fn with_fragment_ocs_status(delivery: &mut Delivery, status: OcsStatus) {
        let Delivery::Payload { ocs_reports, .. } = delivery else {
            panic!("fragment OCS report requires a payload delivery");
        };
        ocs_reports.insert(
            0,
            OcsReport {
                status,
                source: OptionSource::FragmentSet,
            },
        );
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

    fn split_fragment_datagrams(payload: &[u8], per_datagram_options_body: &[u8]) -> Vec<Vec<u8>> {
        split_fragment_datagrams_with_budget(payload, per_datagram_options_body, 24)
    }

    fn split_fragment_datagrams_with_budget(
        payload: &[u8],
        per_datagram_options_body: &[u8],
        max_fragment_surplus_len: usize,
    ) -> Vec<Vec<u8>> {
        let fragments = split_datagram(
            payload,
            per_datagram_options_body,
            SplitConfig {
                max_fragment_surplus_len,
                peer: PeerFragmentLimits {
                    max_reassembled_size: u16::MAX,
                    max_segments: u8::MAX,
                },
                identification: 0x0102_0304,
            },
        )
        .expect("test payload should split");
        fragments
            .iter()
            .map(|fragment| assemble_datagram(SRC, DST, SRC_PORT, DST_PORT, b"", &fragment.surplus_body))
            .collect()
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

        UDP_LENGTH_LOGS.store(0, Ordering::SeqCst);
        let mut too_long = datagram_with_raw_surplus(b"hi", &[], false);
        too_long[24..26].copy_from_slice(&11u16.to_be_bytes());
        for _ in 0..WARN_SAMPLE_INTERVAL {
            assert!(matches!(
                process(&too_long),
                Err(RecvError::UdpLengthExceedsIpPayload {
                    udp_len: 11,
                    transport_payload_len: 10
                })
            ));
        }
        assert!(UDP_LENGTH_LOGS.load(Ordering::SeqCst) >= 1);
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
            payload_with_bearing(b"hello", Vec::new(), false)
        );
        assert_eq!(
            process(&datagram_with_raw_surplus(b"hi", &[0], false)).unwrap(),
            payload_with_bearing(b"hi", Vec::new(), false)
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
        assert_eq!(
            process(&bad).unwrap(),
            payload_with_reports_and_ocs(user_data, Vec::new(), true, Vec::new(), OcsStatus::Failed)
        );
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
            payload_with_reports_and_ocs(
                user_data,
                vec![raw(OptionKind::Req, &[0xaa, 0xbb, 0xcc, 0xdd])],
                true,
                vec![report(OptionKind::Req, OptionStatus::Success, OptionSource::Datagram)],
                OcsStatus::Unused,
            )
        );

        let mut nonzero_udp_zero_ocs = valid.clone();
        let (ip, udp_at) = IpRepr::parse(&nonzero_udp_zero_ocs).unwrap();
        let udp = UdpHeader::parse(&nonzero_udp_zero_ocs[udp_at..]).unwrap();
        let layout = locate_surplus(&ip, &udp).unwrap();
        nonzero_udp_zero_ocs[layout.ocs_at()..layout.ocs_at() + usize::from(length::OCS)].fill(0);
        assert_eq!(
            process(&nonzero_udp_zero_ocs).unwrap(),
            payload_with_reports_and_ocs(user_data, Vec::new(), true, Vec::new(), OcsStatus::InvalidZero)
        );

        let mut bad_ocs = valid;
        let last = bad_ocs.len() - 1;
        bad_ocs[last] ^= 0x01;
        assert_eq!(
            process(&bad_ocs).unwrap(),
            payload_with_reports_and_ocs(user_data, Vec::new(), true, Vec::new(), OcsStatus::Failed)
        );
    }

    #[test]
    fn malformed_tlv_discards_all_options_but_not_payload() {
        let bytes = datagram(b"hello", &[kind::APC, 1, kind::REQ, 6, 1, 2, 3, 4]);
        assert_eq!(process(&bytes).unwrap(), payload(b"hello", Vec::new()));
    }

    #[test]
    fn erratum_8834_overrun_discards_preceding_options_but_delivers_payload() {
        let bytes = datagram(b"hello", &[kind::REQ, 6, 1, 2, 3, 4, 10, 8, 0xaa, 0xbb]);
        assert_eq!(process(&bytes).unwrap(), payload(b"hello", Vec::new()));
    }

    #[test]
    fn known_safe_over_minimum_length_is_ignored_locally() {
        let bytes = datagram(b"hello", &[kind::MDS, 5, 0, 1, 2, kind::REQ, 6, 4, 3, 2, 1]);
        assert_eq!(
            process(&bytes).unwrap(),
            payload_with_reports(
                b"hello",
                vec![raw(OptionKind::Req, &[4, 3, 2, 1])],
                true,
                vec![
                    report(OptionKind::Mds, OptionStatus::Failed, OptionSource::Datagram),
                    report(OptionKind::Req, OptionStatus::Success, OptionSource::Datagram),
                ],
            )
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
            payload_with_reports(
                b"hello",
                vec![raw(OptionKind::Req, &[1, 1, 2, 2])],
                true,
                vec![
                    report(OptionKind::Other(10), OptionStatus::Ignored, OptionSource::Datagram),
                    report(OptionKind::Req, OptionStatus::Success, OptionSource::Datagram),
                ],
            )
        );

        let unsafe_option = datagram(b"hello", &[kind::UNSAFE_MIN, 2]);
        assert_eq!(
            process(&unsafe_option).unwrap(),
            payload_with_reports(
                b"",
                Vec::new(),
                true,
                vec![report(
                    OptionKind::Other(kind::UNSAFE_MIN),
                    OptionStatus::Failed,
                    OptionSource::Datagram,
                )],
            )
        );
    }

    #[test]
    fn unknown_unsafe_precedence_survives_later_malformed_tlv() {
        let bytes = datagram(b"hello", &[kind::UNSAFE_MIN, 2, kind::APC, 6]);
        assert_eq!(
            process(&bytes).unwrap(),
            payload_with_reports(
                b"",
                Vec::new(),
                true,
                vec![report(
                    OptionKind::Other(kind::UNSAFE_MIN),
                    OptionStatus::Failed,
                    OptionSource::Datagram,
                )],
            )
        );
    }

    #[test]
    fn duplicate_non_frag_option_keeps_first_instance() {
        let bytes = datagram(b"hello", &[kind::REQ, 6, 1, 2, 3, 4, kind::REQ, 6, 9, 8, 7, 6]);
        assert_eq!(
            process(&bytes).unwrap(),
            payload_with_reports(
                b"hello",
                vec![raw(OptionKind::Req, &[1, 2, 3, 4])],
                true,
                vec![
                    report(OptionKind::Req, OptionStatus::Success, OptionSource::Datagram),
                    report(OptionKind::Req, OptionStatus::Ignored, OptionSource::Datagram),
                ],
            )
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
    fn valid_empty_payload_non_terminal_frag_buffers() {
        let frag = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
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
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let mut options = encode(frag);
        options.extend(encode(frag));

        assert_eq!(process(&datagram(b"", &options)).unwrap(), Delivery::Buffered);
    }

    #[test]
    fn reassembles_split_fragments_and_reprocesses_options() {
        let mut options = OptionsBuilder::new();
        options.push(OptionKind::Req, vec![1, 2, 3, 4]);
        let datagrams = split_fragment_datagrams(b"abcdefghij", &options.finish().unwrap());
        assert_eq!(datagrams.len(), 2);

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&datagrams[0], &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&datagrams[1], &mut cache, now).unwrap(),
            with_fragment_ocs(payload_with_reports_and_ocs(
                b"abcdefghij",
                vec![raw(OptionKind::Req, &[1, 2, 3, 4])],
                true,
                vec![report(OptionKind::Req, OptionStatus::Success, OptionSource::Datagram)],
                OcsStatus::Unused,
            ))
        );
    }

    #[test]
    fn reassembles_out_of_order_split_fragments() {
        let datagrams = split_fragment_datagrams(b"abcdefghijk", &[]);
        assert_eq!(datagrams.len(), 2);

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&datagrams[1], &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&datagrams[0], &mut cache, now).unwrap(),
            with_fragment_ocs(payload_with_bearing(b"abcdefghijk", Vec::new(), false))
        );
    }

    #[test]
    fn reports_unused_ocs_for_an_all_zero_checksum_fragment_set() {
        let mut datagrams = split_fragment_datagrams(b"abcdefghijk", &[]);
        assert_eq!(datagrams.len(), 2);
        for datagram in &mut datagrams {
            datagram[26..28].fill(0);
            let (ip, udp_at) = IpRepr::parse(datagram).unwrap();
            let udp = UdpHeader::parse(&datagram[udp_at..]).unwrap();
            let layout = locate_surplus(&ip, &udp).unwrap();
            datagram[layout.ocs_at()..layout.ocs_at() + usize::from(length::OCS)].fill(0);
        }

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&datagrams[0], &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        let mut expected = payload_with_bearing(b"abcdefghijk", Vec::new(), false);
        with_fragment_ocs_status(&mut expected, OcsStatus::Unused);
        assert_eq!(process_with_cache(&datagrams[1], &mut cache, now).unwrap(), expected);
    }

    #[test]
    fn reports_valid_ocs_when_a_fragment_set_mixes_valid_and_permitted_unused_forms() {
        let mut datagrams = split_fragment_datagrams(b"abcdefghijk", &[]);
        assert_eq!(datagrams.len(), 2);
        datagrams[0][26..28].fill(0);
        let (ip, udp_at) = IpRepr::parse(&datagrams[0]).unwrap();
        let udp = UdpHeader::parse(&datagrams[0][udp_at..]).unwrap();
        let layout = locate_surplus(&ip, &udp).unwrap();
        datagrams[0][layout.ocs_at()..layout.ocs_at() + usize::from(length::OCS)].fill(0);

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&datagrams[0], &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&datagrams[1], &mut cache, now).unwrap(),
            with_fragment_ocs(payload_with_bearing(b"abcdefghijk", Vec::new(), false))
        );
    }

    #[test]
    fn public_cache_insertion_mixed_with_pipeline_reports_unobserved_fragment_set_ocs() {
        let first = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let second = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        let key = FragKey {
            src: SRC,
            dst: DST,
            src_port: SRC_PORT,
            dst_port: DST_PORT,
            identification: 0x0102_0304,
        };
        assert_eq!(cache.insert(key, first, b"abc", now), ReassemblyOutcome::Incomplete);

        let mut expected = payload_with_bearing(b"abcdef", Vec::new(), false);
        with_fragment_ocs_status(&mut expected, OcsStatus::Unobserved);
        assert_eq!(
            process_with_cache(&fragment_datagram(second, &[], b"def"), &mut cache, now).unwrap(),
            expected
        );
    }

    #[test]
    fn fragment_local_safe_options_are_reported_after_reassembly() {
        let mut first_options = Vec::new();
        first_options.extend(encode(Mds {
            max_datagram_size: 1500,
        }));
        first_options.extend(encode(Mrds {
            max_reassembled_size: 4000,
            max_segments: 4,
        }));
        first_options.extend(encode(Req { token: [1, 1, 1, 1] }));
        first_options.extend(encode(Res { token: [2, 2, 2, 2] }));
        let first = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL) + first_options.len()),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };

        let mut second_options = Vec::new();
        second_options.extend(encode(Mds {
            max_datagram_size: 1200,
        }));
        second_options.extend(encode(Mrds {
            max_reassembled_size: 3000,
            max_segments: 2,
        }));
        second_options.extend(encode(Req { token: [3, 3, 3, 3] }));
        second_options.extend(encode(Res { token: [4, 4, 4, 4] }));
        let second = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL) + second_options.len()),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&fragment_datagram(first, &first_options, b"abc"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&fragment_datagram(second, &second_options, b"def"), &mut cache, now).unwrap(),
            with_fragment_ocs(payload_with_reports(
                b"abcdef",
                vec![
                    raw(OptionKind::Mds, &1200u16.to_be_bytes()),
                    raw(OptionKind::Mrds, &[0x0b, 0xb8, 2]),
                    raw(OptionKind::Req, &[3, 3, 3, 3]),
                    raw(OptionKind::Res, &[4, 4, 4, 4]),
                ],
                false,
                vec![
                    report(OptionKind::Mds, OptionStatus::Success, OptionSource::FragmentSet),
                    report(OptionKind::Mrds, OptionStatus::Success, OptionSource::FragmentSet),
                    report(OptionKind::Req, OptionStatus::Success, OptionSource::FragmentSet),
                    report(OptionKind::Res, OptionStatus::Success, OptionSource::FragmentSet),
                ],
            ))
        );
    }

    #[test]
    fn fragment_local_unsafe_discards_existing_partial() {
        let first = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let mut second_options = vec![kind::UNSAFE_MIN, 2];
        let second = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL) + second_options.len()),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&fragment_datagram(first, &[], b"abc"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&fragment_datagram(second, &second_options, b"def"), &mut cache, now).unwrap(),
            Delivery::Dropped
        );
        assert!(cache.is_empty());

        second_options.clear();
        let second = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            ..second
        };
        assert_eq!(
            process_with_cache(&fragment_datagram(second, &second_options, b"def"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
    }

    #[test]
    fn unsafe_before_frag_stops_before_frag_and_preserves_existing_partial() {
        let first = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let second = Frag {
            frag_start: frag_start_for(b"", 2 + usize::from(length::FRAG_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };
        let valid_terminal = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            ..second
        };
        let mut unsafe_then_frag = vec![kind::UNSAFE_MIN, 2];
        second.encode(&mut unsafe_then_frag);
        unsafe_then_frag.extend_from_slice(b"def");

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&fragment_datagram(first, &[], b"abc"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&datagram(b"", &unsafe_then_frag), &mut cache, now).unwrap(),
            payload_with_reports(
                b"",
                Vec::new(),
                true,
                vec![report(
                    OptionKind::Other(kind::UNSAFE_MIN),
                    OptionStatus::Failed,
                    OptionSource::Datagram,
                )],
            )
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            process_with_cache(&fragment_datagram(valid_terminal, &[], b"def"), &mut cache, now).unwrap(),
            with_fragment_ocs(payload_with_bearing(b"abcdef", Vec::new(), false))
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn unsafe_before_malformed_frag_does_not_discard_existing_partial() {
        let first = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let malformed = Frag {
            frag_start: u16::from(length::UDP_HEADER) + u16::from(length::OCS),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };
        let valid_terminal = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            ..malformed
        };
        let mut unsafe_then_malformed_frag = vec![kind::UNSAFE_MIN, 2];
        malformed.encode(&mut unsafe_then_malformed_frag);

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&fragment_datagram(first, &[], b"abc"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&datagram(b"", &unsafe_then_malformed_frag), &mut cache, now).unwrap(),
            payload_with_reports(
                b"",
                Vec::new(),
                true,
                vec![report(
                    OptionKind::Other(kind::UNSAFE_MIN),
                    OptionStatus::Failed,
                    OptionSource::Datagram,
                )],
            )
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            process_with_cache(&fragment_datagram(valid_terminal, &[], b"def"), &mut cache, now).unwrap(),
            with_fragment_ocs(payload_with_bearing(b"abcdef", Vec::new(), false))
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn malformed_frag_start_discards_existing_partial() {
        let first = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let malformed = Frag {
            frag_start: u16::from(length::UDP_HEADER) + u16::from(length::OCS),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };
        let valid_terminal = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&fragment_datagram(first, &[], b"abc"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(&fragment_datagram(malformed, &[], b""), &mut cache, now).unwrap(),
            Delivery::Dropped
        );
        assert!(cache.is_empty());
        assert_eq!(
            process_with_cache(&fragment_datagram(valid_terminal, &[], b"def"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
    }

    #[test]
    fn reprocess_drops_nested_empty_payload_frag() {
        let nested = Frag {
            frag_start: u16::from(length::UDP_HEADER) + u16::from(length::OCS) + u16::from(length::FRAG_TERMINAL),
            identification: 0x1111_2222,
            frag_offset: 0,
            rdos: Some(u16::from(length::UDP_HEADER)),
        };
        let mut nested_body = vec![0, 0];
        nested.encode(&mut nested_body);
        let datagrams = split_fragment_datagrams_with_budget(b"", &nested_body, 64);
        assert_eq!(datagrams.len(), 1);

        assert_eq!(process(&datagrams[0]).unwrap(), Delivery::Dropped);
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
    fn sub_minimum_option_after_frag_discards_existing_partial_without_user_delivery() {
        let first = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_NON_TERMINAL)),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER),
            rdos: None,
        };
        let malformed_terminal = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL) + 3),
            identification: 0x0102_0304,
            frag_offset: u16::from(length::UDP_HEADER) + 3,
            rdos: Some(u16::from(length::UDP_HEADER) + 6),
        };
        let valid_terminal = Frag {
            frag_start: frag_start_for(b"", usize::from(length::FRAG_TERMINAL)),
            ..malformed_terminal
        };

        let mut cache = ReassemblyCache::new();
        let now = Instant::now();
        assert_eq!(
            process_with_cache(&fragment_datagram(first, &[], b"abc"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
        assert_eq!(
            process_with_cache(
                &fragment_datagram(malformed_terminal, &[kind::MDS, 3, 0], b"def"),
                &mut cache,
                now,
            )
            .unwrap(),
            Delivery::Dropped
        );
        assert!(cache.is_empty());
        assert_eq!(
            process_with_cache(&fragment_datagram(valid_terminal, &[], b"def"), &mut cache, now).unwrap(),
            Delivery::Buffered
        );
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
            payload_with_reports(
                b"hello",
                vec![raw(OptionKind::Req, &[1, 3, 5, 7])],
                true,
                vec![
                    report(OptionKind::Other(10), OptionStatus::Ignored, OptionSource::Datagram),
                    report(OptionKind::Req, OptionStatus::Success, OptionSource::Datagram),
                ],
            )
        );
        for _ in 0..WARN_SAMPLE_INTERVAL {
            let _ = process(&bytes);
        }
        assert!(MUST_SUPPORT_ORDER_LOGS.load(Ordering::SeqCst) >= 1);
    }
}
