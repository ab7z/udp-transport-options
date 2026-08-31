//! Reassembling FRAG fragments (the receive side).
//!
//! Added in Step 12: a cache keyed by [`FragKey`], with offset-sorted insertion, overlap detection,
//! a timeout, garbage collection, and per-datagram and global DoS limits. A completed datagram tail is
//! returned to the receive pipeline for exactly one re-processing pass.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::model::{length, limits};
use crate::options::RawOption;
use crate::options::kind::OptionKind;
use crate::options::typed::{Frag, Mds, Mrds, Req, Res, TypedOption};

/// Receive-side FRAG reassembly state.
///
/// Scope each cache instance to one source/destination address-and-port pair (one UDP 4-tuple).
/// Callers handling multiple socket pairs must keep a separate cache for each pair because
/// [`ReassemblyLimits::max_pending_partials`] applies to the entire cache.
#[derive(Debug)]
pub struct ReassemblyCache {
    partials: HashMap<FragKey, Partial>,
    limits: ReassemblyLimits,
}

impl ReassemblyCache {
    /// Creates an empty reassembly cache with the RFC 9868 IPv4 default limits.
    pub fn new() -> Self {
        Self::with_limits(ReassemblyLimits::default())
    }

    /// Creates an empty reassembly cache with explicit limits.
    pub fn with_limits(limits: ReassemblyLimits) -> Self {
        Self {
            partials: HashMap::new(),
            limits,
        }
    }

    /// Returns the number of incomplete datagrams currently retained.
    pub fn len(&self) -> usize {
        self.partials.len()
    }

    /// Returns whether the cache holds no incomplete datagrams.
    pub fn is_empty(&self) -> bool {
        self.partials.is_empty()
    }

    /// Feeds one validated FRAG fragment into the cache.
    ///
    /// `data` is the fragment data bytes at or after `Frag. Start`, not the per-fragment options.
    pub fn insert(&mut self, key: FragKey, frag: Frag, data: &[u8], now: Instant) -> ReassemblyOutcome {
        self.insert_with_options(key, frag, data, &[], now)
    }

    /// Feeds one validated FRAG fragment and its validated per-fragment options into the cache.
    ///
    /// `data` is the fragment data bytes at or after `Frag. Start`, not the per-fragment options.
    pub fn insert_with_options(
        &mut self,
        key: FragKey,
        frag: Frag,
        data: &[u8],
        fragment_options: &[RawOption],
        now: Instant,
    ) -> ReassemblyOutcome {
        self.insert_with_options_and_failures(
            key,
            frag,
            data,
            FragmentProcessing {
                options: fragment_options,
                option_failures: &[],
                ocs_nonzero: None,
            },
            now,
        )
    }

    pub(crate) fn insert_with_options_and_failures(
        &mut self,
        key: FragKey,
        frag: Frag,
        data: &[u8],
        processing: FragmentProcessing<'_>,
        now: Instant,
    ) -> ReassemblyOutcome {
        self.gc(now);

        let Some(fragment) = NormalizedFragment::new(frag, data.len()) else {
            return self.abort(key, AbortReason::Overlap);
        };
        if usize::from(fragment.udp_length.unwrap_or(0)) > self.limits.max_reassembled_size {
            return self.abort(key, AbortReason::LimitExceeded);
        }
        if usize::from(length::UDP_HEADER)
            .checked_add(fragment.end)
            .is_none_or(|len| len > self.limits.max_reassembled_size)
        {
            return self.abort(key, AbortReason::LimitExceeded);
        }

        if !self.partials.contains_key(&key) {
            if self.partials.len() >= self.limits.max_pending_partials {
                return self.insert_without_retaining(fragment, data, processing, now);
            }
            self.partials.insert(key, Partial::new(now));
        }

        let partial = self
            .partials
            .get_mut(&key)
            .expect("partial was inserted or already present");
        match partial.insert(
            fragment,
            data,
            processing.options,
            processing.option_failures,
            processing.ocs_nonzero,
            self.limits,
        ) {
            InsertResult::Incomplete => ReassemblyOutcome::Incomplete,
            InsertResult::Complete {
                tail,
                udp_length,
                fragment_options,
                fragment_option_failures,
                fragment_ocs_nonzero,
            } => {
                self.partials.remove(&key);
                ReassemblyOutcome::Complete {
                    tail,
                    udp_length,
                    fragment_options,
                    fragment_option_failures,
                    fragment_ocs_nonzero,
                }
            }
            InsertResult::Abort(reason) => {
                self.partials.remove(&key);
                ReassemblyOutcome::Abort(reason)
            }
        }
    }

    /// Discards any incomplete datagram for `key`.
    pub fn discard(&mut self, key: FragKey) {
        self.partials.remove(&key);
    }

    fn abort(&mut self, key: FragKey, reason: AbortReason) -> ReassemblyOutcome {
        self.partials.remove(&key);
        ReassemblyOutcome::Abort(reason)
    }

    fn insert_without_retaining(
        &self,
        fragment: NormalizedFragment,
        data: &[u8],
        processing: FragmentProcessing<'_>,
        now: Instant,
    ) -> ReassemblyOutcome {
        let mut partial = Partial::new(now);
        match partial.insert(
            fragment,
            data,
            processing.options,
            processing.option_failures,
            processing.ocs_nonzero,
            self.limits,
        ) {
            InsertResult::Complete {
                tail,
                udp_length,
                fragment_options,
                fragment_option_failures,
                fragment_ocs_nonzero,
            } => ReassemblyOutcome::Complete {
                tail,
                udp_length,
                fragment_options,
                fragment_option_failures,
                fragment_ocs_nonzero,
            },
            InsertResult::Abort(reason) => ReassemblyOutcome::Abort(reason),
            InsertResult::Incomplete => ReassemblyOutcome::Abort(AbortReason::LimitExceeded),
        }
    }

    /// Drops all expired incomplete datagrams.
    pub fn gc(&mut self, now: Instant) {
        let timeout = self.limits.timeout;
        self.partials.retain(|_, partial| !partial.is_expired(now, timeout));
    }
}

impl Default for ReassemblyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Validated per-fragment processing observations retained until reassembly completes.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FragmentProcessing<'a> {
    /// Successfully processed SAFE options on this fragment.
    pub options: &'a [RawOption],
    /// Option kinds that failed on this fragment.
    pub option_failures: &'a [OptionKind],
    /// Whether this fragment used a validated, non-zero OCS, or `None` if not observed.
    pub ocs_nonzero: Option<bool>,
}

/// Receive-side FRAG reassembly limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyLimits {
    /// Maximum reconstructed UDP datagram size, including the UDP header.
    pub max_reassembled_size: usize,
    /// Maximum accepted fragment count for one reconstructed datagram.
    pub max_segments: usize,
    /// Maximum number of incomplete datagrams retained globally by this cache.
    pub max_pending_partials: usize,
    /// Timeout after which an incomplete datagram is discarded.
    pub timeout: Duration,
}

impl Default for ReassemblyLimits {
    fn default() -> Self {
        Self {
            max_reassembled_size: usize::from(limits::MRDS_DEFAULT_IPV4),
            // RFC 9868 requires support for at least two fragments; callers can raise this cap.
            max_segments: usize::from(limits::MIN_REASSEMBLY_SEGMENTS),
            max_pending_partials: limits::REASSEMBLY_MAX_PENDING_PARTIALS,
            timeout: limits::REASSEMBLY_TIMEOUT_MAX,
        }
    }
}

/// The reassembly key: the UDP 4-tuple plus the FRAG Identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    /// Source IP address.
    pub src: Ipv4Addr,
    /// Destination IP address.
    pub dst: Ipv4Addr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// FRAG Identification shared by all fragments of one original datagram.
    pub identification: u32,
}

/// The result of feeding one fragment into the reassembly cache.
#[derive(Debug, PartialEq, Eq)]
pub enum ReassemblyOutcome {
    /// More fragments are needed; nothing to deliver yet.
    Incomplete,
    /// Reassembly completed; the reconstructed tail and UDP Length are returned for re-processing.
    Complete {
        /// Bytes after the reconstructed UDP header: UDP user data plus any reassembled surplus area.
        tail: Vec<u8>,
        /// Reconstructed UDP Length, i.e. the terminal FRAG RDOS value.
        udp_length: u16,
        /// Coalesced SAFE options that were carried by the individual fragments.
        fragment_options: Vec<RawOption>,
        /// Option kinds that failed on at least one individual fragment.
        fragment_option_failures: Vec<OptionKind>,
        /// Whether at least one fragment carried a validated, non-zero OCS.
        ///
        /// `Some(false)` means all accepted fragments used the RFC-permitted zero OCS with a zero
        /// UDP checksum. `None` means at least one fragment arrived through a public insertion
        /// method that supplies no OCS observation; the receive pipeline surfaces that set as
        /// `OcsStatus::Unobserved`, which never satisfies a required-OCS policy.
        fragment_ocs_nonzero: Option<bool>,
    },
    /// Reassembly was aborted and the partial state discarded.
    Abort(AbortReason),
}

/// Why a reassembly was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// A fragment overlapped previously received data or contradicted terminal metadata.
    Overlap,
    /// A per-datagram or global reassembly limit was exceeded.
    LimitExceeded,
}

#[derive(Debug)]
struct Partial {
    segments: Vec<Segment>,
    terminal_end: Option<usize>,
    udp_length: Option<u16>,
    fragment_count: usize,
    byte_total: usize,
    fragment_options: FragmentOptions,
    fragment_option_failures: FragmentOptionFailures,
    fragment_ocs_nonzero: Option<bool>,
    empty_terminal_options: Option<Vec<RawOption>>,
    empty_terminal_option_failures: Option<Vec<OptionKind>>,
    received_at: Instant,
}

impl Partial {
    fn new(received_at: Instant) -> Self {
        Self {
            segments: Vec::new(),
            terminal_end: None,
            udp_length: None,
            fragment_count: 0,
            byte_total: 0,
            fragment_options: FragmentOptions::default(),
            fragment_option_failures: FragmentOptionFailures::default(),
            fragment_ocs_nonzero: Some(false),
            empty_terminal_options: None,
            empty_terminal_option_failures: None,
            received_at,
        }
    }

    fn is_expired(&self, now: Instant, timeout: Duration) -> bool {
        now.duration_since(self.received_at) >= timeout.min(limits::REASSEMBLY_TIMEOUT_MAX)
    }

    fn insert(
        &mut self,
        fragment: NormalizedFragment,
        data: &[u8],
        fragment_options: &[RawOption],
        fragment_option_failures: &[OptionKind],
        fragment_ocs_nonzero: Option<bool>,
        limits: ReassemblyLimits,
    ) -> InsertResult {
        if self.is_exact_duplicate(fragment, data, fragment_options, fragment_option_failures) {
            self.observe_fragment_ocs(fragment_ocs_nonzero);
            return InsertResult::Incomplete;
        }
        let Some(fragment_count) = self.fragment_count.checked_add(1) else {
            return InsertResult::Abort(AbortReason::LimitExceeded);
        };
        if fragment_count > limits.max_segments {
            return InsertResult::Abort(AbortReason::LimitExceeded);
        }
        let Some(byte_total) = self.byte_total.checked_add(data.len()) else {
            return InsertResult::Abort(AbortReason::LimitExceeded);
        };
        if byte_total
            .checked_add(usize::from(length::UDP_HEADER))
            .is_none_or(|udp_total| udp_total > limits.max_reassembled_size)
        {
            return InsertResult::Abort(AbortReason::LimitExceeded);
        }
        if self.overlaps(fragment.start, fragment.end) {
            return InsertResult::Abort(AbortReason::Overlap);
        }

        if let Some(terminal_end) = self.terminal_end
            && fragment.end > terminal_end
        {
            return InsertResult::Abort(AbortReason::Overlap);
        }
        if let Some(udp_length) = fragment.udp_length {
            let Some(user_tail_len) = usize::from(udp_length).checked_sub(usize::from(length::UDP_HEADER)) else {
                return InsertResult::Abort(AbortReason::Overlap);
            };
            if user_tail_len > fragment.end {
                return InsertResult::Abort(AbortReason::Overlap);
            }
            match (self.terminal_end, self.udp_length) {
                (None, None) => {
                    self.terminal_end = Some(fragment.end);
                    self.udp_length = Some(udp_length);
                    if data.is_empty() {
                        self.empty_terminal_options = Some(fragment_options.to_vec());
                        self.empty_terminal_option_failures = Some(fragment_option_failures.to_vec());
                    }
                    if self.segments.iter().any(|segment| segment.end > fragment.end) {
                        return InsertResult::Abort(AbortReason::Overlap);
                    }
                }
                (Some(existing_end), Some(existing_udp_length))
                    if existing_end == fragment.end && existing_udp_length == udp_length =>
                {
                    if data.is_empty()
                        && (self.empty_terminal_options.as_deref() != Some(fragment_options)
                            || self.empty_terminal_option_failures.as_deref() != Some(fragment_option_failures))
                    {
                        return InsertResult::Abort(AbortReason::Overlap);
                    }
                }
                _ => return InsertResult::Abort(AbortReason::Overlap),
            }
        }

        self.fragment_count = fragment_count;
        self.byte_total = byte_total;
        self.fragment_options.observe(fragment_options);
        self.fragment_option_failures.observe(fragment_option_failures);
        self.observe_fragment_ocs(fragment_ocs_nonzero);
        if !data.is_empty() {
            let index = self
                .segments
                .binary_search_by_key(&fragment.start, |segment| segment.start)
                .unwrap_or_else(|index| index);
            self.segments.insert(
                index,
                Segment {
                    start: fragment.start,
                    end: fragment.end,
                    data: data.to_vec(),
                    fragment_options: fragment_options.to_vec(),
                    fragment_option_failures: fragment_option_failures.to_vec(),
                },
            );
        }

        self.complete()
    }

    fn is_exact_duplicate(
        &self,
        fragment: NormalizedFragment,
        data: &[u8],
        fragment_options: &[RawOption],
        fragment_option_failures: &[OptionKind],
    ) -> bool {
        if let Some(udp_length) = fragment.udp_length {
            if self.udp_length != Some(udp_length) || self.terminal_end != Some(fragment.end) {
                return false;
            }
            if data.is_empty() {
                return self.empty_terminal_options.as_deref() == Some(fragment_options)
                    && self.empty_terminal_option_failures.as_deref() == Some(fragment_option_failures);
            }
        }
        self.segments.iter().any(|segment| {
            segment.start == fragment.start
                && segment.end == fragment.end
                && segment.data.as_slice() == data
                && segment.fragment_options.as_slice() == fragment_options
                && segment.fragment_option_failures.as_slice() == fragment_option_failures
        })
    }

    fn overlaps(&self, start: usize, end: usize) -> bool {
        start < end
            && self
                .segments
                .iter()
                .any(|segment| start < segment.end && segment.start < end)
    }

    fn observe_fragment_ocs(&mut self, fragment_ocs_nonzero: Option<bool>) {
        self.fragment_ocs_nonzero = match (self.fragment_ocs_nonzero, fragment_ocs_nonzero) {
            (Some(accumulated), Some(current)) => Some(accumulated || current),
            _ => None,
        };
    }

    fn complete(&self) -> InsertResult {
        let (Some(terminal_end), Some(udp_length)) = (self.terminal_end, self.udp_length) else {
            return InsertResult::Incomplete;
        };

        let mut cursor = 0;
        for segment in &self.segments {
            if segment.start > cursor {
                return InsertResult::Incomplete;
            }
            if segment.start < cursor {
                return InsertResult::Abort(AbortReason::Overlap);
            }
            cursor = segment.end;
        }
        if cursor != terminal_end {
            return InsertResult::Incomplete;
        }

        let mut tail = Vec::with_capacity(terminal_end);
        for segment in &self.segments {
            tail.extend_from_slice(&segment.data);
        }
        InsertResult::Complete {
            tail,
            udp_length,
            fragment_options: self.fragment_options.to_raw_options(),
            fragment_option_failures: self.fragment_option_failures.to_vec(),
            fragment_ocs_nonzero: self.fragment_ocs_nonzero,
        }
    }
}

#[derive(Debug, Default)]
struct FragmentOptions {
    mds: Option<u16>,
    mrds_size: Option<u16>,
    mrds_segments: Option<u8>,
    req: Option<[u8; 4]>,
    res: Option<[u8; 4]>,
}

impl FragmentOptions {
    fn observe(&mut self, options: &[RawOption]) {
        for option in options {
            match option.kind {
                OptionKind::Mds => {
                    if let Ok(mds) = Mds::decode(&option.value) {
                        self.mds = Some(
                            self.mds
                                .map_or(mds.max_datagram_size, |old| old.min(mds.max_datagram_size)),
                        );
                    }
                }
                OptionKind::Mrds => {
                    if let Ok(mrds) = Mrds::decode(&option.value) {
                        self.mrds_size = Some(
                            self.mrds_size
                                .map_or(mrds.max_reassembled_size, |old| old.min(mrds.max_reassembled_size)),
                        );
                        self.mrds_segments = Some(
                            self.mrds_segments
                                .map_or(mrds.max_segments, |old| old.min(mrds.max_segments)),
                        );
                    }
                }
                OptionKind::Req => {
                    if let Ok(req) = Req::decode(&option.value) {
                        self.req = Some(req.token);
                    }
                }
                OptionKind::Res => {
                    if let Ok(res) = Res::decode(&option.value) {
                        self.res = Some(res.token);
                    }
                }
                _ => {}
            }
        }
    }

    fn to_raw_options(&self) -> Vec<RawOption> {
        let mut options = Vec::new();
        if let Some(value) = self.mds {
            options.push(RawOption {
                kind: OptionKind::Mds,
                value: value.to_be_bytes().to_vec(),
            });
        }
        if let (Some(size), Some(segments)) = (self.mrds_size, self.mrds_segments) {
            let mut value = size.to_be_bytes().to_vec();
            value.push(segments);
            options.push(RawOption {
                kind: OptionKind::Mrds,
                value,
            });
        }
        if let Some(token) = self.req {
            options.push(RawOption {
                kind: OptionKind::Req,
                value: token.to_vec(),
            });
        }
        if let Some(token) = self.res {
            options.push(RawOption {
                kind: OptionKind::Res,
                value: token.to_vec(),
            });
        }
        options
    }
}

#[derive(Debug, Default)]
struct FragmentOptionFailures {
    kinds: Vec<OptionKind>,
}

impl FragmentOptionFailures {
    fn observe(&mut self, failures: &[OptionKind]) {
        for kind in failures {
            if !self.kinds.contains(kind) {
                self.kinds.push(*kind);
            }
        }
    }

    fn to_vec(&self) -> Vec<OptionKind> {
        self.kinds.clone()
    }
}

#[derive(Debug)]
struct Segment {
    start: usize,
    end: usize,
    data: Vec<u8>,
    fragment_options: Vec<RawOption>,
    fragment_option_failures: Vec<OptionKind>,
}

#[derive(Debug, Clone, Copy)]
struct NormalizedFragment {
    start: usize,
    end: usize,
    udp_length: Option<u16>,
}

impl NormalizedFragment {
    fn new(frag: Frag, data_len: usize) -> Option<Self> {
        let start = if frag.frag_offset == 0 && frag.rdos.is_some() {
            0
        } else {
            usize::from(frag.frag_offset).checked_sub(usize::from(length::UDP_HEADER))?
        };
        let end = start.checked_add(data_len)?;
        Some(Self {
            start,
            end,
            udp_length: frag.rdos,
        })
    }
}

enum InsertResult {
    Incomplete,
    Complete {
        tail: Vec<u8>,
        udp_length: u16,
        fragment_options: Vec<RawOption>,
        fragment_option_failures: Vec<OptionKind>,
        fragment_ocs_nonzero: Option<bool>,
    },
    Abort(AbortReason),
}

#[cfg(test)]
mod tests {
    use super::{AbortReason, FragKey, ReassemblyCache, ReassemblyLimits, ReassemblyOutcome};
    use crate::model::limits;
    use crate::options::RawOption;
    use crate::options::kind::OptionKind;
    use crate::options::typed::Frag;

    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    const ID: u32 = 0x0102_0304;

    fn key(id: u32) -> FragKey {
        FragKey {
            src: Ipv4Addr::new(192, 0, 2, 1),
            dst: Ipv4Addr::new(198, 51, 100, 2),
            src_port: 12345,
            dst_port: 54321,
            identification: id,
        }
    }

    fn frag(offset: u16, rdos: Option<u16>) -> Frag {
        Frag {
            frag_start: 20,
            identification: ID,
            frag_offset: offset,
            rdos,
        }
    }

    fn raw(kind: OptionKind, value: &[u8]) -> RawOption {
        RawOption {
            kind,
            value: value.to_vec(),
        }
    }

    fn now() -> Instant {
        Instant::now()
    }

    fn outcome_tail(outcome: ReassemblyOutcome) -> (Vec<u8>, u16) {
        match outcome {
            ReassemblyOutcome::Complete { tail, udp_length, .. } => (tail, udp_length),
            other => panic!("expected complete outcome, got {other:?}"),
        }
    }

    #[test]
    fn in_order_fragments_complete() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abc", t0),
            ReassemblyOutcome::Incomplete
        );
        let (tail, udp_length) = outcome_tail(cache.insert(key(ID), frag(11, Some(14)), b"def", t0));
        assert_eq!(tail, b"abcdef");
        assert_eq!(udp_length, 14);
        assert!(cache.is_empty());
    }

    #[test]
    fn out_of_order_fragments_complete() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        assert_eq!(
            cache.insert(key(ID), frag(11, Some(14)), b"def", t0),
            ReassemblyOutcome::Incomplete
        );
        let (tail, udp_length) = outcome_tail(cache.insert(key(ID), frag(8, None), b"abc", t0));
        assert_eq!(tail, b"abcdef");
        assert_eq!(udp_length, 14);
    }

    #[test]
    fn atomic_terminal_completes_immediately() {
        let mut cache = ReassemblyCache::new();
        let (tail, udp_length) = outcome_tail(cache.insert(key(ID), frag(0, Some(13)), b"hello", now()));
        assert_eq!(tail, b"hello");
        assert_eq!(udp_length, 13);
    }

    #[test]
    fn empty_terminal_fragment_can_close_existing_data() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abc", t0),
            ReassemblyOutcome::Incomplete
        );
        let (tail, udp_length) = outcome_tail(cache.insert(key(ID), frag(11, Some(11)), b"", t0));
        assert_eq!(tail, b"abc");
        assert_eq!(udp_length, 11);
    }

    #[test]
    fn identical_duplicate_is_ignored_but_different_overlap_aborts() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abc", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abc", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abd", t0),
            ReassemblyOutcome::Abort(AbortReason::Overlap)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn same_data_with_different_fragment_options_aborts() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        let first_options = [raw(OptionKind::Req, &[1, 2, 3, 4])];
        let second_options = [raw(OptionKind::Req, &[4, 3, 2, 1])];

        assert_eq!(
            cache.insert_with_options(key(ID), frag(8, None), b"abc", &first_options, t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert_with_options(key(ID), frag(8, None), b"abc", &second_options, t0),
            ReassemblyOutcome::Abort(AbortReason::Overlap)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn empty_terminal_duplicate_with_different_options_aborts() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        let first_options = [raw(OptionKind::Req, &[1, 2, 3, 4])];
        let second_options = [raw(OptionKind::Req, &[4, 3, 2, 1])];

        assert_eq!(
            cache.insert_with_options(key(ID), frag(11, Some(11)), b"", &first_options, t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert_with_options(key(ID), frag(11, Some(11)), b"", &second_options, t0),
            ReassemblyOutcome::Abort(AbortReason::Overlap)
        );
        assert!(cache.is_empty());
    }

    #[test]
    fn partial_overlap_aborts() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abcd", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(10, None), b"xy", t0),
            ReassemblyOutcome::Abort(AbortReason::Overlap)
        );
    }

    #[test]
    fn early_limit_abort_discards_existing_partial() {
        let t0 = now();
        let limits = ReassemblyLimits {
            max_reassembled_size: 12,
            max_segments: 3,
            max_pending_partials: 2,
            timeout: limits::REASSEMBLY_TIMEOUT_MAX,
        };
        let mut cache = ReassemblyCache::with_limits(limits);
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"ab", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(10, None), b"abcdef", t0),
            ReassemblyOutcome::Abort(AbortReason::LimitExceeded)
        );
        assert_eq!(
            cache.insert(key(ID), frag(10, Some(12)), b"cd", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn inconsistent_terminal_metadata_aborts() {
        let mut cache = ReassemblyCache::new();
        let t0 = now();
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abc", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(11, Some(20)), b"", t0),
            ReassemblyOutcome::Abort(AbortReason::Overlap)
        );

        let mut cache = ReassemblyCache::new();
        assert_eq!(
            cache.insert(key(ID), frag(11, Some(14)), b"def", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(8, Some(11)), b"abc", t0),
            ReassemblyOutcome::Abort(AbortReason::Overlap)
        );
    }

    #[test]
    fn limits_fire_and_preserve_other_keys() {
        let t0 = now();
        let limits = ReassemblyLimits {
            max_reassembled_size: 12,
            max_segments: 2,
            max_pending_partials: 2,
            timeout: limits::REASSEMBLY_TIMEOUT_MAX,
        };
        let mut cache = ReassemblyCache::with_limits(limits);
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"abcde", t0),
            ReassemblyOutcome::Abort(AbortReason::LimitExceeded)
        );

        let mut cache = ReassemblyCache::with_limits(limits);
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"a", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(9, None), b"b", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID), frag(10, None), b"c", t0),
            ReassemblyOutcome::Abort(AbortReason::LimitExceeded)
        );

        let limits = ReassemblyLimits {
            max_pending_partials: 1,
            ..limits_from_defaults()
        };
        let mut cache = ReassemblyCache::with_limits(limits);
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"a", t0),
            ReassemblyOutcome::Incomplete
        );
        assert_eq!(
            cache.insert(key(ID + 1), frag(8, None), b"b", t0),
            ReassemblyOutcome::Abort(AbortReason::LimitExceeded)
        );
        assert_eq!(cache.len(), 1);
        let (tail, _) = outcome_tail(cache.insert(key(ID), frag(9, Some(10)), b"b", t0));
        assert_eq!(tail, b"ab");
    }

    #[test]
    fn atomic_complete_bypasses_pending_partial_cap() {
        let t0 = now();
        let limits = ReassemblyLimits {
            max_pending_partials: 1,
            ..limits_from_defaults()
        };
        let mut cache = ReassemblyCache::with_limits(limits);
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"a", t0),
            ReassemblyOutcome::Incomplete
        );

        let (tail, udp_length) = outcome_tail(cache.insert(key(ID + 1), frag(0, Some(13)), b"hello", t0));
        assert_eq!(tail, b"hello");
        assert_eq!(udp_length, 13);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn gc_removes_partial_at_timeout_boundary() {
        let t0 = now();
        let mut cache = ReassemblyCache::new();
        assert_eq!(
            cache.insert(key(ID), frag(8, None), b"a", t0),
            ReassemblyOutcome::Incomplete
        );
        cache.gc(t0 + Duration::from_secs(119));
        assert_eq!(cache.len(), 1);
        cache.gc(t0 + Duration::from_secs(120));
        assert!(cache.is_empty());
    }

    fn limits_from_defaults() -> ReassemblyLimits {
        ReassemblyLimits::default()
    }
}
