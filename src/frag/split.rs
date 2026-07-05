//! Splitting an oversized datagram into FRAG fragments (the send side).
//!
//! Added in Step 11: each fragment is carried with empty UDP user data (UDP Length 8); the data
//! lives in the surplus area after the FRAG option. Non-terminal fragments use the 10-byte form and
//! the terminal fragment the 12-byte form (carrying the Reassembled-Datagram-Option-Start). The
//! single-fragment (atomic) case is supported, and sizing respects MDS/MRDS.

use crate::error::SplitError;
use crate::model::{kind, length, limits};

const IPV4_HEADER_LEN: usize = 20;
const FRAGMENT_SURPLUS_LEN_MAX: usize = u16::MAX as usize - IPV4_HEADER_LEN - length::UDP_HEADER as usize;
const FRAG_NON_TERMINAL_BODY_LEN: usize = length::OCS as usize + length::FRAG_NON_TERMINAL as usize;
const FRAG_TERMINAL_BODY_LEN: usize = length::OCS as usize + length::FRAG_TERMINAL as usize;

/// Peer-side FRAG limits derived from MRDS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerFragmentLimits {
    /// Maximum reassembled UDP datagram size, including the UDP header.
    pub max_reassembled_size: u16,
    /// Maximum number of UDP fragments the peer can reassemble.
    pub max_segments: u8,
}

impl PeerFragmentLimits {
    /// RFC 9868's IPv4 defaults when no MRDS option was received.
    pub const fn default_ipv4() -> Self {
        Self {
            max_reassembled_size: limits::MRDS_DEFAULT_IPV4,
            max_segments: limits::MIN_REASSEMBLY_SEGMENTS,
        }
    }
}

/// Configuration for splitting one logical UDP datagram into FRAG fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SplitConfig {
    /// Maximum surplus bytes per emitted fragment, i.e. OCS-led fragment options plus fragment data.
    pub max_fragment_surplus_len: usize,
    /// Peer-side MRDS limits.
    pub peer: PeerFragmentLimits,
    /// Identification shared by all fragments emitted for this original datagram.
    pub identification: u32,
}

/// One send-side FRAG fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    /// Offset, from the original UDP header, where this fragment's data belongs.
    ///
    /// RFC 9868's standalone/atomic FRAG variant uses offset zero.
    pub frag_offset: u16,
    /// Whether this is the terminal FRAG form.
    pub terminal: bool,
    /// The terminal RDOS pointer, present only on the terminal fragment.
    pub rdos: Option<u16>,
    /// OCS-led surplus body with the OCS placeholder still zero.
    pub surplus_body: Vec<u8>,
}

/// Monotonic FRAG Identification generator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentificationGenerator {
    next: u32,
}

impl IdentificationGenerator {
    /// Creates a generator whose first returned value is `next`.
    pub const fn new(next: u32) -> Self {
        Self { next }
    }

    /// Returns the next Identification value without wrapping.
    pub fn next_id(&mut self) -> Result<u32, SplitError> {
        let id = self.next;
        self.next = self.next.checked_add(1).ok_or(SplitError::IdentificationExhausted)?;
        Ok(id)
    }
}

/// Splits one logical UDP datagram tail into RFC 9868 FRAG surplus bodies.
///
/// `payload` is the original UDP user data. `per_datagram_options_body`, when non-empty, must be the
/// OCS-led body with a zero OCS placeholder that will follow the original UDP Length/RDOS after
/// reassembly. This function inserts the RFC-required alignment pad before that body when RDOS is odd,
/// but it does not compute the reassembled datagram's final OCS; the API layer that materializes the
/// reassembled datagram must do that over the final surplus area. The returned fragment bodies are
/// ready to pass to `socket::send::assemble_datagram` with empty UDP user data.
pub fn split_datagram(
    payload: &[u8],
    per_datagram_options_body: &[u8],
    config: SplitConfig,
) -> Result<Vec<Fragment>, SplitError> {
    if !per_datagram_options_body.is_empty() && per_datagram_options_body.len() < usize::from(length::OCS) {
        return Err(SplitError::OptionsBodyTooShort {
            len: per_datagram_options_body.len(),
        });
    }
    if config.max_fragment_surplus_len > FRAGMENT_SURPLUS_LEN_MAX {
        return Err(SplitError::FragmentSurplusTooLarge {
            len: config.max_fragment_surplus_len,
            max: FRAGMENT_SURPLUS_LEN_MAX,
        });
    }

    let rdos = checked_rdos(payload.len())?;
    let tail = reassembled_tail(payload, per_datagram_options_body);
    let reassembled_len = usize::from(length::UDP_HEADER) + tail.len();
    if reassembled_len > usize::from(config.peer.max_reassembled_size) {
        return Err(SplitError::ReassembledDatagramTooLarge {
            len: reassembled_len,
            max: usize::from(config.peer.max_reassembled_size),
        });
    }

    let terminal_body_len = fragment_options_body_len(Some(rdos));
    if config.max_fragment_surplus_len < terminal_body_len {
        return Err(SplitError::FragmentCapacityTooSmall {
            required: terminal_body_len,
            max: config.max_fragment_surplus_len,
        });
    }
    let terminal_capacity = config.max_fragment_surplus_len - terminal_body_len;

    let non_terminal_body_len = fragment_options_body_len(None);
    let non_terminal_capacity = config.max_fragment_surplus_len.saturating_sub(non_terminal_body_len);

    let ranges = chunk_ranges(
        tail.len(),
        terminal_capacity,
        non_terminal_capacity,
        non_terminal_body_len,
        config,
    )?;
    if ranges.len() > usize::from(config.peer.max_segments) {
        return Err(SplitError::SegmentLimitExceeded {
            needed: ranges.len(),
            max: config.peer.max_segments,
        });
    }

    let atomic = ranges.len() == 1;
    let mut fragments = Vec::with_capacity(ranges.len());
    for (start, end, terminal) in ranges {
        let offset = if atomic {
            checked_fragment_offset(0)?
        } else {
            checked_fragment_offset(usize::from(length::UDP_HEADER) + start)?
        };
        let rdos = terminal.then_some(rdos);
        let mut surplus_body = fragment_options_body(config.identification, offset, rdos);
        surplus_body.extend_from_slice(&tail[start..end]);
        fragments.push(Fragment {
            frag_offset: offset,
            terminal,
            rdos,
            surplus_body,
        });
    }

    Ok(fragments)
}

fn checked_rdos(payload_len: usize) -> Result<u16, SplitError> {
    let rdos = usize::from(length::UDP_HEADER)
        .checked_add(payload_len)
        .ok_or(SplitError::RdosTooLarge {
            rdos: usize::MAX,
            max: usize::from(u16::MAX),
        })?;
    u16::try_from(rdos).map_err(|_| SplitError::RdosTooLarge {
        rdos,
        max: usize::from(u16::MAX),
    })
}

fn checked_fragment_offset(offset: usize) -> Result<u16, SplitError> {
    u16::try_from(offset).map_err(|_| SplitError::FragmentOffsetTooLarge {
        offset,
        max: usize::from(u16::MAX),
    })
}

fn reassembled_tail(payload: &[u8], per_datagram_options_body: &[u8]) -> Vec<u8> {
    let pad_len = usize::from(!per_datagram_options_body.is_empty() && rdos_needs_options_pad(payload.len()));
    let mut tail = Vec::with_capacity(payload.len() + pad_len + per_datagram_options_body.len());
    tail.extend_from_slice(payload);
    if pad_len == 1 {
        tail.push(0);
    }
    tail.extend_from_slice(per_datagram_options_body);
    tail
}

fn rdos_needs_options_pad(payload_len: usize) -> bool {
    (usize::from(length::UDP_HEADER) + payload_len) % 2 == 1
}

fn chunk_ranges(
    tail_len: usize,
    terminal_capacity: usize,
    non_terminal_capacity: usize,
    non_terminal_body_len: usize,
    config: SplitConfig,
) -> Result<Vec<(usize, usize, bool)>, SplitError> {
    if tail_len <= terminal_capacity {
        return Ok(vec![(0, tail_len, true)]);
    }

    if non_terminal_capacity == 0 {
        return Err(SplitError::FragmentCapacityTooSmall {
            required: non_terminal_body_len + 1,
            max: config.max_fragment_surplus_len,
        });
    }

    let mut ranges = Vec::new();
    let mut start = 0;
    let mut remaining = tail_len;
    while remaining > terminal_capacity {
        let take = non_terminal_capacity.min(remaining - terminal_capacity);
        ranges.push((start, start + take, false));
        start += take;
        remaining -= take;
    }
    ranges.push((start, tail_len, true));
    Ok(ranges)
}

fn fragment_options_body_len(rdos: Option<u16>) -> usize {
    if rdos.is_some() {
        FRAG_TERMINAL_BODY_LEN
    } else {
        FRAG_NON_TERMINAL_BODY_LEN
    }
}

fn fragment_options_body(identification: u32, frag_offset: u16, rdos: Option<u16>) -> Vec<u8> {
    let body_len = fragment_options_body_len(rdos);
    let frag_start = u16::from(length::UDP_HEADER) + body_len as u16;
    let frag_len = if rdos.is_some() {
        length::FRAG_TERMINAL
    } else {
        length::FRAG_NON_TERMINAL
    };

    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(&[0, 0]);
    body.push(kind::FRAG);
    body.push(frag_len);
    body.extend_from_slice(&frag_value(frag_start, identification, frag_offset, rdos));
    body
}

fn frag_value(frag_start: u16, identification: u32, frag_offset: u16, rdos: Option<u16>) -> Vec<u8> {
    let mut value = Vec::with_capacity(if rdos.is_some() { 10 } else { 8 });
    value.extend_from_slice(&frag_start.to_be_bytes());
    value.extend_from_slice(&identification.to_be_bytes());
    value.extend_from_slice(&frag_offset.to_be_bytes());
    if let Some(rdos) = rdos {
        value.extend_from_slice(&rdos.to_be_bytes());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::{
        FRAGMENT_SURPLUS_LEN_MAX, IdentificationGenerator, PeerFragmentLimits, SplitConfig, SplitError,
        rdos_needs_options_pad, split_datagram,
    };
    use crate::model::length;
    use crate::options::kind::OptionKind;
    use crate::options::parse::OptionsIter;
    use crate::options::serialize::OptionsBuilder;
    use crate::options::typed::{Frag, TypedOption};

    fn config(max_fragment_surplus_len: usize, max_segments: u8) -> SplitConfig {
        SplitConfig {
            max_fragment_surplus_len,
            peer: PeerFragmentLimits {
                max_reassembled_size: u16::MAX,
                max_segments,
            },
            identification: 0x1234_5678,
        }
    }

    fn parsed_frag(surplus_body: &[u8]) -> (Frag, &[u8]) {
        assert_eq!(&surplus_body[..2], &[0, 0]);
        let option = OptionsIter::new(&surplus_body[2..])
            .next()
            .expect("FRAG option")
            .expect("valid FRAG TLV");
        let frag = Frag::decode(option.value).expect("valid FRAG value");
        let data_start = usize::from(frag.frag_start) - usize::from(length::UDP_HEADER);
        (frag, &surplus_body[data_start..])
    }

    fn reassemble_payload(fragments: &[super::Fragment]) -> Vec<u8> {
        let mut ordered = fragments.to_vec();
        ordered.sort_by_key(|fragment| fragment.frag_offset);
        let mut out = Vec::new();
        let atomic = ordered.len() == 1 && ordered[0].terminal;
        let mut expected_offset = if atomic { 0 } else { usize::from(length::UDP_HEADER) };
        for fragment in ordered {
            let (frag, chunk) = parsed_frag(&fragment.surplus_body);
            assert_eq!(usize::from(fragment.frag_offset), expected_offset);
            assert_eq!(frag.frag_offset, fragment.frag_offset);
            out.extend_from_slice(chunk);
            expected_offset += chunk.len();
        }
        out
    }

    #[test]
    fn atomic_fragment_is_terminal() {
        let fragments = split_datagram(b"abc", &[], config(64, 2)).unwrap();
        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].terminal);
        assert_eq!(fragments[0].frag_offset, 0);
        assert_eq!(fragments[0].rdos, Some(u16::from(length::UDP_HEADER) + 3));

        let (frag, chunk) = parsed_frag(&fragments[0].surplus_body);
        assert_eq!(frag.identification, 0x1234_5678);
        assert_eq!(frag.frag_offset, 0);
        assert_eq!(frag.rdos, Some(11));
        assert_eq!(chunk, b"abc");
    }

    #[test]
    fn multiple_fragments_are_contiguous_and_share_identification() {
        let payload = vec![0xa5; 25];
        let fragments = split_datagram(&payload, &[], config(24, 4)).unwrap();
        assert_eq!(fragments.len(), 3);

        let mut saw_terminal = false;
        for fragment in &fragments {
            let (frag, chunk) = parsed_frag(&fragment.surplus_body);
            assert_eq!(frag.identification, 0x1234_5678);
            assert_eq!(fragment.terminal, frag.rdos.is_some());
            saw_terminal |= fragment.terminal;
            if fragment.terminal {
                assert_eq!(frag.rdos, Some(u16::from(length::UDP_HEADER) + payload.len() as u16));
            } else {
                assert!(chunk.len() <= 12);
                assert_eq!(frag.rdos, None);
            }
        }
        assert!(saw_terminal);
        assert_eq!(reassemble_payload(&fragments), payload);
    }

    #[test]
    fn odd_rdos_adds_pad_before_original_options_body() {
        let options_body = OptionsBuilder::new().finish().unwrap();
        let payload = b"abc";
        assert!(rdos_needs_options_pad(payload.len()));

        let fragments = split_datagram(payload, &options_body, config(64, 2)).unwrap();
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0].rdos, Some(11));

        let mut expected = payload.to_vec();
        expected.push(0);
        expected.extend_from_slice(&options_body);
        assert_eq!(reassemble_payload(&fragments), expected);
    }

    #[test]
    fn rejects_reassembled_datagram_larger_than_mrds() {
        let mut cfg = config(64, 2);
        cfg.peer.max_reassembled_size = 10;
        assert_eq!(
            split_datagram(b"abc", &[], cfg),
            Err(SplitError::ReassembledDatagramTooLarge { len: 11, max: 10 })
        );
    }

    #[test]
    fn rejects_splits_that_exceed_peer_segment_limit() {
        let mut cfg = config(24, 1);
        cfg.peer.max_reassembled_size = u16::MAX;
        let err = split_datagram(&[0xa5; 25], &[], cfg).unwrap_err();
        assert_eq!(err, SplitError::SegmentLimitExceeded { needed: 3, max: 1 });
    }

    #[test]
    fn rejects_fragment_budget_too_small_for_terminal_body() {
        let err = split_datagram(b"", &[], config(13, 1)).unwrap_err();
        assert_eq!(err, SplitError::FragmentCapacityTooSmall { required: 14, max: 13 });
    }

    #[test]
    fn splits_non_empty_payload_with_empty_terminal_when_budget_allows() {
        let fragments = split_datagram(b"a", &[], config(14, 2)).unwrap();
        assert_eq!(fragments.len(), 2);

        let (first_frag, first_chunk) = parsed_frag(&fragments[0].surplus_body);
        assert!(!fragments[0].terminal);
        assert_eq!(first_frag.frag_offset, u16::from(length::UDP_HEADER));
        assert_eq!(first_frag.rdos, None);
        assert_eq!(first_chunk, b"a");

        let (terminal_frag, terminal_chunk) = parsed_frag(&fragments[1].surplus_body);
        assert!(fragments[1].terminal);
        assert_eq!(terminal_frag.frag_offset, u16::from(length::UDP_HEADER) + 1);
        assert_eq!(terminal_frag.rdos, Some(u16::from(length::UDP_HEADER) + 1));
        assert!(terminal_chunk.is_empty());

        assert_eq!(reassemble_payload(&fragments), b"a");
    }

    #[test]
    fn rejects_too_short_original_options_body() {
        assert_eq!(
            split_datagram(b"", &[0], config(64, 1)),
            Err(SplitError::OptionsBodyTooShort { len: 1 })
        );
    }

    #[test]
    fn rejects_unsendable_ipv4_fragment_surplus_budget() {
        assert_eq!(
            split_datagram(b"", &[], config(FRAGMENT_SURPLUS_LEN_MAX + 1, 1)),
            Err(SplitError::FragmentSurplusTooLarge {
                len: FRAGMENT_SURPLUS_LEN_MAX + 1,
                max: FRAGMENT_SURPLUS_LEN_MAX,
            })
        );
    }

    #[test]
    fn largest_ipv4_fragment_budget_still_emits_sendable_fragments() {
        let payload = vec![0xa5; usize::from(u16::MAX) - usize::from(length::UDP_HEADER)];
        let fragments = split_datagram(&payload, &[], config(FRAGMENT_SURPLUS_LEN_MAX, 2)).unwrap();

        assert_eq!(fragments.len(), 2);
        assert!(
            fragments
                .iter()
                .all(|fragment| fragment.surplus_body.len() <= FRAGMENT_SURPLUS_LEN_MAX)
        );
        assert_eq!(reassemble_payload(&fragments), payload);
    }

    #[test]
    fn default_ipv4_mrds_payload_fits_two_ethernet_sized_fragments() {
        let payload = vec![0xa5; 2918];
        let cfg = SplitConfig {
            max_fragment_surplus_len: 1472,
            peer: PeerFragmentLimits::default_ipv4(),
            identification: 0x1234_5678,
        };
        let fragments = split_datagram(&payload, &[], cfg).unwrap();

        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].frag_offset, u16::from(length::UDP_HEADER));
        assert_eq!(fragments[1].frag_offset, u16::from(length::UDP_HEADER) + 1460);
        assert_eq!(fragments[0].surplus_body.len(), 1472);
        assert_eq!(fragments[1].surplus_body.len(), 1472);
        assert_eq!(
            fragments[1].rdos,
            Some(u16::from(length::UDP_HEADER) + payload.len() as u16)
        );
        assert_eq!(reassemble_payload(&fragments), payload);
    }

    #[test]
    fn identification_generator_does_not_wrap() {
        let mut generator = IdentificationGenerator::new(41);
        assert_eq!(generator.next_id(), Ok(41));
        assert_eq!(generator.next_id(), Ok(42));

        let mut exhausted = IdentificationGenerator::new(u32::MAX);
        assert_eq!(exhausted.next_id(), Err(SplitError::IdentificationExhausted));
    }

    #[test]
    fn frag_start_points_to_data_after_minimal_frag_body() {
        let fragments = split_datagram(b"abc", &[], config(64, 2)).unwrap();
        let (frag, _) = parsed_frag(&fragments[0].surplus_body);
        assert_eq!(
            usize::from(frag.frag_start),
            usize::from(length::UDP_HEADER) + fragments[0].surplus_body.len() - 3
        );

        let first_option = OptionsIter::new(&fragments[0].surplus_body[2..])
            .next()
            .expect("FRAG option")
            .expect("valid option");
        assert_eq!(first_option.kind, OptionKind::Frag);
    }
}
