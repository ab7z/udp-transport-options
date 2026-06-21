//! The option serializer.
//!
//! [`OptionsBuilder`] emits the OCS-led options body: a two-byte zero OCS placeholder, canonical
//! TLV options, EOL, and zero-fill to a 2-byte boundary. The optional pre-OCS alignment pad for an
//! odd surplus start belongs to the wire/send layer, not to this builder.

use crate::error::SerializeError;
use crate::model::{kind, length};
use crate::options::RawOption;
use crate::options::kind::OptionKind;

const OCS_PLACEHOLDER_LEN: usize = length::OCS as usize;
const DEFAULT_VALUE_LEN_MAX: usize = 252;
const EXTENDED_VALUE_LEN_MAX: usize = u16::MAX as usize - 4;
const BODY_LEN_MAX: usize = u16::MAX as usize - 1;
const FRAG_VALUE_LENS: [usize; 2] = [
    length::FRAG_NON_TERMINAL as usize - 2,
    length::FRAG_TERMINAL as usize - 2,
];

/// Builds canonical UDP option bytes after the optional surplus-area pad.
#[derive(Debug, Clone, Default)]
pub struct OptionsBuilder {
    options: Vec<RawOption>,
}

impl OptionsBuilder {
    /// Creates an empty builder.
    pub const fn new() -> Self {
        Self { options: Vec::new() }
    }

    /// Appends one raw option value. The value excludes Kind/Length framing.
    pub fn push(&mut self, kind: OptionKind, value: impl Into<Vec<u8>>) -> &mut Self {
        self.options.push(RawOption {
            kind,
            value: value.into(),
        });
        self
    }

    /// Appends one owned raw option.
    pub fn push_raw(&mut self, option: RawOption) -> &mut Self {
        self.options.push(option);
        self
    }

    /// Appends a sequence of owned raw options.
    pub fn extend_raw<I>(&mut self, options: I) -> &mut Self
    where
        I: IntoIterator<Item = RawOption>,
    {
        self.options.extend(options);
        self
    }

    /// Finishes the canonical OCS-led options body.
    pub fn finish(self) -> Result<Vec<u8>, SerializeError> {
        let mut options = self.validated_options()?;
        options.sort_by_key(|option| canonical_rank(option.kind.to_byte()));

        let body_len = serialized_body_len(&options)?;
        patch_frag_start(&mut options, body_len)?;
        let mut out = Vec::with_capacity(body_len);
        out.extend_from_slice(&[0, 0]);

        for option in &options {
            if out.len() % 2 == 1 {
                out.push(kind::NOP);
            }
            encode_option(&mut out, option)?;
        }

        out.push(kind::EOL);
        if out.len() % 2 == 1 {
            out.push(0);
        }
        debug_assert_eq!(out.len(), body_len);
        Ok(out)
    }

    fn validated_options(self) -> Result<Vec<RawOption>, SerializeError> {
        let mut seen_frag = false;
        for option in &self.options {
            validate_option(option)?;
            if option.kind.to_byte() == kind::FRAG {
                if seen_frag {
                    return Err(SerializeError::DuplicateFrag);
                }
                seen_frag = true;
            }
        }
        Ok(self.options)
    }
}

fn validate_option(option: &RawOption) -> Result<(), SerializeError> {
    let raw_kind = option.kind.to_byte();
    match raw_kind {
        kind::EOL | kind::NOP => Err(SerializeError::ReservedKind { kind: raw_kind }),
        kind::UNSAFE_MIN..=u8::MAX => Err(SerializeError::UnsafeKind { kind: raw_kind }),
        _ if is_out_of_scope_assigned_safe_kind(raw_kind) => {
            Err(SerializeError::UnsupportedAssignedKind { kind: raw_kind })
        }
        _ if option.value.len() > EXTENDED_VALUE_LEN_MAX => Err(SerializeError::ValueTooLong {
            kind: raw_kind,
            value_len: option.value.len(),
            max: EXTENDED_VALUE_LEN_MAX,
        }),
        _ => validate_fixed_value_len(raw_kind, option.value.len()),
    }
}

fn is_out_of_scope_assigned_safe_kind(kind: u8) -> bool {
    matches!(
        kind,
        kind::TIME | kind::AUTH | kind::EXP | kind::SAFE_RESERVED_MIN..=kind::SAFE_RESERVED_MAX
    )
}

fn fixed_value_lens(kind: u8) -> &'static [usize] {
    match kind {
        kind::APC => &[length::APC as usize - 2],
        kind::FRAG => &FRAG_VALUE_LENS,
        kind::MDS => &[length::MDS as usize - 2],
        kind::MRDS => &[length::MRDS as usize - 2],
        kind::REQ => &[length::REQ as usize - 2],
        kind::RES => &[length::RES as usize - 2],
        _ => &[],
    }
}

fn validate_fixed_value_len(kind: u8, value_len: usize) -> Result<(), SerializeError> {
    let expected = fixed_value_lens(kind);
    if expected.is_empty() || expected.contains(&value_len) {
        Ok(())
    } else {
        Err(SerializeError::InvalidFixedValueLength { kind, value_len })
    }
}

fn patch_frag_start(options: &mut [RawOption], body_len: usize) -> Result<(), SerializeError> {
    let start = length::UDP_HEADER as usize + body_len;
    let start = u16::try_from(start).map_err(|_| SerializeError::FragmentStartTooLarge {
        start,
        max: u16::MAX as usize,
    })?;

    for option in options {
        if option.kind.to_byte() == kind::FRAG {
            // Validation has already restricted FRAG values to the two RFC lengths, both of which
            // begin with the 16-bit Frag. Start field.
            option.value[..2].copy_from_slice(&start.to_be_bytes());
        }
    }

    Ok(())
}

fn canonical_rank(kind: u8) -> (u16, u8) {
    match kind {
        kind::FRAG => (0, kind),
        kind::APC => (1, kind),
        kind::MDS => (2, kind),
        kind::MRDS => (3, kind),
        kind::REQ => (4, kind),
        kind::RES => (5, kind),
        other => (1000 + u16::from(other), other),
    }
}

fn encoded_len(value_len: usize) -> usize {
    if value_len <= DEFAULT_VALUE_LEN_MAX {
        value_len + 2
    } else {
        value_len + 4
    }
}

fn checked_body_add(current: usize, add: usize) -> Result<usize, SerializeError> {
    // `serialized_body_len` is called after per-option length validation, so arithmetic overflow is
    // not reachable for valid builder input. Keep the checked add as a hard defensive boundary.
    let len = current.checked_add(add).ok_or(SerializeError::BodyTooLong {
        len: usize::MAX,
        max: BODY_LEN_MAX,
    })?;
    if len > BODY_LEN_MAX {
        return Err(SerializeError::BodyTooLong { len, max: BODY_LEN_MAX });
    }
    Ok(len)
}

fn serialized_body_len(options: &[RawOption]) -> Result<usize, SerializeError> {
    let mut len = OCS_PLACEHOLDER_LEN;
    for option in options {
        if len % 2 == 1 {
            len = checked_body_add(len, 1)?;
        }
        len = checked_body_add(len, encoded_len(option.value.len()))?;
    }

    len = checked_body_add(len, 1)?;
    if len % 2 == 1 {
        len = checked_body_add(len, 1)?;
    }
    Ok(len)
}

fn encode_option(out: &mut Vec<u8>, option: &RawOption) -> Result<(), SerializeError> {
    let raw_kind = option.kind.to_byte();
    let value_len = option.value.len();
    out.push(raw_kind);

    if value_len <= DEFAULT_VALUE_LEN_MAX {
        out.push((value_len + 2) as u8);
    } else {
        let total_len = value_len + 4;
        // `validate_option` bounds `value_len` to `u16::MAX - 4`; this remains a defensive guard
        // for callers that might reach this helper without the builder's validation sequence.
        if total_len > u16::MAX as usize {
            return Err(SerializeError::ValueTooLong {
                kind: raw_kind,
                value_len,
                max: EXTENDED_VALUE_LEN_MAX,
            });
        }
        out.push(kind::EXTENDED_LENGTH_MARKER);
        out.extend_from_slice(&(total_len as u16).to_be_bytes());
    }

    out.extend_from_slice(&option.value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BODY_LEN_MAX, DEFAULT_VALUE_LEN_MAX, EXTENDED_VALUE_LEN_MAX, OptionsBuilder};
    use crate::error::SerializeError;
    use crate::model::{kind, length};
    use crate::options::kind::OptionKind;
    use crate::options::parse::OptionsIter;

    fn finish_one(option_kind: OptionKind, value: Vec<u8>) -> Result<Vec<u8>, SerializeError> {
        let mut builder = OptionsBuilder::new();
        builder.push(option_kind, value);
        builder.finish()
    }

    #[test]
    fn empty_builder_emits_ocs_eol_and_zero_fill() {
        assert_eq!(OptionsBuilder::new().finish(), Ok(vec![0, 0, kind::EOL, 0]));
    }

    #[test]
    fn body_starts_with_zero_ocs_placeholder() {
        let body = finish_one(OptionKind::Req, vec![1, 2, 3, 4]).unwrap();
        assert_eq!(&body[..2], &[0, 0]);
        assert_eq!(body.len() % 2, 0);
    }

    #[test]
    fn rejects_user_supplied_eol_and_nop() {
        assert_eq!(
            finish_one(OptionKind::Eol, vec![]),
            Err(SerializeError::ReservedKind { kind: kind::EOL })
        );
        assert_eq!(
            finish_one(OptionKind::Nop, vec![]),
            Err(SerializeError::ReservedKind { kind: kind::NOP })
        );
    }

    #[test]
    fn rejects_unsafe_kinds() {
        assert_eq!(
            finish_one(OptionKind::Other(kind::UNSAFE_MIN), vec![]),
            Err(SerializeError::UnsafeKind { kind: kind::UNSAFE_MIN })
        );
    }

    #[test]
    fn default_length_boundary_uses_one_byte_length() {
        let body = finish_one(OptionKind::Other(10), vec![0xaa; DEFAULT_VALUE_LEN_MAX]).unwrap();
        assert_eq!(&body[..4], &[0, 0, 10, 254]);
    }

    #[test]
    fn extended_length_boundary_uses_big_endian_total_length() {
        let body = finish_one(OptionKind::Other(10), vec![0xaa; DEFAULT_VALUE_LEN_MAX + 1]).unwrap();
        assert_eq!(&body[..6], &[0, 0, 10, kind::EXTENDED_LENGTH_MARKER, 0x01, 0x01]);
    }

    #[test]
    fn rejects_unencodable_values() {
        assert_eq!(
            finish_one(OptionKind::Other(10), vec![0; EXTENDED_VALUE_LEN_MAX + 1]),
            Err(SerializeError::ValueTooLong {
                kind: 10,
                value_len: EXTENDED_VALUE_LEN_MAX + 1,
                max: EXTENDED_VALUE_LEN_MAX
            })
        );
    }

    #[test]
    fn rejects_bodies_that_exceed_even_u16_limit() {
        assert_eq!(
            finish_one(OptionKind::Other(10), vec![0; EXTENDED_VALUE_LEN_MAX]),
            Err(SerializeError::BodyTooLong {
                len: BODY_LEN_MAX + 3,
                max: BODY_LEN_MAX
            })
        );
    }

    #[test]
    fn canonical_order_puts_frag_then_other_must_support_then_safe() {
        let mut builder = OptionsBuilder::new();
        builder
            .push(OptionKind::Other(11), [0x0b])
            .push(OptionKind::Res, [0x07, 0x07, 0x07, 0x07])
            .push(OptionKind::Req, [0x06, 0x06, 0x06, 0x06])
            .push(OptionKind::Mrds, [0x05, 0x05, 0x05])
            .push(OptionKind::Mds, [0x04, 0x04])
            .push(OptionKind::Frag, [0x03; 8])
            .push(OptionKind::Apc, [0x02, 0x02, 0x02, 0x02])
            .push(OptionKind::Other(10), [0x0a]);

        let body = builder.finish().unwrap();
        let kinds: Vec<_> = OptionsIter::new(&body[2..])
            .map(|item| item.unwrap().kind.to_byte())
            .filter(|kind| *kind != kind::NOP && *kind != kind::EOL)
            .collect();
        assert_eq!(
            kinds,
            [
                kind::FRAG,
                kind::APC,
                kind::MDS,
                kind::MRDS,
                kind::REQ,
                kind::RES,
                10,
                11
            ]
        );
    }

    #[test]
    fn rejects_malformed_fixed_size_options() {
        assert_eq!(
            finish_one(OptionKind::Frag, vec![0; 7]),
            Err(SerializeError::InvalidFixedValueLength {
                kind: kind::FRAG,
                value_len: 7
            })
        );
        assert_eq!(
            finish_one(OptionKind::Apc, vec![0; 3]),
            Err(SerializeError::InvalidFixedValueLength {
                kind: kind::APC,
                value_len: 3
            })
        );
    }

    #[test]
    fn rejects_out_of_scope_assigned_safe_kinds() {
        for raw_kind in [
            kind::TIME,
            kind::AUTH,
            kind::EXP,
            kind::SAFE_RESERVED_MIN,
            kind::SAFE_RESERVED_MAX,
        ] {
            assert_eq!(
                finish_one(OptionKind::Other(raw_kind), vec![]),
                Err(SerializeError::UnsupportedAssignedKind { kind: raw_kind })
            );
        }
    }

    #[test]
    fn rejects_duplicate_frag_options() {
        let mut builder = OptionsBuilder::new();
        builder.push(OptionKind::Frag, [0; 8]).push(OptionKind::Frag, [0; 10]);

        assert_eq!(builder.finish(), Err(SerializeError::DuplicateFrag));
    }

    #[test]
    fn patches_frag_start_to_final_body_len() {
        let body = finish_one(OptionKind::Frag, vec![0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]).unwrap();

        let start = u16::from_be_bytes([body[4], body[5]]);
        assert_eq!(start, u16::from(length::UDP_HEADER) + body.len() as u16);
        assert_eq!(&body[6..12], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn stable_order_is_preserved_for_equal_kinds() {
        let mut builder = OptionsBuilder::new();
        builder
            .push(OptionKind::Other(10), [1])
            .push(OptionKind::Other(10), [2])
            .push(OptionKind::Other(10), [3]);

        let body = builder.finish().unwrap();
        let values: Vec<_> = OptionsIter::new(&body[2..])
            .filter_map(|item| {
                let option = item.unwrap();
                (option.kind.to_byte() == 10).then(|| option.value[0])
            })
            .collect();
        assert_eq!(values, [1, 2, 3]);
    }

    #[test]
    fn inserts_one_nop_before_next_tlv_when_alignment_requires_it() {
        let mut builder = OptionsBuilder::new();
        builder
            .push(OptionKind::Mrds, [0, 0, 1])
            .push(OptionKind::Req, [9, 8, 7, 6]);

        let body = builder.finish().unwrap();
        assert_eq!(
            body,
            vec![
                0,
                0,
                kind::MRDS,
                5,
                0,
                0,
                1,
                kind::NOP,
                kind::REQ,
                6,
                9,
                8,
                7,
                6,
                kind::EOL,
                0
            ]
        );
    }

    #[test]
    fn does_not_insert_nop_before_eol_or_tail_fill() {
        let body = finish_one(OptionKind::Mrds, vec![0, 0, 1]).unwrap();
        assert_eq!(body, vec![0, 0, kind::MRDS, 5, 0, 0, 1, kind::EOL]);
    }
}
