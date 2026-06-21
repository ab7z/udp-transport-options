// Shared TLV parser invariant oracle.
//
// Used by `mod common_options;` from the property tests and spliced into the `options_tlv` fuzz
// target via `include!`. The oracle stays at the parser boundary: it checks totality, halt
// behavior, exact borrowed value ranges, and NOP-run accounting without applying receive-pipeline
// policy.

use udp_transport_options::error::ParseError;
use udp_transport_options::model::{kind, length};
use udp_transport_options::options::RawOption;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::parse::OptionsIter;
use udp_transport_options::options::serialize::OptionsBuilder;

struct ExpectedOption {
    kind: OptionKind,
    value_start: Option<usize>,
    value_end: usize,
    next_pos: usize,
    is_eol: bool,
}

enum ExpectedStep {
    Done,
    Option(ExpectedOption),
    Error(ParseError),
}

fn expected_step(bytes: &[u8], pos: usize) -> ExpectedStep {
    if pos >= bytes.len() {
        return ExpectedStep::Done;
    }

    let raw_kind = bytes[pos];
    let option_kind = OptionKind::from_byte(raw_kind);
    match raw_kind {
        kind::EOL => ExpectedStep::Option(ExpectedOption {
            kind: option_kind,
            value_start: None,
            value_end: pos + 1,
            next_pos: pos + 1,
            is_eol: true,
        }),
        kind::NOP => ExpectedStep::Option(ExpectedOption {
            kind: option_kind,
            value_start: None,
            value_end: pos + 1,
            next_pos: pos + 1,
            is_eol: false,
        }),
        _ => {
            let Some(len_byte) = bytes.get(pos + 1).copied() else {
                return ExpectedStep::Error(ParseError::Overrun { offset: pos });
            };

            if len_byte == kind::EXTENDED_LENGTH_MARKER {
                if pos + 4 > bytes.len() {
                    return ExpectedStep::Error(ParseError::Overrun { offset: pos });
                }

                let total_len = u16::from_be_bytes([bytes[pos + 2], bytes[pos + 3]]) as usize;
                if total_len < usize::from(kind::EXTENDED_LENGTH_MARKER) {
                    return ExpectedStep::Error(ParseError::InvalidLength {
                        kind: raw_kind,
                        len: total_len,
                    });
                }

                let end = pos + total_len;
                if end > bytes.len() {
                    return ExpectedStep::Error(ParseError::Overrun { offset: pos });
                }

                ExpectedStep::Option(ExpectedOption {
                    kind: option_kind,
                    value_start: Some(pos + 4),
                    value_end: end,
                    next_pos: end,
                    is_eol: false,
                })
            } else {
                let total_len = usize::from(len_byte);
                if total_len < 2 {
                    return ExpectedStep::Error(ParseError::InvalidLength {
                        kind: raw_kind,
                        len: total_len,
                    });
                }

                let end = pos + total_len;
                if end > bytes.len() {
                    return ExpectedStep::Error(ParseError::Overrun { offset: pos });
                }

                ExpectedStep::Option(ExpectedOption {
                    kind: option_kind,
                    value_start: Some(pos + 2),
                    value_end: end,
                    next_pos: end,
                    is_eol: false,
                })
            }
        }
    }
}

/// Asserts parser invariants over arbitrary option bytes after the OCS field.
///
/// Returns silently for malformed input after confirming that the iterator reports exactly one
/// error and then halts. Arbitrary fuzz input must never panic or loop forever.
pub fn check_tlv_parser_invariants(bytes: &[u8]) {
    let mut iter = OptionsIter::new(bytes);
    let mut yielded = 0usize;
    let mut current_nop_run = 0usize;
    let mut max_nop_run = 0usize;
    let base = bytes.as_ptr() as usize;
    let mut expected_pos = 0usize;

    loop {
        match expected_step(bytes, expected_pos) {
            ExpectedStep::Done => {
                assert_eq!(iter.next(), None);
                assert_eq!(iter.max_nop_run(), max_nop_run);
                return;
            }
            ExpectedStep::Option(expected) => {
                yielded += 1;
                assert!(yielded <= bytes.len() + 1);

                let item = iter.next().expect("expected parser item");
                let option = item.expect("expected valid parser item");
                assert_eq!(option.kind, expected.kind);
                assert!(expected.next_pos > expected_pos);

                match expected.value_start {
                    Some(value_start) => {
                        assert_eq!(option.value.as_ptr() as usize, base + value_start);
                        assert_eq!(option.value, &bytes[value_start..expected.value_end]);
                    }
                    None => {
                        assert!(option.value.is_empty());
                    }
                }

                match option.kind {
                    OptionKind::Nop => {
                        current_nop_run += 1;
                        max_nop_run = max_nop_run.max(current_nop_run);
                    }
                    _ => current_nop_run = 0,
                }
                assert_eq!(iter.max_nop_run(), max_nop_run);

                expected_pos = expected.next_pos;
                if expected.is_eol {
                    assert_eq!(iter.next(), None);
                    assert_eq!(iter.max_nop_run(), max_nop_run);
                    return;
                }
            }
            ExpectedStep::Error(expected) => {
                yielded += 1;
                assert!(yielded <= bytes.len() + 1);
                assert_eq!(iter.next(), Some(Err(expected)));
                assert_eq!(iter.next(), None);
                assert_eq!(iter.max_nop_run(), max_nop_run);
                return;
            }
        }
    }
}

#[allow(dead_code)]
fn canonical_rank(raw_kind: u8) -> (u16, u8) {
    let rank = match raw_kind {
        kind::FRAG => 0,
        kind::APC => 1,
        kind::MDS => 2,
        kind::MRDS => 3,
        kind::REQ => 4,
        kind::RES => 5,
        other => 1000 + u16::from(other),
    };
    (rank, raw_kind)
}

#[allow(dead_code)]
fn is_builder_accepted(option: &RawOption) -> bool {
    let raw_kind = option.kind.to_byte();
    raw_kind != kind::EOL
        && raw_kind != kind::NOP
        && raw_kind < kind::UNSAFE_MIN
        && !is_out_of_scope_assigned_safe_kind(raw_kind)
        && has_valid_fixed_value_len(raw_kind, option.value.len())
}

#[allow(dead_code)]
fn is_out_of_scope_assigned_safe_kind(raw_kind: u8) -> bool {
    matches!(
        raw_kind,
        kind::TIME | kind::AUTH | kind::EXP | kind::SAFE_RESERVED_MIN..=kind::SAFE_RESERVED_MAX
    )
}

#[allow(dead_code)]
fn has_valid_fixed_value_len(raw_kind: u8, value_len: usize) -> bool {
    match raw_kind {
        kind::APC => value_len == length::APC as usize - 2,
        kind::FRAG => {
            value_len == length::FRAG_NON_TERMINAL as usize - 2 || value_len == length::FRAG_TERMINAL as usize - 2
        }
        kind::MDS => value_len == length::MDS as usize - 2,
        kind::MRDS => value_len == length::MRDS as usize - 2,
        kind::REQ => value_len == length::REQ as usize - 2,
        kind::RES => value_len == length::RES as usize - 2,
        _ => true,
    }
}

#[allow(dead_code)]
fn encoded_len(value_len: usize) -> usize {
    if value_len <= 252 { value_len + 2 } else { value_len + 4 }
}

#[allow(dead_code)]
fn serialized_body_len_for_oracle(options: &[RawOption]) -> Option<usize> {
    let mut len = length::OCS as usize;
    for option in options {
        if len % 2 == 1 {
            len = len.checked_add(1)?;
        }
        len = len.checked_add(encoded_len(option.value.len()))?;
    }

    len = len.checked_add(1)?;
    if len % 2 == 1 {
        len = len.checked_add(1)?;
    }
    Some(len)
}

#[allow(dead_code)]
fn patch_frag_start_for_oracle(options: &mut [RawOption]) -> Option<()> {
    let body_len = serialized_body_len_for_oracle(options)?;
    let start = u16::try_from(length::UDP_HEADER as usize + body_len).ok()?;
    for option in options {
        if option.kind.to_byte() == kind::FRAG {
            option.value[..2].copy_from_slice(&start.to_be_bytes());
        }
    }
    Some(())
}

#[allow(dead_code)]
pub fn canonical_semantic_options(options: &[RawOption]) -> Option<Vec<RawOption>> {
    let mut seen_frag = false;
    for option in options {
        if !is_builder_accepted(option) {
            return None;
        }
        if option.kind.to_byte() == kind::FRAG {
            if seen_frag {
                return None;
            }
            seen_frag = true;
        }
    }

    let mut indexed: Vec<_> = options.iter().enumerate().collect();
    indexed.sort_by_key(|(_, option)| canonical_rank(option.kind.to_byte()));
    let mut sorted: Vec<_> = indexed
        .into_iter()
        .map(|(_, option)| RawOption {
            kind: OptionKind::from_byte(option.kind.to_byte()),
            value: option.value.clone(),
        })
        .collect();
    patch_frag_start_for_oracle(&mut sorted)?;
    Some(sorted)
}

#[allow(dead_code)]
pub fn finish_raw_options(options: Vec<RawOption>) -> Option<Vec<u8>> {
    let mut builder = OptionsBuilder::new();
    builder.extend_raw(options);
    builder.finish().ok()
}

#[allow(dead_code)]
pub fn parsed_semantic_options(body: &[u8]) -> Vec<RawOption> {
    assert!(body.len() >= 2);
    assert_eq!(&body[..2], &[0, 0]);

    let mut parsed = Vec::new();
    for item in OptionsIter::new(&body[2..]) {
        let option = item.expect("serializer output must parse");
        match option.kind.to_byte() {
            kind::EOL | kind::NOP => {}
            _ => parsed.push(option.into()),
        }
    }
    parsed
}

#[allow(dead_code)]
pub fn check_serializer_invariants(options: Vec<RawOption>) {
    let Some(body) = finish_raw_options(options.clone()) else {
        return;
    };

    assert_eq!(&body[..2], &[0, 0]);
    assert_eq!(body.len() % 2, 0);
    check_tlv_parser_invariants(&body[2..]);

    let expected = canonical_semantic_options(&options).expect("accepted serialized options");
    assert_eq!(parsed_semantic_options(&body), expected);
}

#[allow(dead_code)]
pub fn raw_options_from_fuzz_bytes(bytes: &[u8]) -> Vec<RawOption> {
    let mut options = Vec::new();
    let mut pos = 0usize;

    while pos + 3 <= bytes.len() && options.len() < 4 {
        let raw_kind = bytes[pos];
        let value_len = (usize::from(bytes[pos + 1]) | (usize::from(bytes[pos + 2] & 0x01) << 8)).min(260);
        pos += 3;

        let available = bytes.len() - pos;
        let take = value_len.min(available);
        options.push(RawOption {
            kind: OptionKind::from_byte(raw_kind),
            value: bytes[pos..pos + take].to_vec(),
        });
        pos += take;
    }

    options
}
