// Shared TLV parser invariant oracle.
//
// Used by `mod common_options;` from the property tests and spliced into the `options_tlv` fuzz
// target via `include!`. The oracle stays at the parser boundary: it checks totality, halt
// behavior, exact borrowed value ranges, and NOP-run accounting without applying receive-pipeline
// policy.

use udp_transport_options::error::ParseError;
use udp_transport_options::model::kind;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::parse::OptionsIter;

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
