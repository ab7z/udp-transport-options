//! The zero-copy TLV parser.
//!
//! [`OptionRef`] borrows the surplus bytes; the iterator that produces it (validating Length and
//! bounds, handling the extended-length form, terminating on EOL, and reporting a single error on
//! malformed input) is total and allocation-free.

use super::kind::OptionKind;
use crate::error::ParseError;
use crate::model::kind;

/// A borrowed view of one parsed option: its Kind and its value bytes (excluding framing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionRef<'a> {
    /// The option Kind.
    pub kind: OptionKind,
    /// The option's value bytes (no Kind/Length framing); empty for EOL and NOP.
    pub value: &'a [u8],
}

/// A zero-copy iterator over the TLV option bytes after the OCS field.
#[derive(Debug, Clone)]
pub struct OptionsIter<'a> {
    bytes: &'a [u8],
    pos: usize,
    done: bool,
    current_nop_run: usize,
    max_nop_run: usize,
}

impl<'a> OptionsIter<'a> {
    /// Creates an iterator over the option bytes after the OCS field.
    pub const fn new(options_bytes: &'a [u8]) -> Self {
        Self {
            bytes: options_bytes,
            pos: 0,
            done: false,
            current_nop_run: 0,
            max_nop_run: 0,
        }
    }

    /// Returns the largest consecutive NOP run observed so far.
    pub const fn max_nop_run(&self) -> usize {
        self.max_nop_run
    }

    fn fail(&mut self, error: ParseError) -> Option<Result<OptionRef<'a>, ParseError>> {
        self.done = true;
        Some(Err(error))
    }

    fn value_slice(&mut self, start: usize, header_len: usize, total_len: usize) -> &'a [u8] {
        self.pos = start + total_len;
        self.current_nop_run = 0;
        &self.bytes[start + header_len..start + total_len]
    }
}

impl<'a> Iterator for OptionsIter<'a> {
    type Item = Result<OptionRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.pos >= self.bytes.len() {
            return None;
        }

        let start = self.pos;
        let raw_kind = self.bytes[start];
        let option_kind = OptionKind::from_byte(raw_kind);

        match raw_kind {
            kind::EOL => {
                self.pos += 1;
                self.current_nop_run = 0;
                self.done = true;
                Some(Ok(OptionRef {
                    kind: option_kind,
                    value: &[],
                }))
            }
            kind::NOP => {
                self.pos += 1;
                self.current_nop_run += 1;
                self.max_nop_run = self.max_nop_run.max(self.current_nop_run);
                Some(Ok(OptionRef {
                    kind: option_kind,
                    value: &[],
                }))
            }
            _ => {
                let Some(len_byte) = self.bytes.get(start + 1).copied() else {
                    return self.fail(ParseError::Overrun { offset: start });
                };

                if len_byte == kind::EXTENDED_LENGTH_MARKER {
                    if start + 4 > self.bytes.len() {
                        return self.fail(ParseError::Overrun { offset: start });
                    }

                    let total_len = u16::from_be_bytes([self.bytes[start + 2], self.bytes[start + 3]]) as usize;
                    if total_len < usize::from(kind::EXTENDED_LENGTH_MARKER) {
                        return self.fail(ParseError::InvalidLength {
                            kind: raw_kind,
                            len: total_len,
                        });
                    }

                    let end = start + total_len;
                    if end > self.bytes.len() {
                        return self.fail(ParseError::Overrun { offset: start });
                    }

                    let value = self.value_slice(start, 4, total_len);
                    Some(Ok(OptionRef {
                        kind: option_kind,
                        value,
                    }))
                } else {
                    let total_len = usize::from(len_byte);
                    if total_len < 2 {
                        return self.fail(ParseError::InvalidLength {
                            kind: raw_kind,
                            len: total_len,
                        });
                    }

                    let end = start + total_len;
                    if end > self.bytes.len() {
                        return self.fail(ParseError::Overrun { offset: start });
                    }

                    let value = self.value_slice(start, 2, total_len);
                    Some(Ok(OptionRef {
                        kind: option_kind,
                        value,
                    }))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OptionRef, OptionsIter};
    use crate::error::ParseError;
    use crate::model::kind;
    use crate::options::kind::OptionKind;

    fn assert_single_error(bytes: &[u8], expected: ParseError) {
        let mut iter = OptionsIter::new(bytes);
        assert_eq!(iter.next(), Some(Err(expected)));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn accepts_empty_input() {
        let mut iter = OptionsIter::new(&[]);
        assert_eq!(iter.next(), None);
        assert_eq!(iter.max_nop_run(), 0);
    }

    #[test]
    fn parses_mixed_default_extended_and_eol() {
        let mut bytes = vec![kind::NOP, kind::APC, 3, 0xaa, 200, kind::EXTENDED_LENGTH_MARKER, 0, 255];
        let ext_value_at = bytes.len();
        bytes.extend((0..251).map(|i| i as u8));
        bytes.extend_from_slice(&[kind::EOL, kind::APC]);

        let mut iter = OptionsIter::new(&bytes);
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Nop,
                value: &[]
            }))
        );
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Apc,
                value: &[0xaa]
            }))
        );
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Other(200),
                value: &bytes[ext_value_at..ext_value_at + 251]
            }))
        );
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Eol,
                value: &[]
            }))
        );
        assert_eq!(iter.next(), None);
        assert_eq!(iter.max_nop_run(), 1);
    }

    #[test]
    fn accepts_exact_end_without_eol() {
        let bytes = [kind::APC, 2, kind::MDS, 4, 0x12, 0x34];
        let mut iter = OptionsIter::new(&bytes);
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Apc,
                value: &[]
            }))
        );
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Mds,
                value: &[0x12, 0x34]
            }))
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn tracks_maximum_nop_run() {
        let bytes = [
            kind::NOP,
            kind::NOP,
            kind::APC,
            2,
            kind::NOP,
            kind::NOP,
            kind::NOP,
            kind::EOL,
        ];
        let mut iter = OptionsIter::new(&bytes);
        while iter.next().is_some() {}
        assert_eq!(iter.max_nop_run(), 3);
    }

    #[test]
    fn preserves_maximum_nop_run_after_error() {
        let bytes = [kind::NOP, kind::NOP, kind::APC];
        let mut iter = OptionsIter::new(&bytes);
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Nop,
                value: &[]
            }))
        );
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Nop,
                value: &[]
            }))
        );
        assert_eq!(iter.next(), Some(Err(ParseError::Overrun { offset: 2 })));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.max_nop_run(), 2);
    }

    #[test]
    fn preserves_unknown_safe_and_unsafe_kinds() {
        let bytes = [8, 2, 192, 2];
        let mut iter = OptionsIter::new(&bytes);
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Other(8),
                value: &[]
            }))
        );
        assert_eq!(
            iter.next(),
            Some(Ok(OptionRef {
                kind: OptionKind::Other(192),
                value: &[]
            }))
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn malformed_default_forms_yield_one_error() {
        assert_single_error(&[kind::APC], ParseError::Overrun { offset: 0 });
        assert_single_error(
            &[kind::APC, 1],
            ParseError::InvalidLength {
                kind: kind::APC,
                len: 1,
            },
        );
        assert_single_error(&[kind::APC, 3], ParseError::Overrun { offset: 0 });
    }

    #[test]
    fn malformed_extended_forms_yield_one_error() {
        assert_single_error(
            &[kind::APC, kind::EXTENDED_LENGTH_MARKER, 0],
            ParseError::Overrun { offset: 0 },
        );
        assert_single_error(
            &[kind::APC, kind::EXTENDED_LENGTH_MARKER, 0, 254],
            ParseError::InvalidLength {
                kind: kind::APC,
                len: 254,
            },
        );
        assert_single_error(
            &[kind::APC, kind::EXTENDED_LENGTH_MARKER, 1, 0, 0],
            ParseError::Overrun { offset: 0 },
        );
    }
}
