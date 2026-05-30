//! The zero-copy TLV parser.
//!
//! [`OptionRef`] borrows the surplus bytes; the iterator that produces it (validating Length and
//! bounds, handling the extended-length form, terminating on EOL, and reporting a single error on
//! malformed input) is added in Step 4.

use super::kind::OptionKind;

/// A borrowed view of one parsed option: its Kind and its value bytes (excluding framing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptionRef<'a> {
    /// The option Kind.
    pub kind: OptionKind,
    /// The option's value bytes (no Kind/Length framing); empty for EOL and NOP.
    pub value: &'a [u8],
}
