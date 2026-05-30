//! UDP Options: Kind classification, the zero-copy parser, the serializer, the OCS, and typed
//! option values.
//!
//! The design rule is *parse borrowed, decode owned*: the parser yields [`parse::OptionRef`] values
//! that borrow the surplus bytes, while [`RawOption`] and the typed values in [`typed`] are owned and
//! never carry a lifetime across the public API boundary.

pub mod kind;
pub mod ocs;
pub mod parse;
pub mod serialize;
pub mod typed;

use kind::OptionKind;

/// An owned option (Kind plus value bytes): the owned counterpart of [`parse::OptionRef`].
///
/// The value excludes the Kind/Length framing and is empty for [`OptionKind::Eol`] and
/// [`OptionKind::Nop`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawOption {
    /// The option Kind.
    pub kind: OptionKind,
    /// The option's value bytes (no framing).
    pub value: Vec<u8>,
}
