//! The option Kind and its SAFE/UNSAFE and must-support classification.
//!
//! The mapping to and from the raw Kind byte and the classification predicates are added in Step 3
//! (backed by the constants in [`crate::model::kind`]).

/// A UDP option Kind.
///
/// The named variants are the must-support options of RFC 9868; any other Kind byte (assigned or
/// not) is carried in [`OptionKind::Other`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionKind {
    /// End of Options List (Kind 0).
    Eol,
    /// No Operation (Kind 1).
    Nop,
    /// Additional Payload Checksum (Kind 2).
    Apc,
    /// Fragmentation (Kind 3).
    Frag,
    /// Maximum Datagram Size (Kind 4).
    Mds,
    /// Maximum Reassembled Datagram Size (Kind 5).
    Mrds,
    /// Echo Request (Kind 6).
    Req,
    /// Echo Response (Kind 7).
    Res,
    /// Any other Kind, carrying its raw Kind byte.
    Other(u8),
}
