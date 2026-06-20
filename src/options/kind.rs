//! The option Kind and its SAFE/UNSAFE and must-support classification.
//!
//! The mapping to and from the raw Kind byte and the classification predicates are backed by the
//! constants in [`crate::model::kind`].

use crate::model::{kind, length};

const NO_FIXED_LENGTHS: &[u8] = &[];
const APC_LENGTHS: &[u8] = &[length::APC];
const FRAG_LENGTHS: &[u8] = &[length::FRAG_NON_TERMINAL, length::FRAG_TERMINAL];
const MDS_LENGTHS: &[u8] = &[length::MDS];
const MRDS_LENGTHS: &[u8] = &[length::MRDS];
const REQ_LENGTHS: &[u8] = &[length::REQ];
const RES_LENGTHS: &[u8] = &[length::RES];

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

/// The framing shape selected by an option Kind byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptionFraming {
    /// EOL and NOP: Kind byte only, no Length field.
    SingleByte,
    /// All other Kinds: Kind + Length + Value. The extended form is selected by the Length field.
    LengthDelimited,
}

impl OptionKind {
    /// Maps a raw Kind byte to the corresponding named variant or [`OptionKind::Other`].
    pub const fn from_byte(byte: u8) -> Self {
        match byte {
            kind::EOL => Self::Eol,
            kind::NOP => Self::Nop,
            kind::APC => Self::Apc,
            kind::FRAG => Self::Frag,
            kind::MDS => Self::Mds,
            kind::MRDS => Self::Mrds,
            kind::REQ => Self::Req,
            kind::RES => Self::Res,
            other => Self::Other(other),
        }
    }

    /// Returns the raw Kind byte represented by this value.
    pub const fn to_byte(self) -> u8 {
        match self {
            Self::Eol => kind::EOL,
            Self::Nop => kind::NOP,
            Self::Apc => kind::APC,
            Self::Frag => kind::FRAG,
            Self::Mds => kind::MDS,
            Self::Mrds => kind::MRDS,
            Self::Req => kind::REQ,
            Self::Res => kind::RES,
            Self::Other(byte) => byte,
        }
    }

    /// Returns true when the raw Kind byte is in the SAFE range (`0..=191`).
    pub const fn is_safe(self) -> bool {
        self.to_byte() < kind::UNSAFE_MIN
    }

    /// Returns true when the raw Kind byte is in the UNSAFE range (`192..=255`).
    pub const fn is_unsafe(self) -> bool {
        !self.is_safe()
    }

    /// Returns true for the RFC 9868 must-support Kind range (`0..=7`).
    pub const fn is_must_support(self) -> bool {
        self.to_byte() <= kind::RES
    }

    /// Returns the framing shape selected by this Kind byte.
    pub const fn framing(self) -> OptionFraming {
        match self.to_byte() {
            kind::EOL | kind::NOP => OptionFraming::SingleByte,
            _ => OptionFraming::LengthDelimited,
        }
    }

    /// Returns true for the single-byte EOL and NOP options.
    pub const fn is_single_byte(self) -> bool {
        matches!(self.framing(), OptionFraming::SingleByte)
    }

    /// Returns the allowed fixed total TLV lengths for fixed-size Kinds.
    ///
    /// EOL and NOP are single-byte options, not TLVs, so they return an empty slice. Unknown Kinds
    /// likewise have no fixed expected length at this layer.
    pub const fn fixed_tlv_lengths(self) -> &'static [u8] {
        match self.to_byte() {
            kind::APC => APC_LENGTHS,
            kind::FRAG => FRAG_LENGTHS,
            kind::MDS => MDS_LENGTHS,
            kind::MRDS => MRDS_LENGTHS,
            kind::REQ => REQ_LENGTHS,
            kind::RES => RES_LENGTHS,
            _ => NO_FIXED_LENGTHS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{OptionFraming, OptionKind};
    use crate::model::{kind, length};

    #[test]
    fn from_byte_maps_named_kinds() {
        let cases = [
            (kind::EOL, OptionKind::Eol),
            (kind::NOP, OptionKind::Nop),
            (kind::APC, OptionKind::Apc),
            (kind::FRAG, OptionKind::Frag),
            (kind::MDS, OptionKind::Mds),
            (kind::MRDS, OptionKind::Mrds),
            (kind::REQ, OptionKind::Req),
            (kind::RES, OptionKind::Res),
        ];

        for (byte, expected) in cases {
            assert_eq!(OptionKind::from_byte(byte), expected);
            assert_eq!(expected.to_byte(), byte);
        }
    }

    #[test]
    fn all_kind_bytes_round_trip_exactly() {
        for byte in 0..=u8::MAX {
            assert_eq!(OptionKind::from_byte(byte).to_byte(), byte);
        }
    }

    #[test]
    fn unknown_boundaries_are_preserved_as_other() {
        for byte in [8, 191, 192, 255] {
            assert_eq!(OptionKind::from_byte(byte), OptionKind::Other(byte));
            assert_eq!(OptionKind::from_byte(byte).to_byte(), byte);
        }
    }

    #[test]
    fn safe_and_unsafe_boundary_is_exact() {
        assert!(OptionKind::from_byte(191).is_safe());
        assert!(!OptionKind::from_byte(191).is_unsafe());
        assert!(!OptionKind::from_byte(192).is_safe());
        assert!(OptionKind::from_byte(192).is_unsafe());

        for byte in 0..=u8::MAX {
            let kind = OptionKind::from_byte(byte);
            assert_eq!(kind.is_safe(), byte < kind::UNSAFE_MIN);
            assert_eq!(kind.is_unsafe(), byte >= kind::UNSAFE_MIN);
        }
    }

    #[test]
    fn must_support_boundary_is_exact() {
        assert!(OptionKind::from_byte(7).is_must_support());
        assert!(!OptionKind::from_byte(8).is_must_support());

        for byte in 0..=u8::MAX {
            assert_eq!(OptionKind::from_byte(byte).is_must_support(), byte <= kind::RES);
        }
    }

    #[test]
    fn only_eol_and_nop_are_single_byte() {
        for byte in 0..=u8::MAX {
            let kind = OptionKind::from_byte(byte);
            let is_single_byte = byte == kind::EOL || byte == kind::NOP;
            assert_eq!(
                kind.framing(),
                if is_single_byte {
                    OptionFraming::SingleByte
                } else {
                    OptionFraming::LengthDelimited
                }
            );
            assert_eq!(kind.is_single_byte(), is_single_byte);
        }
    }

    #[test]
    fn fixed_tlv_lengths_match_must_support_table() {
        assert_eq!(OptionKind::Apc.fixed_tlv_lengths(), &[length::APC]);
        assert_eq!(
            OptionKind::Frag.fixed_tlv_lengths(),
            &[length::FRAG_NON_TERMINAL, length::FRAG_TERMINAL]
        );
        assert_eq!(OptionKind::Mds.fixed_tlv_lengths(), &[length::MDS]);
        assert_eq!(OptionKind::Mrds.fixed_tlv_lengths(), &[length::MRDS]);
        assert_eq!(OptionKind::Req.fixed_tlv_lengths(), &[length::REQ]);
        assert_eq!(OptionKind::Res.fixed_tlv_lengths(), &[length::RES]);
        assert_eq!(OptionKind::Eol.fixed_tlv_lengths(), &[]);
        assert_eq!(OptionKind::Nop.fixed_tlv_lengths(), &[]);
        assert_eq!(OptionKind::Other(8).fixed_tlv_lengths(), &[]);
        assert_eq!(OptionKind::Other(191).fixed_tlv_lengths(), &[]);
        assert_eq!(OptionKind::Other(192).fixed_tlv_lengths(), &[]);
        assert_eq!(OptionKind::Other(255).fixed_tlv_lengths(), &[]);
    }

    #[test]
    fn manual_other_values_classify_by_raw_byte() {
        assert!(OptionKind::Other(kind::EOL).is_single_byte());
        assert!(OptionKind::Other(kind::RES).is_must_support());
        assert_eq!(
            OptionKind::Other(kind::FRAG).fixed_tlv_lengths(),
            &[length::FRAG_NON_TERMINAL, length::FRAG_TERMINAL]
        );
        assert!(OptionKind::Other(191).is_safe());
        assert!(OptionKind::Other(192).is_unsafe());
    }
}
