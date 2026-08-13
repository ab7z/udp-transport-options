//! The Option Checksum (OCS), RFC 9868 Section 9.
//!
//! Added in Step 6: computation (a two-pass back-patch over the surplus area, treating the OCS field
//! as zero, including the surplus length) and validation (the one's-complement sum over the surplus
//! area must be zero). Built on [`crate::wire::checksum`].

use crate::error::ParseError;
use crate::wire::checksum::Checksum;

const OCS_LEN: usize = 2;

/// The OCS-local disposition for the stored checksum field.
///
/// The full receive-side RFC 9868 Section 14 matrix is applied later by the receive pipeline; this
/// enum only reports what the OCS field itself says.
///
/// The Step 10 pipeline must branch on the variant:
///
/// - process the options: [`OcsCheck::Valid`] and [`OcsCheck::Unused`]
/// - ignore the options and discard the surplus area: [`OcsCheck::IgnoreOptions`] and
///   [`OcsCheck::Error`]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcsCheck {
    /// A non-zero OCS validates to one's-complement zero; options are processed.
    Valid,
    /// The OCS is unused because both the OCS and UDP checksum fields are zero.
    ///
    /// RFC 9868 Section 9 treats the surplus area as assumed correct in this case, so options are
    /// still processed.
    Unused,
    /// The OCS is zero while the UDP checksum is non-zero.
    ///
    /// This means the options must be ignored and the surplus area silently discarded.
    IgnoreOptions,
    /// OCS validation failed before the options can be trusted.
    Error(ParseError),
}

/// Back-patches the OCS into an OCS-led body.
///
/// `body` starts at the two-byte OCS field, not at the optional pre-OCS alignment pad. The caller
/// still passes the full surplus-area length, including any pad byte, as `surplus_len`.
pub fn compute(body: &mut [u8], surplus_len: u16) {
    assert!(
        body.len() >= OCS_LEN,
        "OCS-led body must include the two-byte OCS field"
    );

    body[..OCS_LEN].fill(0);

    let mut checksum = Checksum::new();
    checksum.add_slice(body);
    checksum.add_u16(surplus_len);

    let mut ocs = checksum.finish();
    if ocs == 0 {
        ocs = 0xffff;
    }
    body[..OCS_LEN].copy_from_slice(&ocs.to_be_bytes());
}

/// Validates the stored OCS over an OCS-led body.
///
/// `udp_checksum_field` is the raw UDP checksum field from the wire. It is only used for the
/// zero-OCS dispositions.
pub fn validate(body: &[u8], surplus_len: u16, udp_checksum_field: u16) -> OcsCheck {
    if body.len() < OCS_LEN {
        return OcsCheck::Error(ParseError::Overrun { offset: 0 });
    }

    let ocs = u16::from_be_bytes([body[0], body[1]]);
    if ocs == 0 {
        return if udp_checksum_field == 0 {
            OcsCheck::Unused
        } else {
            OcsCheck::IgnoreOptions
        };
    }

    let mut checksum = Checksum::new();
    checksum.add_slice(body);
    checksum.add_u16(surplus_len);
    if checksum.sum() == 0xffff {
        OcsCheck::Valid
    } else {
        OcsCheck::Error(ParseError::OcsMismatch)
    }
}

/// Checks the optional pre-OCS alignment pad byte.
pub fn check_pad(pad: u8, needs_pad: bool) -> Result<(), ParseError> {
    if needs_pad && pad != 0 {
        Err(ParseError::NonZeroPad)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::kind;
    use crate::options::serialize::OptionsBuilder;

    #[test]
    fn empty_canonical_body_patches_and_validates() {
        let mut body = OptionsBuilder::new().finish().unwrap();
        assert_eq!(body, [0, 0, kind::EOL, 0]);

        compute(&mut body, 4);

        assert_ne!(&body[..2], &[0, 0]);
        assert_eq!(validate(&body, 4, 0x1234), OcsCheck::Valid);
    }

    #[test]
    fn minimal_ocs_only_body_validates() {
        let mut body = [0, 0];

        compute(&mut body, 2);

        assert_eq!(body, [0xff, 0xfd]);
        assert_eq!(validate(&body, 2, 0x1234), OcsCheck::Valid);
    }

    #[test]
    fn flipping_any_byte_in_patched_body_fails() {
        let mut body = OptionsBuilder::new().finish().unwrap();
        compute(&mut body, 4);

        for i in 0..body.len() {
            let mut corrupted = body.clone();
            corrupted[i] ^= 0x01;
            assert_eq!(
                validate(&corrupted, 4, 0x1234),
                OcsCheck::Error(ParseError::OcsMismatch)
            );
        }
    }

    #[test]
    fn forced_zero_is_sent_as_ffff_and_validates() {
        let mut body = [0, 0, 0xff, 0xfb];

        compute(&mut body, 4);

        assert_eq!(&body[..2], &[0xff, 0xff]);
        assert_eq!(validate(&body, 4, 0x1234), OcsCheck::Valid);
    }

    #[test]
    fn odd_start_uses_full_surplus_len_but_starts_sum_at_ocs() {
        let mut body = OptionsBuilder::new().finish().unwrap();

        compute(&mut body, 5);

        assert_eq!(check_pad(0, true), Ok(()));
        assert_eq!(validate(&body, 5, 0x1234), OcsCheck::Valid);
        assert_eq!(
            validate(&body, body.len() as u16, 0x1234),
            OcsCheck::Error(ParseError::OcsMismatch)
        );
    }

    #[test]
    fn zero_ocs_disposition_depends_on_udp_checksum_field() {
        let body = [0, 0, kind::EOL, 0];

        assert_eq!(validate(&body, 4, 0), OcsCheck::Unused);
        assert_eq!(validate(&body, 4, 1), OcsCheck::IgnoreOptions);
    }

    #[test]
    fn too_short_validate_input_is_overrun() {
        assert_eq!(validate(&[], 0, 1), OcsCheck::Error(ParseError::Overrun { offset: 0 }));
        assert_eq!(validate(&[0], 1, 1), OcsCheck::Error(ParseError::Overrun { offset: 0 }));
    }

    #[test]
    fn pad_check_rejects_only_present_nonzero_pad() {
        assert_eq!(check_pad(0, true), Ok(()));
        assert_eq!(check_pad(1, true), Err(ParseError::NonZeroPad));
        assert_eq!(check_pad(1, false), Ok(()));
    }

    // Golden vectors, derived by hand from RFC 9868 Section 9 before running them against this
    // implementation: fold 16-bit big-endian words starting at the OCS field (the optional pad
    // byte sits on the far side of the 2-byte grid and contributes nothing), add the full surplus
    // length including any pad, invert. The expected constants below come from that manual
    // arithmetic (cross-checked with an independent Python fold), not from `Checksum`, so a
    // folding error shared by `compute` and `validate` cannot mask itself here. Every vector keeps
    // the folded sum non-palindromic, so the byte-swapped sum of a one-byte mis-grouping (the
    // error class the wire-checker odd-pad bug fell into) cannot validate.

    #[test]
    fn golden_even_start_tlv_body() {
        // Sum: 0xdead + 0xbeef -> 0x9d9d (end-around carry); + 0x0100 -> 0x9e9d;
        // + len 0x0008 -> 0x9ea5. OCS = !0x9ea5 = 0x615a.
        let mut body = [0, 0, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x00];
        compute(&mut body, 8);

        assert_eq!(&body[..2], &[0x61, 0x5a]);
        assert_eq!(validate(&body, 8, 0x1234), OcsCheck::Valid);

        let mut swapped = body;
        swapped.swap(0, 1);
        assert_eq!(validate(&swapped, 8, 0x1234), OcsCheck::Error(ParseError::OcsMismatch));
    }

    #[test]
    fn golden_odd_start_pad_in_length_not_in_fold() {
        // Surplus layout: one pad byte, OCS, options 0x01 0x02 0x03 0x04; surplus_len = 1 + 2 + 4.
        // Sum: 0x0102 + 0x0304 = 0x0406; + len 0x0007 -> 0x040d. OCS = !0x040d = 0xfbf2.
        let mut body = [0, 0, 0x01, 0x02, 0x03, 0x04];
        compute(&mut body, 7);

        assert_eq!(&body[..2], &[0xfb, 0xf2]);
        assert_eq!(validate(&body, 7, 0x1234), OcsCheck::Valid);
        // Forgetting the pad byte in the length must fail validation.
        assert_eq!(validate(&body, 6, 0x1234), OcsCheck::Error(ParseError::OcsMismatch));

        let mut swapped = body;
        swapped.swap(0, 1);
        assert_eq!(validate(&swapped, 7, 0x1234), OcsCheck::Error(ParseError::OcsMismatch));
    }

    #[test]
    fn golden_dangling_tail_byte_is_high_byte() {
        // Sum: 0xab00 (a trailing odd byte is the high byte of the final word) + len 0x0003
        // -> 0xab03. OCS = !0xab03 = 0x54fc.
        let mut body = [0, 0, 0xab];
        compute(&mut body, 3);

        assert_eq!(&body[..2], &[0x54, 0xfc]);
        assert_eq!(validate(&body, 3, 0x1234), OcsCheck::Valid);

        let mut swapped = body;
        swapped.swap(0, 1);
        assert_eq!(validate(&swapped, 3, 0x1234), OcsCheck::Error(ParseError::OcsMismatch));
    }
}
