//! The Option Checksum (OCS), RFC 9868 Section 9.
//!
//! Added in Step 6: computation (a two-pass back-patch over the surplus area, treating the OCS field
//! as zero, including the surplus length) and validation (the one's-complement sum over the surplus
//! area must be zero). Built on [`crate::wire::checksum`].
