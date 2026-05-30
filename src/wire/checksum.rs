//! The one's-complement Internet checksum (RFC 1071).
//!
//! Implemented in Step 1. This primitive backs both the UDP checksum and the RFC 9868 Option
//! Checksum (OCS), so it is hand-rolled rather than pulled from a crate.
