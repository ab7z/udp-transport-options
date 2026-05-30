//! Locating the surplus area within an IP datagram.
//!
//! The surplus area runs from the end of the UDP payload (UDP Length) to the end of the IP transport
//! payload. It must begin on a 2-byte boundary relative to the IP datagram; if its natural start is
//! odd, a single zero pad byte precedes the OCS. The computation is added in Step 2.

/// The computed layout of the surplus area relative to the start of the IP datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SurplusLayout {
    /// Byte offset of the surplus area (after any pad), from the start of the IP datagram. Even.
    pub starts_at: usize,
    /// Whether a single zero pad byte precedes the OCS (true when the natural start was odd).
    pub needs_pad: bool,
    /// Length of the surplus area in bytes, including any pad byte and the OCS.
    pub len: usize,
}
