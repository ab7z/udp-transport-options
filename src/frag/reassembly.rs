//! Reassembling FRAG fragments (the receive side).
//!
//! Added in Step 12: a cache keyed by [`FragKey`], with offset-sorted insertion, overlap detection,
//! a timeout, garbage collection, and per-socket-pair and global DoS limits. A completed datagram is
//! re-fed into the receive pipeline once (a reassembled datagram must not itself carry FRAG).

use std::net::IpAddr;

/// The reassembly key: the UDP 5-tuple plus the FRAG Identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragKey {
    /// Source IP address.
    pub src: IpAddr,
    /// Destination IP address.
    pub dst: IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// FRAG Identification shared by all fragments of one original datagram.
    pub identification: u32,
}

/// The result of feeding one fragment into the reassembly cache.
#[derive(Debug)]
pub enum ReassemblyOutcome {
    /// More fragments are needed; nothing to deliver yet.
    Incomplete,
    /// Reassembly completed; the owned, reconstructed datagram is returned for re-processing.
    Complete(Vec<u8>),
    /// Reassembly was aborted and the partial state discarded.
    Abort(AbortReason),
}

/// Why a reassembly was aborted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortReason {
    /// A fragment overlapped previously received data.
    Overlap,
    /// A per-pair or global reassembly limit was exceeded.
    LimitExceeded,
    /// The reassembly timed out.
    Timeout,
}
