//! The pure receive pipeline.
//!
//! This module is deliberately free of I/O so it can be unit-tested without `CAP_NET_RAW`. It holds
//! the bulk of the receive-side correctness: the RFC 9868 processing order (verify the UDP checksum,
//! locate and validate the surplus area, validate the OCS, parse the options, then either reassemble
//! a fragment or deliver the payload). The `process_datagram` function is added in Step 10.

use crate::options::RawOption;

/// The outcome of processing one received datagram.
#[derive(Debug)]
pub enum Delivery {
    /// The payload to hand to the application, with any successfully parsed options.
    Payload {
        /// The UDP user data.
        data: Vec<u8>,
        /// Parsed options (empty if the surplus area was absent or its options were discarded).
        options: Vec<RawOption>,
    },
    /// The datagram was a fragment; it was buffered and there is nothing to deliver yet.
    Buffered,
}
