//! The raw send path (Linux, `IP_HDRINCL`).
//!
//! Added in Step 8: build the IP header, UDP header (with UDP Length < IP Total Length to create the
//! surplus area), and the surplus area; compute the UDP checksum and the OCS by hand; and transmit.
