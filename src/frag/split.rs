//! Splitting an oversized datagram into FRAG fragments (the send side).
//!
//! Added in Step 11: each fragment is carried with empty UDP user data (UDP Length 8); the data
//! lives in the surplus area after the FRAG option. Non-terminal fragments use the 10-byte form and
//! the terminal fragment the 12-byte form (carrying the Reassembled-Datagram-Option-Start). The
//! single-fragment (atomic) case is supported, and sizing respects MDS/MRDS.
