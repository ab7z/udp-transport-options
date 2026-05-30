//! The public API.
//!
//! Added in Step 13. Two tiers are planned:
//!
//! - a **low-level** API that lets the caller set and read explicit options on individual datagrams,
//!   and
//! - a **high-level** peer that sends and receives payloads with typed options, applying the OCS and
//!   fragmentation/reassembly transparently.
