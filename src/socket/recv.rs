//! The raw receive path (Linux, `SOCK_RAW` `IPPROTO_UDP`).
//!
//! Added in Step 8: read full IP datagrams with the surplus area intact, filter by destination port,
//! and hand the bytes to the receive pipeline. Mitigates raw-socket noise (own-source copies and
//! ICMP port-unreachable when no normal UDP socket is bound).
