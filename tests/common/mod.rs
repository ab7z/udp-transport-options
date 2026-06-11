// Shared wire-layer joint-invariant oracle.
//
// Used by `mod common;` from the integration tests and spliced verbatim into the `wire_datagram`
// fuzz target via `include!` (which is why this file carries no `//!` inner attributes). Keeping
// the single oracle shared guarantees the property tests, the regression replays, and the fuzzer
// can never drift apart in what they check.

use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::surplus::locate_surplus;
use udp_transport_options::wire::udp::{self, UdpHeader};

/// Asserts the joint wire-layer invariants over one IP datagram buffer.
///
/// Every offset is re-derived from the parsed headers and the buffer itself — never from the
/// values under test — and every claimed range is actually indexed, so a wrong layout panics here
/// instead of surviving as a plausible-looking field value (the `SurplusLayout.starts_at`
/// off-by-one found in the step-2 review would have been an immediate slice panic). Returns
/// silently when the buffer does not parse: arbitrary fuzz input must never panic.
pub fn check_wire_invariants(buf: &[u8]) {
    let Ok((ip, udp_at)) = IpRepr::parse(buf) else { return };
    assert_eq!(udp_at, ip.header_len());
    let ip_end = ip.header_len() + ip.transport_payload_len();
    assert!(ip_end <= buf.len());

    let Ok(udp) = UdpHeader::parse(&buf[udp_at..]) else {
        return;
    };
    let udp_len = usize::from(udp.length);
    let natural_start = udp_at + udp_len;
    let layout = locate_surplus(&ip, &udp);

    if udp_len > ip.transport_payload_len() {
        // Invalid per FR-49 (dropped upstream); locate_surplus must refuse defensively.
        assert_eq!(layout, None);
        return;
    }

    // The user data slice (bounded by UDP Length) is in-bounds and checksummable.
    let user_data = &buf[udp_at + udp::HEADER_LEN..natural_start];
    let _ = UdpHeader { checksum: 0, ..udp }.compute_checksum(&ip, user_data);

    let raw_surplus = ip_end - natural_start;
    let want_pad = natural_start % 2 == 1;
    match layout {
        // No usable surplus exactly when the area cannot hold the aligned OCS plus any pad.
        None => assert!(raw_surplus < usize::from(want_pad) + 2),
        Some(layout) => {
            assert_eq!(layout.starts_at, natural_start);
            // The joint invariant the step-2 review bug violated: the surplus area is exactly
            // the transport payload past the UDP Length, so it must end at the IP datagram end.
            assert_eq!(layout.starts_at + layout.len, ip_end);
            assert_eq!(layout.needs_pad, want_pad);
            assert_eq!(layout.range(), layout.starts_at..ip_end);
            let surplus = &buf[layout.range()];
            assert!(surplus.len() >= usize::from(layout.needs_pad) + 2);
            // The OCS field is 2-byte aligned relative to the IP datagram start and in-bounds.
            let ocs_at = layout.ocs_at();
            assert_eq!(ocs_at, layout.starts_at + usize::from(layout.needs_pad));
            assert_eq!(ocs_at % 2, 0);
            assert!(ocs_at + 2 <= ip_end);
            let _ocs = &buf[ocs_at..ocs_at + 2];
        }
    }
}
