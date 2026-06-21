// Shared OCS invariant oracle.
//
// Used by `mod common_ocs;` from the property tests and spliced into the `options_ocs` fuzz target
// via `include!`.

use udp_transport_options::error::ParseError;
use udp_transport_options::options::ocs::{self, OcsCheck};

fn representative_positions(len: usize) -> impl Iterator<Item = usize> {
    let mut positions = Vec::from([0, 1, len / 2, len.saturating_sub(1)]);
    positions.sort_unstable();
    positions.dedup();
    positions.into_iter().filter(move |pos| *pos < len)
}

#[allow(dead_code)]
pub fn check_ocs_invariants(bytes: &[u8]) {
    let surplus_len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    let _ = ocs::validate(bytes, surplus_len, 0x1234);

    if bytes.len() < 2 {
        assert_eq!(
            ocs::validate(bytes, surplus_len, 0x1234),
            OcsCheck::Error(ParseError::Overrun { offset: 0 })
        );
        return;
    }

    // The OCS-led body starts at the OCS field. The surplus length is the full area length:
    // body.len() for an even-start layout, and body.len() + 1 when a single zero pad precedes the
    // OCS in an odd-start layout.
    check_compute_validate(bytes, surplus_len);
    if let Some(padded_len) = surplus_len.checked_add(1) {
        check_compute_validate(bytes, padded_len);
    }

    // Zero-OCS dispositions and the pad-byte rule do not depend on the checksum sum.
    let mut zero_ocs = bytes.to_vec();
    zero_ocs[..2].fill(0);
    assert_eq!(ocs::validate(&zero_ocs, surplus_len, 0), OcsCheck::Unused);
    assert_eq!(ocs::validate(&zero_ocs, surplus_len, 1), OcsCheck::IgnoreOptions);
    assert_eq!(ocs::check_pad(0, true), Ok(()));
    assert_eq!(ocs::check_pad(1, true), Err(ParseError::NonZeroPad));
    assert_eq!(ocs::check_pad(1, false), Ok(()));
}

fn check_compute_validate(bytes: &[u8], surplus_len: u16) {
    let mut body = bytes.to_vec();
    ocs::compute(&mut body, surplus_len);
    assert_eq!(ocs::validate(&body, surplus_len, 0x1234), OcsCheck::Valid);

    for i in representative_positions(body.len()) {
        let mut corrupted = body.clone();
        corrupted[i] ^= 0x01;
        assert_ne!(ocs::validate(&corrupted, surplus_len, 0x1234), OcsCheck::Valid);
    }
}
