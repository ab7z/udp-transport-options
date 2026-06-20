//! Replays the curated seed datagrams (and, over time, minimized fuzz crashes) through the shared
//! invariant oracle and against hand-derived expectations.
//!
//! The byte vectors are embedded with `include_bytes!` because the achim cargo runner ships only
//! the test binary over ssh — runtime file reads would fail there. Flow for a fuzz finding:
//! minimize the crash artifact (`cargo +nightly fuzz tmin ...`), check the bytes in under
//! `tests/data/`, list them here as a permanent regression, then fix. The same files seed the
//! fuzzer from `fuzz/seeds/wire_datagram/`. proptest findings follow the same flow: the
//! `.proptest-regressions` sidecar only replays where the source tree is present (not on achim),
//! so every shrunk counterexample is embedded here too — the `shrunk_*` entries are the
//! mutation-test counterexamples that flagged the `SurplusLayout.starts_at` off-by-one.

mod common;

use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::surplus::{SurplusLayout, locate_surplus};
use udp_transport_options::wire::udp::{self, UdpHeader};

const SEEDS: &[(&str, &[u8])] = &[
    ("v4_hello", include_bytes!("data/v4_hello.bin")),
    (
        "v4_hello_surplus_even",
        include_bytes!("data/v4_hello_surplus_even.bin"),
    ),
    ("v4_hello_surplus_odd", include_bytes!("data/v4_hello_surplus_odd.bin")),
    (
        "shrunk_v4_min_odd_surplus",
        include_bytes!("data/shrunk_v4_min_odd_surplus.bin"),
    ),
    (
        "shrunk_v4_long_odd_surplus",
        include_bytes!("data/shrunk_v4_long_odd_surplus.bin"),
    ),
];

fn seed(name: &str) -> &'static [u8] {
    SEEDS.iter().find(|(n, _)| *n == name).expect("known seed").1
}

fn parse(bytes: &[u8]) -> (IpRepr, UdpHeader) {
    let (ip, offset) = IpRepr::parse(bytes).expect("seed parses");
    let header = UdpHeader::parse(&bytes[offset..]).expect("seed UDP header parses");
    (ip, header)
}

#[test]
fn seeds_satisfy_wire_invariants() {
    for (name, bytes) in SEEDS {
        parse(bytes); // a seed that stops parsing is a curation error, not a silent skip
        common::check_wire_invariants(bytes);
        println!("seed ok: {name}");
    }
}

#[test]
fn seed_layouts_match_hand_derived_offsets() {
    let layout = |name| {
        let (ip, header) = parse(seed(name));
        locate_surplus(&ip, &header)
    };
    // The plain hello datagram carries no surplus at all.
    assert_eq!(layout("v4_hello"), None);
    // Header 20 + UDP Length 12: even start, no pad.
    assert_eq!(
        layout("v4_hello_surplus_even"),
        Some(SurplusLayout {
            starts_at: 32,
            needs_pad: false,
            len: 4
        })
    );
    // Header 20 + UDP Length 13: odd start, the zero pad byte is the area's first byte.
    assert_eq!(
        layout("v4_hello_surplus_odd"),
        Some(SurplusLayout {
            starts_at: 33,
            needs_pad: true,
            len: 5
        })
    );
}

#[test]
fn seed_udp_checksums_match_independent_computation() {
    // Expected values computed with an independent (Python) RFC 1071 implementation.
    for (name, expected) in [("v4_hello", 0x9f5c), ("v4_hello_surplus_even", 0x0e5f)] {
        let bytes = seed(name);
        let (ip, header) = parse(bytes);
        let user_at = ip.header_len() + udp::HEADER_LEN;
        let user_data = &bytes[user_at..ip.header_len() + usize::from(header.length)];
        assert_eq!(header.compute_checksum(&ip, user_data), expected, "{name}");
        assert_eq!(header.checksum, expected, "{name}");
    }
}
