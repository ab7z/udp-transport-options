//! Wire-verification traffic generator (Step 10.5). Emits a fixed scenario set of RFC 9868
//! datagrams to loopback so `scripts/wire-check.sh` can capture the post-kernel bytes with tcpdump
//! and verify them with the independent checker `scripts/wire-check.py` plus a tshark field
//! cross-check. Unlike the Step 0.5 spike this is a permanent lane, not throwaway.
//!
//! Not run directly -- `scripts/wire-check.sh` starts the capture first:
//!
//! ```text
//! scripts/vm-ubuntu-server.sh wire
//! ```
//!
//! One destination port per scenario (`PORT_BASE` + scenario index). The checker owns the mirrored
//! scenario table and fails on any port-set or byte mismatch, so the constants below must stay in
//! sync with `scripts/wire-check.py`.

use std::net::Ipv4Addr;
use std::process;
use std::thread;
use std::time::Duration;

use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::ocs;
use udp_transport_options::options::serialize::OptionsBuilder;
use udp_transport_options::options::typed::{Apc, Frag, Mds, Mrds, Req, Res, TypedOption};
use udp_transport_options::socket::send::{RawSender, assemble_datagram};
use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::udp::{self, UdpHeader};

const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
/// Fixed source port, above the spike marker range (`0x9868` + case index) so stale spike traffic
/// can never collide with this lane.
const SRC_PORT: u16 = 0x9a00;
/// Scenario `i` sends to `PORT_BASE + i`.
const PORT_BASE: u16 = 0x9a68;

const REQ_TOKEN: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
const RES_TOKEN: [u8; 4] = [0xfe, 0xed, 0xfa, 0xce];
const FRAG_ID: u32 = 0x1122_3344;
/// Fragment-data length for the data-carrying FRAG scenarios.
const FRAG_DATA_LEN: usize = 64;

struct Scenario {
    name: &'static str,
    datagram: Vec<u8>,
}

/// [`OptionsBuilder::push`] takes the value without Kind/Length framing while the typed encoders
/// emit the full TLV; stripping the fixed two-byte header lets the scenarios exercise the
/// production field encoding (big-endian field order) end to end.
fn typed_value(option: &impl TypedOption) -> Vec<u8> {
    let mut tlv = Vec::new();
    option.encode(&mut tlv);
    tlv.split_off(2)
}

/// The deterministic fill used for extended-length values and fragment data (spike pattern).
fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

fn body(options: Vec<(OptionKind, Vec<u8>)>) -> Vec<u8> {
    let mut builder = OptionsBuilder::new();
    for (kind, value) in options {
        builder.push(kind, value);
    }
    builder.finish().expect("scenario options are valid builder input")
}

/// Hand-builds the two shapes [`assemble_datagram`] cannot emit: a datagram with no surplus area
/// at all (it asserts an OCS-led body) and the RFC 9868 Section 9 "OCS unused" form (it always
/// computes a real UDP checksum and patches a real OCS). The OCS placeholder in `options_body` is
/// deliberately left zero here.
fn hand_built_datagram(user: &[u8], dst_port: u16, zero_udp_checksum: bool, options_body: &[u8]) -> Vec<u8> {
    let udp_len = u16::try_from(udp::HEADER_LEN + user.len()).expect("UDP length fits the 16-bit field");
    let natural_start = 20 + udp::HEADER_LEN + user.len();
    assert!(
        options_body.is_empty() || natural_start.is_multiple_of(2),
        "hand-built scenarios use even user-data lengths so no pad byte is involved"
    );
    let total_len = u16::try_from(natural_start + options_body.len()).expect("total length fits the 16-bit field");

    let ip = IpRepr {
        src: LOOPBACK,
        dst: LOOPBACK,
        ihl: 5,
        total_len,
    };
    let mut datagram = vec![0u8; usize::from(total_len)];
    ip.write(&mut datagram[..20]);

    let mut header = UdpHeader {
        src_port: SRC_PORT,
        dst_port,
        length: udp_len,
        checksum: 0,
    };
    if !zero_udp_checksum {
        header.checksum = header.compute_checksum(&ip, user);
    }
    header.write(&mut datagram[20..20 + udp::HEADER_LEN]);

    let user_at = 20 + udp::HEADER_LEN;
    datagram[user_at..user_at + user.len()].copy_from_slice(user);
    datagram[natural_start..].copy_from_slice(options_body);
    datagram
}

/// Finds the 2-byte `Other(77)` filler whose canonical body makes the OCS sum come out `0x0000`,
/// which [`ocs::compute`] must then transmit as `0xFFFF` (RFC 9868 Section 9). Deterministic (first
/// hit of an ascending scan) and cheap: at most 65536 folds over an 8-byte body.
fn forced_zero_ocs_filler() -> [u8; 2] {
    for filler in 0..=u16::MAX {
        let mut builder = OptionsBuilder::new();
        builder.push(OptionKind::Other(77), filler.to_be_bytes());
        let mut candidate = builder.finish().expect("Other(77) with a 2-byte value is valid");
        let surplus_len = u16::try_from(candidate.len()).expect("surplus length fits the 16-bit field");
        ocs::compute(&mut candidate, surplus_len);
        if candidate[..2] == [0xff, 0xff] {
            return filler.to_be_bytes();
        }
    }
    unreachable!("the one's-complement sum is a bijection in the 16-bit filler, so a hit exists")
}

/// Builds the scenario datagrams in port order (`PORT_BASE + index`); mirrored in
/// `scripts/wire-check.py`.
fn scenarios() -> Vec<Scenario> {
    // `OptionsBuilder::finish` patches Frag.Start to the final fragment-data offset, so all FRAG
    // scenarios pass a zero placeholder.
    let frag = |frag_offset: u16, rdos: Option<u16>| Frag {
        frag_start: 0,
        identification: FRAG_ID,
        frag_offset,
        rdos,
    };
    let req = Req { token: REQ_TOKEN };
    let port = |index: u16| PORT_BASE + index;

    let mut frag_data_nonterm = body(vec![
        (OptionKind::Frag, typed_value(&frag(0, None))),
        (OptionKind::Req, typed_value(&req)),
    ]);
    frag_data_nonterm.extend_from_slice(&pattern(FRAG_DATA_LEN));
    // Terminal counterpart, as if it carried the second 64-byte half of a 128-byte payload: RDOS
    // points past the reassembled data (8-byte UDP header + 128 bytes).
    let mut frag_data_term = body(vec![
        (
            OptionKind::Frag,
            typed_value(&frag(64, Some(8 + 2 * FRAG_DATA_LEN as u16))),
        ),
        (OptionKind::Req, typed_value(&req)),
    ]);
    frag_data_term.extend_from_slice(&pattern(FRAG_DATA_LEN));

    vec![
        Scenario {
            name: "baseline",
            datagram: hand_built_datagram(b"plain", port(0), false, &[]),
        },
        Scenario {
            name: "canon-even",
            datagram: assemble_datagram(
                LOOPBACK,
                LOOPBACK,
                SRC_PORT,
                port(1),
                b"wire",
                &body(vec![
                    (OptionKind::Apc, typed_value(&Apc::compute(b"wire"))),
                    (
                        OptionKind::Mds,
                        typed_value(&Mds {
                            max_datagram_size: 1500,
                        }),
                    ),
                    (
                        OptionKind::Mrds,
                        typed_value(&Mrds {
                            max_reassembled_size: 2926,
                            max_segments: 2,
                        }),
                    ),
                    (OptionKind::Req, typed_value(&req)),
                    (OptionKind::Res, typed_value(&Res { token: RES_TOKEN })),
                ]),
            ),
        },
        Scenario {
            name: "pad-odd",
            datagram: assemble_datagram(
                LOOPBACK,
                LOOPBACK,
                SRC_PORT,
                port(2),
                b"odd",
                &body(vec![(OptionKind::Req, typed_value(&req))]),
            ),
        },
        Scenario {
            name: "frag-nonterm",
            datagram: assemble_datagram(
                LOOPBACK,
                LOOPBACK,
                SRC_PORT,
                port(3),
                b"",
                &body(vec![(OptionKind::Frag, typed_value(&frag(0x0008, None)))]),
            ),
        },
        Scenario {
            name: "frag-term",
            datagram: assemble_datagram(
                LOOPBACK,
                LOOPBACK,
                SRC_PORT,
                port(4),
                b"",
                &body(vec![(OptionKind::Frag, typed_value(&frag(0x0010, Some(0x001c))))]),
            ),
        },
        Scenario {
            name: "ocs-forced-ffff",
            datagram: assemble_datagram(
                LOOPBACK,
                LOOPBACK,
                SRC_PORT,
                port(5),
                b"",
                &body(vec![(OptionKind::Other(77), forced_zero_ocs_filler().to_vec())]),
            ),
        },
        Scenario {
            name: "ext-len",
            datagram: assemble_datagram(
                LOOPBACK,
                LOOPBACK,
                SRC_PORT,
                port(6),
                b"",
                &body(vec![(OptionKind::Other(11), pattern(300))]),
            ),
        },
        Scenario {
            name: "cksum0-ocs0",
            datagram: hand_built_datagram(
                b"nochksum",
                port(7),
                true,
                &body(vec![(OptionKind::Req, typed_value(&req))]),
            ),
        },
        Scenario {
            name: "frag-data-nonterm",
            datagram: assemble_datagram(LOOPBACK, LOOPBACK, SRC_PORT, port(8), b"", &frag_data_nonterm),
        },
        Scenario {
            name: "frag-data-term",
            datagram: assemble_datagram(LOOPBACK, LOOPBACK, SRC_PORT, port(9), b"", &frag_data_term),
        },
    ]
}

fn main() {
    let sender = match RawSender::new() {
        Ok(sender) => sender,
        Err(err) => {
            eprintln!(
                "wire_probe FAIL: raw socket unavailable ({err}); needs Linux CAP_NET_RAW (run via scripts/wire-check.sh under sudo)"
            );
            process::exit(2);
        }
    };

    let all = scenarios();
    println!(
        "wire_probe: {LOOPBACK} -> {LOOPBACK} (src port {SRC_PORT}), {} scenarios",
        all.len()
    );
    for (index, scenario) in all.iter().enumerate() {
        let dst_port = PORT_BASE + u16::try_from(index).expect("scenario count fits u16");
        if let Err(err) = sender.send(LOOPBACK, &scenario.datagram) {
            eprintln!("wire_probe FAIL: {} (port {dst_port}): {err}", scenario.name);
            process::exit(1);
        }
        println!(
            "  {:<18} port {dst_port}  {:>3} bytes",
            scenario.name,
            scenario.datagram.len()
        );
        // Spike precedent: a short gap keeps the capture ordering clean.
        thread::sleep(Duration::from_millis(10));
    }
    println!("wire_probe: sent {} datagrams", all.len());
}
