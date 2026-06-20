//! Shared case generator for the Step 0.5 spike client/server pair (throwaway -- roadmap Step 0.5).
//!
//! `spike_client` (default netns) and `spike_server` (netns `spk`) both use the same deterministic
//! case table. It is not library code and not a conformance test; its findings fold into the real
//! Step 8 (`src/socket/`), after which the whole spike can be deleted. See `scripts/spike.sh`
//! and `docs/plan/steps/00b-spike.md`.
//!
//! Three findings (confirmed on the wire) shape these cases:
//!   A. Linux raw `IP_HDRINCL` forces IP Total Length to the *buffer* length -- you cannot append
//!      bytes "beyond" IP Total Length; every appended byte is delivered as surplus.
//!   B. The `IP_HDRINCL` path refuses to fragment: a send larger than the link MTU fails `EMSGSIZE`.
//!   C. The raw receive path performs no UDP-level validation: bad/zero checksums and lying UDP
//!      Length fields are delivered as-is (the header-anomaly cases).

use std::io;

pub const IP_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;

/// The staged link's MTU (`scripts/spike.sh` sets both veth ends to this).
pub const MTU: usize = 1500;

/// First marker UDP port; case `i` uses `MARKER_BASE + i` (0x9868 nods to RFC 9868).
pub const MARKER_BASE: u16 = 0x9868;

/// The surplus payload: an incrementing pattern (`00 01 02 .. ff 00 ..`) so a prefix is obvious in a
/// hexdump and any reorder/corruption shows up immediately.
pub fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 256) as u8).collect()
}

/// How a case is scored, and by whom.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// Delivered to the server, which checks the surplus arrived intact (gating).
    Wire,
    /// Header-anomaly case: the server gates only on *arrival* and logs the observed shape;
    /// no byte-level verdict (the spike observes kernel behaviour, it does not judge it).
    WireRaw,
    /// Oversized: the client expects the send to fail with `EMSGSIZE`; never reaches the server.
    SendFails,
}

/// What the client writes into the UDP checksum field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CksumMode {
    /// The correctly computed checksum.
    Auto,
    /// Literal zero ("no checksum" per RFC 768).
    Zero,
    /// A deliberately wrong (nonzero) value.
    Bad,
}

/// Raw case shape shared by the client and server projections.
pub struct CaseParts {
    pub label: String,
    /// UDP user-data length (the `0xAA` fill).
    pub udp_data_len: usize,
    /// Surplus bytes appended after the UDP payload.
    pub surplus_len: usize,
    /// IP Total Length value written into the header (see Finding A).
    pub written_ip_total_len: usize,
    /// `Some(n)`: write `n` into the UDP Length field instead of the real length (anomaly cases).
    pub udp_len_override: Option<u16>,
    /// What to write into the UDP checksum field (anomaly cases use `Zero`/`Bad`).
    pub cksum: CksumMode,
    pub check: Check,
}

/// UDP-user-data sizes crossed by `case_parts()`: empty, minimal odd, small odd, large.
const UDP_DATA_DIMS: &[usize] = &[0, 1, 13, 1392];
/// Surplus sizes crossed by `case_parts()`: none, single byte, small even/odd pair, and the MTU
/// boundary from below and above (1471/1472/1473 with empty user data).
const SURPLUS_DIMS: &[usize] = &[0, 1, 8, 39, 40, 1471, 1472, 1473];

/// Build one cross-product case; the expectation is *derived*, never listed: anything whose
/// physical size exceeds the MTU must fail to send (Finding B), everything else must arrive
/// with the surplus intact (Finding A makes the written IP Total Length irrelevant for that).
fn combo(label: String, udp_data_len: usize, surplus_len: usize, written_ip_total_len: usize) -> CaseParts {
    let physical = IP_HDR_LEN + UDP_HDR_LEN + udp_data_len + surplus_len;
    let check = if physical > MTU { Check::SendFails } else { Check::Wire };
    CaseParts {
        label,
        udp_data_len,
        surplus_len,
        written_ip_total_len,
        udp_len_override: None,
        cksum: CksumMode::Auto,
        check,
    }
}

/// The case table: a deterministic generator (client and server build the identical list).
///
/// Cross product of `UDP_DATA_DIMS` x `SURPLUS_DIMS` x the written-IP-Total-Length variants
/// `honest` (= physical), `under` (declares *no* surplus -- the old `hide-attempt`, only when
/// there is one), and `over` (declares 40 bytes more than the buffer; Finding A predicts the
/// kernel rewrites *both* directions to the buffer length). The expectation per combo is derived
/// from the physical size vs the MTU, so the MTU boundary is exercised from both sides across
/// all user-data sizes. Appended to that: the explicit far-over-MTU case and the header-anomaly
/// cases (`WireRaw`), which probe whether the kernel validates anything UDP-level before
/// delivering to a raw socket.
pub fn case_parts() -> Vec<CaseParts> {
    let mut v = Vec::new();
    for &d in UDP_DATA_DIMS {
        for &s in SURPLUS_DIMS {
            let physical = IP_HDR_LEN + UDP_HDR_LEN + d + s;
            v.push(combo(format!("d{d}-s{s}-honest"), d, s, physical));
            if s > 0 {
                v.push(combo(format!("d{d}-s{s}-under"), d, s, physical - s));
            }
            v.push(combo(format!("d{d}-s{s}-over"), d, s, physical + 40));
        }
    }

    // Finding B, far past the MTU (kept from the original hand-written table).
    v.push(combo("over-mtu-3000".into(), 0, 2972, 3000));

    // Header-anomaly cases: does the kernel check the UDP checksum or the UDP Length field
    // before handing the datagram to SOCK_RAW/IPPROTO_UDP? All four are expected to *arrive*;
    // what the server observes is logged, not judged.
    let anomaly = |label: &str, udp_len_override: Option<u16>, cksum: CksumMode| CaseParts {
        label: label.into(),
        udp_data_len: 0,
        surplus_len: 40,
        written_ip_total_len: IP_HDR_LEN + UDP_HDR_LEN + 40,
        udp_len_override,
        cksum,
        check: Check::WireRaw,
    };
    v.push(anomaly("cksum-zero", None, CksumMode::Zero));
    v.push(anomaly("cksum-bad", None, CksumMode::Bad));
    v.push(anomaly("len-overclaim", Some(500), CksumMode::Auto)); // claims 500 of 48 available bytes
    v.push(anomaly("len-under-8", Some(4), CksumMode::Auto)); // shorter than the UDP header itself

    v
}

/// Marker UDP port for the case at `index`.
pub fn marker_port(index: usize) -> u16 {
    MARKER_BASE + index as u16
}

/// Errors the spike binaries surface; case mismatches are handled in each binary's own reporting.
pub enum SpikeError {
    /// Raw socket creation failed for lack of `CAP_NET_RAW`.
    Permission,
    Io(io::Error),
}

impl From<io::Error> for SpikeError {
    fn from(e: io::Error) -> Self {
        if e.raw_os_error() == Some(libc::EPERM) || e.raw_os_error() == Some(libc::EACCES) {
            SpikeError::Permission
        } else {
            SpikeError::Io(e)
        }
    }
}
