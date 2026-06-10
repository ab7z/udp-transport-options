//! Shared helpers for the Step 0.5 spike client/server pair (throwaway -- roadmap Step 0.5).
//!
//! `spike_client` (default netns) and `spike_server` (netns `spk`) both pull their constants, the
//! case generator, the hand-built IPv4+UDP datagram, and the marker matcher from here. It is not library
//! code and not a conformance test; its findings fold into the real Steps 8-9 (`src/socket/`), after
//! which the whole spike can be deleted. See `scripts/spike.sh` and `docs/plan/steps/00b-spike.md`.
//!
//! Three findings (confirmed on the wire) shape these cases:
//!   A. Linux raw `IP_HDRINCL` forces IP Total Length to the *buffer* length -- you cannot append
//!      bytes "beyond" IP Total Length; every appended byte is delivered as surplus.
//!   B. The `IP_HDRINCL` path refuses to fragment: a send larger than the link MTU fails `EMSGSIZE`.
//!   C. The raw receive path performs no UDP-level validation: bad/zero checksums and lying UDP
//!      Length fields are delivered as-is (the header-anomaly cases).
//!
//! Each example uses only a subset of these helpers, so dead-code is expected and allowed.
#![allow(dead_code)]

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::AsRawFd;

use socket2::Socket;

pub const IP_HDR_LEN: usize = 20;
pub const UDP_HDR_LEN: usize = 8;

/// The staged link's MTU (`scripts/spike.sh` sets both veth ends to this).
pub const MTU: usize = 1500;

/// Endpoints on the veth /24: client in the default netns, server in netns `spk`.
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
pub const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

pub const SRC_PORT: u16 = 40000;
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

/// What `build_datagram` writes into the UDP checksum field.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CksumMode {
    /// The correctly computed checksum.
    Auto,
    /// Literal zero ("no checksum" per RFC 768).
    Zero,
    /// A deliberately wrong (nonzero) value.
    Bad,
}

/// One datagram shape. The surplus (`pattern(surplus_len)`) is appended after the UDP user data;
/// `written_ip_total_len` is the IP Total Length the client *writes* (the kernel may override it --
/// Finding A), letting the `under`/`over` variants declare a smaller/larger length than the buffer
/// on purpose. The override fields exist for the header-anomaly cases only.
pub struct Case {
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

impl Case {
    pub fn udp_len(&self) -> usize {
        UDP_HDR_LEN + self.udp_data_len
    }

    /// Physical bytes the client puts on the wire: headers + user data + surplus.
    pub fn physical_len(&self) -> usize {
        IP_HDR_LEN + self.udp_len() + self.surplus_len
    }
}

/// UDP-user-data sizes crossed by `cases()`: empty, minimal odd, small odd, large.
pub const UDP_DATA_DIMS: &[usize] = &[0, 1, 13, 1392];
/// Surplus sizes crossed by `cases()`: none, single byte, small even/odd pair, and the MTU
/// boundary from below and above (1471/1472/1473 with empty user data).
pub const SURPLUS_DIMS: &[usize] = &[0, 1, 8, 39, 40, 1471, 1472, 1473];

/// Build one cross-product case; the expectation is *derived*, never listed: anything whose
/// physical size exceeds the MTU must fail to send (Finding B), everything else must arrive
/// with the surplus intact (Finding A makes the written IP Total Length irrelevant for that).
fn combo(label: String, udp_data_len: usize, surplus_len: usize, written_ip_total_len: usize) -> Case {
    let physical = IP_HDR_LEN + UDP_HDR_LEN + udp_data_len + surplus_len;
    Case {
        label,
        udp_data_len,
        surplus_len,
        written_ip_total_len,
        udp_len_override: None,
        cksum: CksumMode::Auto,
        check: if physical > MTU { Check::SendFails } else { Check::Wire },
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
pub fn cases() -> Vec<Case> {
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
    let anomaly = |label: &str, udp_len_override: Option<u16>, cksum: CksumMode| Case {
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

/// Build a complete IPv4 + UDP datagram for `case`, sent to `dst_port`, with the surplus appended as
/// the tail. The UDP checksum covers the pseudo-header + UDP header + user data only (never the
/// surplus, per RFC 9868). The IP Total Length field is `case.written_ip_total_len` (the kernel may
/// override it -- Finding A).
pub fn build_datagram(case: &Case, dst_port: u16) -> Vec<u8> {
    let udp_len = case.udp_len();
    let mut pkt = Vec::with_capacity(case.physical_len());

    // --- IPv4 header (20 bytes, no options) ---
    pkt.push(0x45); // version 4, IHL 5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&(case.written_ip_total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes()); // identification: per-case (= marker port)
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset (DF clear)
    pkt.push(64); // TTL
    pkt.push(libc::IPPROTO_UDP as u8);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum (patched below; kernel may redo it)
    pkt.extend_from_slice(&CLIENT_IP.octets());
    pkt.extend_from_slice(&SERVER_IP.octets());
    let ip_checksum = ones_complement_checksum(&pkt[..IP_HDR_LEN]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // --- UDP header (8 bytes) + user data; UDP Length covers the header + user data ---
    // (anomaly cases may write a lying UDP Length and/or a zero/corrupted checksum instead)
    let written_udp_len = case.udp_len_override.unwrap_or(udp_len as u16);
    pkt.extend_from_slice(&SRC_PORT.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&written_udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (patched below)
    pkt.resize(IP_HDR_LEN + UDP_HDR_LEN + case.udp_data_len, 0xAA); // 0xAA user data, distinct from surplus
    let computed = udp_checksum(CLIENT_IP, SERVER_IP, &pkt[IP_HDR_LEN..IP_HDR_LEN + udp_len]);
    let udp_checksum = match case.cksum {
        CksumMode::Auto => computed,
        CksumMode::Zero => 0,
        CksumMode::Bad => {
            let bad = computed.wrapping_add(1);
            if bad == 0 { 1 } else { bad }
        }
    };
    pkt[IP_HDR_LEN + 6..IP_HDR_LEN + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    // --- Surplus tail ---
    pkt.extend_from_slice(&pattern(case.surplus_len));
    pkt
}

/// A matched marker datagram as the server observed it (after any kernel reassembly).
pub struct Marker<'a> {
    pub dst_port: u16,
    /// IP Total Length as delivered -- the kernel sets this to the buffer length (Finding A).
    pub total_len: usize,
    /// The UDP Length *field* as delivered (the anomaly cases write a lying value).
    pub udp_len_field: usize,
    /// Surplus = bytes from the end of the UDP datagram up to the observed IP Total Length.
    /// `None` when the UDP Length field is inconsistent (under 8 or past the IP Total Length),
    /// because then no well-defined surplus exists.
    pub surplus: Option<&'a [u8]>,
}

/// If `data` is one of our marker datagrams (matched by destination port out of `n_cases` marker
/// ports), return what the receiver sees bounded by IP Total Length. A lying UDP Length field
/// does not disqualify the match -- the anomaly cases need to be observed, not filtered out.
/// Total over the wire; never panics on malformed input.
pub fn match_marker(data: &[u8], n_cases: usize) -> Option<Marker<'_>> {
    if data.len() < IP_HDR_LEN {
        return None;
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if ihl < IP_HDR_LEN || data.len() < ihl || data[9] != libc::IPPROTO_UDP as u8 {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len > data.len() || total_len < ihl + UDP_HDR_LEN {
        return None;
    }
    let udp = &data[ihl..];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if !(MARKER_BASE..MARKER_BASE + n_cases as u16).contains(&dst_port) {
        return None;
    }
    let surplus = if udp_len >= UDP_HDR_LEN && ihl + udp_len <= total_len {
        Some(&data[ihl + udp_len..total_len])
    } else {
        None
    };
    Some(Marker {
        dst_port,
        total_len,
        udp_len_field: udp_len,
        surplus,
    })
}

/// Enable `IP_HDRINCL` so the kernel sends our hand-built IP header.
pub fn set_hdrincl(sock: &Socket) -> io::Result<()> {
    let one: libc::c_int = 1;
    // SAFETY: valid fd, valid option pointer/length for IP_HDRINCL.
    let ret = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            std::ptr::addr_of!(one).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// UDP checksum over the IPv4 pseudo-header plus the UDP datagram (header + user data, no surplus).
pub fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(libc::IPPROTO_UDP as u8);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    let sum = ones_complement_checksum(&pseudo);
    // A computed checksum of 0 is transmitted as 0xFFFF (0 means "no checksum" for UDP).
    if sum == 0 { 0xFFFF } else { sum }
}

/// RFC 1071 one's-complement Internet checksum (throwaway; the real one is Step 1).
pub fn ones_complement_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        sum += u16::from_be_bytes([c[0], c[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (u16::from(*last) << 8) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Space-separated hex of up to `max` bytes, with an ellipsis marker when truncated.
pub fn hex(bytes: &[u8], max: usize) -> String {
    let mut s = String::new();
    for b in bytes.iter().take(max) {
        s.push_str(&format!("{b:02x} "));
    }
    if bytes.len() > max {
        s.push_str("...");
    }
    s.trim_end().to_string()
}
