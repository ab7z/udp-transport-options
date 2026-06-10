//! Step 0.5 spike -- client. Runs in the **default** netns (source 10.0.0.1) and raw-sends each
//! case's hand-built IPv4+UDP datagram across the staged 1500-MTU veth link to the server
//! (10.0.0.2, netns `spk`). Throwaway; see `scripts/spike.sh` and `docs/plan/steps/00b-spike.md`.
//!
//! It gates the send-limit cases (every over-MTU combo must fail `EMSGSIZE`); the server gates delivery.
//! Not run directly -- `scripts/spike.sh` builds it and runs it after the server is listening:
//!
//! ```text
//! scripts/vm-ubuntu-server.sh spike
//! ```
//!
//! The `unsafe` here (raw `IP_HDRINCL` setsockopt) is deliberately inline and minimal;
//! the production path confines all `unsafe` behind safe wrappers in `src/socket/`.

#[path = "support/common.rs"]
mod common;

use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::os::fd::AsRawFd;
use std::process;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use common::{CaseParts, Check, CksumMode, IP_HDR_LEN, SpikeError, UDP_HDR_LEN, case_parts, marker_port, pattern};

/// Endpoints on the veth /24: client in the default netns, server in netns `spk`.
const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const SERVER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const SRC_PORT: u16 = 40000;

/// One datagram shape. The surplus (`pattern(surplus_len)`) is appended after the UDP user data;
/// `written_ip_total_len` is the IP Total Length the client *writes* (the kernel may override it --
/// Finding A), letting the `under`/`over` variants declare a smaller/larger length than the buffer
/// on purpose. The override fields exist for the header-anomaly cases only.
struct Case {
    label: String,
    /// UDP user-data length (the `0xAA` fill).
    udp_data_len: usize,
    /// Surplus bytes appended after the UDP payload.
    surplus_len: usize,
    /// IP Total Length value written into the header (see Finding A).
    written_ip_total_len: usize,
    /// `Some(n)`: write `n` into the UDP Length field instead of the real length (anomaly cases).
    udp_len_override: Option<u16>,
    /// What to write into the UDP checksum field (anomaly cases use `Zero`/`Bad`).
    cksum: CksumMode,
    check: Check,
}

impl Case {
    fn udp_len(&self) -> usize {
        UDP_HDR_LEN + self.udp_data_len
    }

    /// Physical bytes the client puts on the wire: headers + user data + surplus.
    fn physical_len(&self) -> usize {
        IP_HDR_LEN + self.udp_len() + self.surplus_len
    }
}

fn cases() -> Vec<Case> {
    case_parts()
        .into_iter()
        .map(
            |CaseParts {
                 label,
                 udp_data_len,
                 surplus_len,
                 written_ip_total_len,
                 udp_len_override,
                 cksum,
                 check,
             }| Case {
                label,
                udp_data_len,
                surplus_len,
                written_ip_total_len,
                udp_len_override,
                cksum,
                check,
            },
        )
        .collect()
}

fn main() {
    let sock = match open_send_socket() {
        Ok(s) => s,
        Err(SpikeError::Permission) => {
            eprintln!("spike_client FAIL: raw socket needs CAP_NET_RAW (run via scripts/spike.sh under sudo)");
            process::exit(2);
        }
        Err(SpikeError::Io(e)) => {
            eprintln!("spike_client FAIL: {e}");
            process::exit(1);
        }
    };

    let all = cases();
    println!(
        "spike_client: {CLIENT_IP} -> {SERVER_IP} (src port {SRC_PORT}), {} cases",
        all.len()
    );
    // The destination IP comes from our IP header for an IP_HDRINCL socket; the sockaddr port is
    // ignored, so any port is fine here.
    let dest = SockAddr::from(SocketAddrV4::new(SERVER_IP, 0));

    let mut sent = 0usize;
    let mut emsgsize = 0usize;
    let mut failed = 0usize;
    for (i, case) in all.iter().enumerate() {
        let port = marker_port(i);
        let pkt = build_datagram(case, port);
        let label = &case.label;
        let phys = case.physical_len();
        let result = sock.send_to(&pkt, &dest);

        match case.check {
            // Wire and WireRaw cases must leave the host; the server scores them.
            Check::Wire | Check::WireRaw => match result {
                Ok(_) => sent += 1,
                Err(e) => {
                    println!("  {label:<18} port {port} physical={phys} -> FAIL unexpected send error: {e}");
                    failed += 1;
                }
            },
            Check::SendFails => match result {
                Err(ref e) if e.raw_os_error() == Some(libc::EMSGSIZE) => emsgsize += 1,
                Ok(n) => {
                    println!("  {label:<18} port {port} physical={phys} -> FAIL expected EMSGSIZE but sent {n}B");
                    failed += 1;
                }
                Err(e) => {
                    println!("  {label:<18} port {port} physical={phys} -> FAIL expected EMSGSIZE, got: {e}");
                    failed += 1;
                }
            },
        }

        // Small gap so each case drains before the next (clean tcpdump, less reorder).
        thread::sleep(Duration::from_millis(10));
    }

    let client_ok = failed == 0;
    println!(
        "spike_client: {} ({sent} sent, {emsgsize} EMSGSIZE as expected (Finding B), {failed} failed)",
        if client_ok {
            "PASS (send-side)"
        } else {
            "FAIL (send-side)"
        }
    );
    process::exit(if client_ok { 0 } else { 1 });
}

fn open_send_socket() -> Result<Socket, SpikeError> {
    let sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::from(libc::IPPROTO_UDP)),
    )?;
    set_hdrincl(&sock)?;
    Ok(sock)
}

/// Enable `IP_HDRINCL` so the kernel sends our hand-built IP header.
fn set_hdrincl(sock: &Socket) -> io::Result<()> {
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

/// Build a complete IPv4 + UDP datagram for `case`, sent to `dst_port`, with the surplus appended as
/// the tail. The UDP checksum covers the pseudo-header + UDP header + user data only (never the
/// surplus, per RFC 9868). The IP Total Length field is `case.written_ip_total_len` (the kernel may
/// override it -- Finding A).
fn build_datagram(case: &Case, dst_port: u16) -> Vec<u8> {
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

/// UDP checksum over the IPv4 pseudo-header plus the UDP datagram (header + user data, no surplus).
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
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
fn ones_complement_checksum(bytes: &[u8]) -> u16 {
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
