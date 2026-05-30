//! Throwaway loopback spike -- roadmap Step 0.5.
//!
//! De-risks the project's core premise *before* any RFC 9868 machinery exists: does a UDP datagram
//! whose `UDP Length` is smaller than the IP `Total Length` -- i.e. one carrying trailing "surplus
//! area" bytes -- survive a raw send -> raw recv round-trip over `127.0.0.1` inside the single Linux
//! `dev` service?
//!
//! It sends ARBITRARY surplus bytes: no OCS, no TLV options, no FRAG, no IPv6, no library wiring.
//! This is not library code and not a conformance test. Its findings fold into the real Steps 8-9
//! (`src/socket/{send,recv}.rs`), after which this example can be deleted.
//!
//! Run it (needs `CAP_NET_RAW`; the `dev` service carries it, effective for root, so go via
//! `sudo -E`):
//!
//! ```text
//! docker compose run --rm dev sudo -E cargo run --example loopback_spike
//! ```
//!
//! The `unsafe` here (raw `setsockopt`) is deliberately inline and minimal; the production path
//! confines all `unsafe` behind safe wrappers in `src/socket/`.

use std::io;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

/// UDP destination port used as the spike's marker (0x9868 nods to RFC 9868).
const MARKER_PORT: u16 = 0x9868;
const SRC_PORT: u16 = 40000;
/// Arbitrary surplus-area payload. Its survival is the whole point of the spike.
const SURPLUS: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x9, 0x8, 0x6, 0x8];

const IP_HDR_LEN: usize = 20;
const UDP_HDR_LEN: usize = 8;

fn main() {
    match run() {
        Ok(()) => println!("PASS: surplus bytes survived loopback ({} bytes intact)", SURPLUS.len()),
        Err(SpikeError::Permission) => {
            eprintln!("FAIL: raw socket needs CAP_NET_RAW -- run through the Docker `dev` service:");
            eprintln!("      docker compose run --rm dev sudo -E cargo run --example loopback_spike");
            std::process::exit(2);
        }
        Err(SpikeError::Io(e)) => {
            eprintln!("FAIL: {e}");
            std::process::exit(1);
        }
        Err(SpikeError::Mismatch(msg)) => {
            eprintln!("FAIL: {msg}");
            std::process::exit(1);
        }
    }
}

enum SpikeError {
    Permission,
    Io(io::Error),
    Mismatch(String),
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

fn run() -> Result<(), SpikeError> {
    // Receiver first, so it is listening before we send. It signals readiness, then reports the
    // surplus bytes it observed (or an error) back over the channel.
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), SpikeError>>();
    let (result_tx, result_rx) = mpsc::channel::<Result<Vec<u8>, String>>();

    let receiver = thread::spawn(move || receive_loop(&ready_tx, &result_tx));

    // Propagate a receiver-side socket-creation failure (e.g. EPERM) before we try to send.
    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => return Err(SpikeError::Io(io::Error::other("receiver thread exited early"))),
    }

    send_datagram()?;

    let observed = match result_rx.recv_timeout(Duration::from_secs(3)) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(msg)) => return Err(SpikeError::Mismatch(msg)),
        Err(_) => {
            return Err(SpikeError::Mismatch(
                "no matching datagram within 3s -- the local kernel/loopback dropped or stripped the surplus area"
                    .to_string(),
            ));
        }
    };
    let _ = receiver.join();

    hexdump("received surplus area", &observed);
    if observed == SURPLUS {
        Ok(())
    } else {
        Err(SpikeError::Mismatch(format!(
            "surplus mismatch: sent {SURPLUS:02x?}, got {observed:02x?}"
        )))
    }
}

/// Build a complete IPv4 + UDP datagram by hand with `UDP Length == 8` (empty user data) so the
/// `SURPLUS` bytes form a genuine surplus area (`UDP Length` < IP `Total Length`), then send it over
/// a raw `IP_HDRINCL` socket to `127.0.0.1`.
fn send_datagram() -> Result<(), SpikeError> {
    let total_len = IP_HDR_LEN + UDP_HDR_LEN + SURPLUS.len();
    let src = Ipv4Addr::LOCALHOST;
    let dst = Ipv4Addr::LOCALHOST;

    let mut pkt = Vec::with_capacity(total_len);

    // --- IPv4 header (20 bytes, no options) ---
    pkt.push(0x45); // version 4, IHL 5
    pkt.push(0x00); // DSCP/ECN
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
    pkt.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    pkt.push(64); // TTL
    pkt.push(libc::IPPROTO_UDP as u8);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // header checksum (patched below)
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let ip_checksum = ones_complement_checksum(&pkt[..IP_HDR_LEN]);
    pkt[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    // --- UDP header (8 bytes); UDP Length covers only the header (no user data) ---
    let udp_len = UDP_HDR_LEN as u16;
    pkt.extend_from_slice(&SRC_PORT.to_be_bytes());
    pkt.extend_from_slice(&MARKER_PORT.to_be_bytes());
    pkt.extend_from_slice(&udp_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum (patched below)
    let udp_checksum = udp_checksum(src, dst, &pkt[IP_HDR_LEN..IP_HDR_LEN + UDP_HDR_LEN]);
    pkt[IP_HDR_LEN + 6..IP_HDR_LEN + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    // --- Surplus area (arbitrary bytes, outside the UDP checksum) ---
    pkt.extend_from_slice(SURPLUS);

    let sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::from(libc::IPPROTO_UDP)),
    )?;
    set_hdrincl(&sock)?;
    // Port is ignored for an IP_HDRINCL raw socket; the destination comes from our IP header.
    let dest = SockAddr::from(SocketAddrV4::new(dst, 0));
    sock.send_to(&pkt, &dest)?;
    Ok(())
}

/// Raw `SOCK_RAW`/`IPPROTO_UDP` receive: the kernel hands us full IP datagrams (header + surplus).
/// Filter to our marker port in userspace and report the trailing surplus bytes.
fn receive_loop(ready_tx: &mpsc::Sender<Result<(), SpikeError>>, result_tx: &mpsc::Sender<Result<Vec<u8>, String>>) {
    let sock = match Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::from(libc::IPPROTO_UDP)),
    ) {
        Ok(s) => s,
        Err(e) => {
            let _ = ready_tx.send(Err(SpikeError::from(e)));
            return;
        }
    };
    if let Err(e) = sock.set_read_timeout(Some(Duration::from_secs(3))) {
        let _ = ready_tx.send(Err(SpikeError::from(e)));
        return;
    }
    let _ = ready_tx.send(Ok(()));

    let mut buf = [MaybeUninit::<u8>::uninit(); 2048];
    loop {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                let _ = result_tx.send(Err(format!("recv failed: {e}")));
                return;
            }
        };
        // SAFETY: the kernel initialized the first `n` bytes of `buf`.
        let data = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
        if let Some(surplus) = match_marker(data) {
            let _ = result_tx.send(Ok(surplus.to_vec()));
            return;
        }
        // Not ours (other loopback UDP traffic): keep waiting until the read timeout fires.
    }
}

/// If `data` is one of our marker datagrams, return its surplus area (the bytes past `UDP Length`).
fn match_marker(data: &[u8]) -> Option<&[u8]> {
    if data.len() < IP_HDR_LEN {
        return None;
    }
    let ihl = ((data[0] & 0x0f) as usize) * 4;
    if ihl < IP_HDR_LEN || data[9] != libc::IPPROTO_UDP as u8 {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if total_len > data.len() || total_len < ihl + UDP_HDR_LEN {
        return None;
    }
    let udp = &data[ihl..];
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if dst_port != MARKER_PORT || udp_len != UDP_HDR_LEN {
        return None;
    }
    // Surplus area = everything after the UDP header, up to IP Total Length.
    Some(&data[ihl + UDP_HDR_LEN..total_len])
}

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

/// UDP checksum over the IPv4 pseudo-header plus the UDP header (no user data, no surplus area).
fn udp_checksum(src: Ipv4Addr, dst: Ipv4Addr, udp_header: &[u8]) -> u16 {
    let udp_len = udp_header.len() as u16;
    let mut pseudo = Vec::with_capacity(12 + udp_header.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(libc::IPPROTO_UDP as u8);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    pseudo.extend_from_slice(udp_header);
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

fn hexdump(label: &str, bytes: &[u8]) {
    print!("{label} ({} bytes):", bytes.len());
    for b in bytes {
        print!(" {b:02x}");
    }
    println!();
}
