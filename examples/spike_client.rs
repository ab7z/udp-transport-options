//! Step 0.5 spike -- client. Runs in the **default** netns (source 10.0.0.1) and raw-sends each
//! case's hand-built IPv4+UDP datagram across the staged 1500-MTU veth link to the server
//! (10.0.0.2, netns `spk`). Throwaway; see `scripts/spike.sh` and `docs/plan/steps/00b-spike.md`.
//!
//! It gates the send-limit finding (`over-mtu` must fail `EMSGSIZE`); the server gates delivery.
//! Not run directly -- `scripts/spike.sh` builds it and runs it after the server is listening:
//!
//! ```text
//! docker compose run --rm dev sudo -E scripts/spike.sh
//! ```
//!
//! The `unsafe` here (raw `IP_HDRINCL` setsockopt, in `common`) is deliberately inline and minimal;
//! the production path confines all `unsafe` behind safe wrappers in `src/socket/`.

mod common;

use std::net::SocketAddrV4;
use std::process;
use std::thread;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use common::{CASES, CLIENT_IP, Check, SERVER_IP, SRC_PORT, SpikeError, build_datagram, marker_port};

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

    println!(
        "spike_client: {CLIENT_IP} -> {SERVER_IP} (src port {SRC_PORT}), {} cases",
        CASES.len()
    );
    // The destination IP comes from our IP header for an IP_HDRINCL socket; the sockaddr port is
    // ignored, so any port is fine here.
    let dest = SockAddr::from(SocketAddrV4::new(SERVER_IP, 0));

    let mut client_ok = true;
    for (i, case) in CASES.iter().enumerate() {
        let port = marker_port(i);
        let pkt = build_datagram(case, port);
        let label = case.label;
        let phys = case.physical_len();
        let result = sock.send_to(&pkt, &dest);
        match case.check {
            Check::Wire => match result {
                Ok(n) => println!("  {label:<13} port {port} physical={phys} -> sent {n}B"),
                Err(e) => {
                    println!("  {label:<13} port {port} physical={phys} -> FAIL unexpected send error: {e}");
                    client_ok = false;
                }
            },
            Check::SendFails => match result {
                Err(ref e) if e.raw_os_error() == Some(libc::EMSGSIZE) => {
                    println!(
                        "  {label:<13} port {port} physical={phys} -> PASS got EMSGSIZE (Finding B: IP_HDRINCL won't fragment)"
                    );
                }
                Ok(n) => {
                    println!("  {label:<13} port {port} physical={phys} -> FAIL expected EMSGSIZE but sent {n}B");
                    client_ok = false;
                }
                Err(e) => {
                    println!("  {label:<13} port {port} physical={phys} -> FAIL expected EMSGSIZE, got: {e}");
                    client_ok = false;
                }
            },
        }
        // Small gap so each case drains before the next (clean tcpdump, less reorder).
        thread::sleep(Duration::from_millis(30));
    }

    println!(
        "spike_client: {}",
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
    common::set_hdrincl(&sock)?;
    Ok(sock)
}
