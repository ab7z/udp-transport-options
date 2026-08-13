#![cfg(target_os = "linux")]

mod common_assemble;

use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use udp_transport_options::error::SocketError;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::parse::OptionsIter;
use udp_transport_options::options::serialize::OptionsBuilder;
use udp_transport_options::options::typed::{Res, TypedOption};
use udp_transport_options::socket::recv::RawReceiver;
use udp_transport_options::socket::send::{RawSender, assemble_datagram};

const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const RECV_TIMEOUT: Duration = Duration::from_millis(100);
// The fixture models a token previously received from the peer in a REQ.
const RES_TOKEN: [u8; 4] = [5, 6, 7, 8];

#[test]
#[ignore = "requires Linux CAP_NET_RAW/root; run through scripts/vm-ubuntu-server.sh ignored"]
fn loopback_round_trip_preserves_surplus_and_filters_ports() -> Result<(), Box<dyn Error>> {
    let Some(sender) = raw_sender_or_skip()? else {
        return Ok(());
    };
    let options_body = options_body();

    let (src_port, dst_port, _) = distinct_ports();
    let receiver = RawReceiver::bind(dst_port, Some(src_port), None)?;
    receiver.set_read_timeout(Some(RECV_TIMEOUT))?;
    let user_data = b"hello";
    let datagram = assemble_datagram(LOOPBACK, LOOPBACK, src_port, dst_port, user_data, &options_body);

    let sent = sender.send(LOOPBACK, &datagram)?;
    assert_eq!(sent, datagram.len());

    let received = recv_until(&receiver, Duration::from_secs(2))?.expect("loopback datagram should arrive");
    common_assemble::check_datagram_matches(
        &received,
        LOOPBACK,
        LOOPBACK,
        src_port,
        dst_port,
        user_data,
        &options_body,
    );
    let res = OptionsIter::new(&options_body[2..])
        .map(|option| option.expect("fixed options body should parse"))
        .find(|option| option.kind == OptionKind::Res)
        .expect("round-tripped options should contain RES");
    assert_eq!(Res::decode(res.value)?.token, RES_TOKEN);

    let (filter_src_port, filter_dst_port, wrong_dst_port) = distinct_ports();
    let filter_receiver = RawReceiver::bind(filter_dst_port, Some(filter_src_port), None)?;
    filter_receiver.set_read_timeout(Some(RECV_TIMEOUT))?;
    let _wrong_sink = UdpSocket::bind(SocketAddrV4::new(LOOPBACK, wrong_dst_port))?;
    let wrong_datagram = assemble_datagram(
        LOOPBACK,
        LOOPBACK,
        filter_src_port,
        wrong_dst_port,
        b"ignored",
        &options_body,
    );

    let sent = sender.send(LOOPBACK, &wrong_datagram)?;
    assert_eq!(sent, wrong_datagram.len());
    assert!(recv_until(&filter_receiver, Duration::from_millis(600))?.is_none());

    let (expected_src_port, wrong_src_port, shared_dst_port) = distinct_ports();
    let src_filter_receiver = RawReceiver::bind(shared_dst_port, Some(expected_src_port), None)?;
    src_filter_receiver.set_read_timeout(Some(RECV_TIMEOUT))?;
    let wrong_src_datagram = assemble_datagram(
        LOOPBACK,
        LOOPBACK,
        wrong_src_port,
        shared_dst_port,
        b"wrong-src",
        &options_body,
    );

    let sent = sender.send(LOOPBACK, &wrong_src_datagram)?;
    assert_eq!(sent, wrong_src_datagram.len());
    assert!(recv_until(&src_filter_receiver, Duration::from_millis(600))?.is_none());

    let (own_src_port, own_dst_port, _) = distinct_ports();
    let own_src_receiver = RawReceiver::bind(own_dst_port, Some(own_src_port), Some(LOOPBACK))?;
    own_src_receiver.set_read_timeout(Some(RECV_TIMEOUT))?;
    let own_src_datagram = assemble_datagram(
        LOOPBACK,
        LOOPBACK,
        own_src_port,
        own_dst_port,
        b"own-source",
        &options_body,
    );

    let sent = sender.send(LOOPBACK, &own_src_datagram)?;
    assert_eq!(sent, own_src_datagram.len());
    assert!(recv_until(&own_src_receiver, Duration::from_millis(600))?.is_none());

    Ok(())
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW/root; run through scripts/vm-ubuntu-server.sh ignored"]
fn recv_deadline_holds_under_filtered_noise() -> Result<(), Box<dyn Error>> {
    // Follow-up to the PR 27 review: SO_RCVTIMEO re-arms per raw read, so before the deadline fix
    // a steady stream of filtered datagrams kept `recv` from ever returning `None`.
    let (src_port, dst_port, noise_port) = distinct_ports();
    let receiver = match RawReceiver::bind(dst_port, Some(src_port), None) {
        Ok(receiver) => receiver,
        Err(SocketError::PermissionDenied) => {
            if std::env::var_os("ACHIM_SUDO").is_some() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ACHIM_SUDO=1 but CAP_NET_RAW/root is unavailable",
                )));
            }
            eprintln!("skipping raw-socket deadline test: CAP_NET_RAW/root is unavailable");
            return Ok(());
        }
        Err(error) => return Err(Box::new(error)),
    };
    receiver.set_read_timeout(Some(Duration::from_millis(300)))?;

    // Bound to the noise target port: suppresses ICMP port-unreachable and later proves that
    // noise really flowed while `recv` was blocking.
    let noise_sink = UdpSocket::bind(SocketAddrV4::new(LOOPBACK, noise_port))?;
    noise_sink.set_nonblocking(true)?;

    // The noise source is a child process, not a thread (repo rule: no threads anywhere,
    // including tests): this test binary re-invoked on the `noise_sender_child` helper.
    let mut noise = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", "noise_sender_child"])
        .env("NOISE_TARGET_PORT", noise_port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let start = Instant::now();
    let result = receiver.recv();
    let elapsed = start.elapsed();
    let _ = noise.kill();
    noise.wait()?;

    let mut sink_buf = [0u8; 16];
    let noise_flowed = noise_sink.recv_from(&mut sink_buf).is_ok();

    eprintln!("recv elapsed under filtered noise: {elapsed:?}");
    assert!(result?.is_none(), "no datagram matches the src/dst port filters");
    assert!(
        noise_flowed,
        "the noise child never delivered a datagram; the run proves nothing"
    );
    assert!(
        elapsed >= Duration::from_millis(250),
        "recv returned before the deadline: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "recv did not honor the deadline under filtered noise: {elapsed:?}"
    );
    Ok(())
}

/// Helper for `recv_deadline_holds_under_filtered_noise`, run as a child process. Without
/// `NOISE_TARGET_PORT` in the environment (the normal `--ignored` lane) it is a no-op.
#[test]
#[ignore = "no-op helper; driven by recv_deadline_holds_under_filtered_noise via NOISE_TARGET_PORT"]
fn noise_sender_child() {
    let Ok(port) = std::env::var("NOISE_TARGET_PORT") else {
        return;
    };
    let port: u16 = port.parse().expect("NOISE_TARGET_PORT is a UDP port number");
    let socket = UdpSocket::bind(SocketAddrV4::new(LOOPBACK, 0)).expect("noise source socket");
    // Datagrams well inside the parent's 300 ms timeout, hard-capped so a regression in the
    // parent fails its elapsed assertion instead of hanging both processes.
    for _ in 0..200 {
        let _ = socket.send_to(b"noise", SocketAddrV4::new(LOOPBACK, port));
        thread::sleep(Duration::from_millis(25));
    }
}

fn raw_sender_or_skip() -> Result<Option<RawSender>, Box<dyn Error>> {
    match RawSender::new() {
        Ok(sender) => Ok(Some(sender)),
        Err(SocketError::PermissionDenied) => {
            if std::env::var_os("ACHIM_SUDO").is_some() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "ACHIM_SUDO=1 but CAP_NET_RAW/root is unavailable",
                )));
            }
            eprintln!("skipping raw-socket loopback test: CAP_NET_RAW/root is unavailable");
            Ok(None)
        }
        Err(error) => Err(Box::new(error)),
    }
}

fn options_body() -> Vec<u8> {
    let mut builder = OptionsBuilder::new();
    builder.push(OptionKind::Req, [1, 2, 3, 4]);
    builder.push(OptionKind::Res, RES_TOKEN);
    builder.finish().expect("fixed options are serializable")
}

fn recv_until(receiver: &RawReceiver, timeout: Duration) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(datagram) = receiver.recv()? {
            return Ok(Some(datagram));
        }
    }
    Ok(None)
}

fn distinct_ports() -> (u16, u16, u16) {
    loop {
        let a = unused_port();
        let b = unused_port();
        let c = unused_port();
        if a != b && a != c && b != c {
            return (a, b, c);
        }
    }
}

fn unused_port() -> u16 {
    UdpSocket::bind(SocketAddrV4::new(LOOPBACK, 0))
        .expect("ephemeral loopback port")
        .local_addr()
        .expect("local addr")
        .port()
}
