#![cfg(target_os = "linux")]

mod common_assemble;

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::serialize::OptionsBuilder;
use udp_transport_options::socket::recv::RawReceiver;
use udp_transport_options::socket::send::{RawSender, assemble_datagram};

const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const RECV_TIMEOUT: Duration = Duration::from_millis(100);

#[test]
#[ignore = "requires Linux CAP_NET_RAW/root; run through scripts/vm-ubuntu-server.sh ignored"]
fn loopback_round_trip_preserves_surplus_and_filters_ports() -> Result<(), Box<dyn Error>> {
    let sender = RawSender::new()?;
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

fn options_body() -> Vec<u8> {
    let mut builder = OptionsBuilder::new();
    builder.push(OptionKind::Req, [1, 2, 3, 4]);
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
