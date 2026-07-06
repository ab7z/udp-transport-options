#![cfg(target_os = "linux")]

use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::{Duration, Instant};

use udp_transport_options::api::{
    ApiDelivery, DatagramAddrs, FragmentationMode, ReceivePolicy, SendConfig, SendOptions, build_outgoing_datagrams,
    decode_datagram,
};
use udp_transport_options::error::SocketError;
use udp_transport_options::frag::reassembly::{ReassemblyCache, ReassemblyLimits};
use udp_transport_options::frag::split::PeerFragmentLimits;
use udp_transport_options::model::kind;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::serialize::OptionsBuilder;
use udp_transport_options::options::typed::{Mds, Mrds, Req};
use udp_transport_options::recv::pipeline::{Delivery, OptionStatus, process_datagram};
use udp_transport_options::socket::recv::RawReceiver;
use udp_transport_options::socket::send::{RawSender, assemble_datagram};

const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const RECV_TIMEOUT: Duration = Duration::from_millis(100);

#[test]
#[ignore = "requires Linux CAP_NET_RAW/root; run through scripts/vm-ubuntu-server.sh ignored"]
fn loopback_delivers_supported_options() -> Result<(), Box<dyn Error>> {
    let Some(sender) = raw_sender_or_skip()? else {
        return Ok(());
    };
    let (src_port, dst_port) = distinct_ports();
    let receiver = receiver(src_port, dst_port)?;
    let mut options = SendOptions::new().with_apc();
    options.push_typed(Mds {
        max_datagram_size: 1500,
    });
    options.push_typed(Mrds {
        max_reassembled_size: 2926,
        max_segments: 2,
    });
    options.push_typed(Req {
        token: [0xde, 0xad, 0xbe, 0xef],
    });

    let datagrams = build_outgoing_datagrams(addrs(src_port, dst_port), b"loopback", options, SendConfig::default())?;
    assert_eq!(datagrams.len(), 1);
    send_all(&sender, &datagrams)?;

    let received = recv_until(&receiver, Duration::from_secs(2))?.expect("option datagram should arrive");
    let Delivery::Payload {
        data,
        options,
        option_bearing,
        reports,
    } = process_datagram(&received, &mut ReassemblyCache::new(), Instant::now())?
    else {
        panic!("supported options should deliver one payload");
    };
    assert_eq!(data, b"loopback");
    assert!(option_bearing);
    assert!(options.iter().any(|option| option.kind == OptionKind::Apc));
    assert!(options.iter().any(|option| option.kind == OptionKind::Mds));
    assert!(options.iter().any(|option| option.kind == OptionKind::Mrds));
    assert!(options.iter().any(|option| option.kind == OptionKind::Req));
    assert!(
        reports
            .iter()
            .any(|report| report.kind == OptionKind::Apc && report.status == OptionStatus::Success)
    );

    Ok(())
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW/root; run through scripts/vm-ubuntu-server.sh ignored"]
fn loopback_discards_options_on_ocs_failure_but_delivers_payload() -> Result<(), Box<dyn Error>> {
    let Some(sender) = raw_sender_or_skip()? else {
        return Ok(());
    };
    let (src_port, dst_port) = distinct_ports();
    let receiver = receiver(src_port, dst_port)?;
    let mut builder = OptionsBuilder::new();
    builder.push(OptionKind::Req, [1, 2, 3, 4]);
    let body = builder.finish()?;
    let mut datagram = assemble_datagram(LOOPBACK, LOOPBACK, src_port, dst_port, b"ocs", &body);
    let last = datagram.len() - 1;
    datagram[last] ^= 0x01;

    send_all(&sender, &[datagram])?;
    let received = recv_until(&receiver, Duration::from_secs(2))?.expect("corrupted OCS datagram should arrive");
    let Delivery::Payload {
        data,
        options,
        option_bearing,
        reports,
    } = process_datagram(&received, &mut ReassemblyCache::new(), Instant::now())?
    else {
        panic!("OCS failure should still deliver the UDP payload");
    };
    assert_eq!(data, b"ocs");
    assert!(option_bearing);
    assert!(options.is_empty());
    assert!(reports.is_empty());

    Ok(())
}

#[test]
#[ignore = "covered by the root-gated integration lane; pure pipeline needs no privilege"]
fn fragmented_datagrams_reassemble_through_pipeline() -> Result<(), Box<dyn Error>> {
    let (src_port, dst_port) = distinct_ports();
    let config = SendConfig {
        max_datagram_len: 64,
        peer: PeerFragmentLimits {
            max_reassembled_size: 256,
            max_segments: 8,
        },
        fragmentation: FragmentationMode::Auto,
        identification: 0x0102_0304,
    };
    let payload = vec![0x5a; 80];
    let datagrams = build_outgoing_datagrams(addrs(src_port, dst_port), &payload, SendOptions::new(), config)?;
    assert!(datagrams.len() > 1);

    let mut cache = ReassemblyCache::with_limits(ReassemblyLimits {
        max_reassembled_size: 256,
        max_segments: 8,
        max_pending_partials: 8,
        timeout: udp_transport_options::model::limits::REASSEMBLY_TIMEOUT_MAX,
    });
    let mut last = ApiDelivery::Buffered;
    for datagram in &datagrams {
        last = decode_datagram(datagram, &mut cache, Instant::now(), &ReceivePolicy::default())?;
    }

    let ApiDelivery::Received(received) = last else {
        panic!("last fragment should complete reassembly");
    };
    assert_eq!(received.data, payload);
    Ok(())
}

#[test]
#[ignore = "requires Linux CAP_NET_RAW/root; run through scripts/vm-ubuntu-server.sh ignored"]
fn loopback_malformed_surplus_delivers_payload_without_options() -> Result<(), Box<dyn Error>> {
    let Some(sender) = raw_sender_or_skip()? else {
        return Ok(());
    };
    let (src_port, dst_port) = distinct_ports();
    let receiver = receiver(src_port, dst_port)?;
    let malformed_body = [0, 0, kind::REQ, 7, 1, 2, 3, 4, 5];
    let datagram = assemble_datagram(LOOPBACK, LOOPBACK, src_port, dst_port, b"bad", &malformed_body);

    send_all(&sender, &[datagram])?;
    let received = recv_until(&receiver, Duration::from_secs(2))?.expect("malformed surplus datagram should arrive");
    let Delivery::Payload {
        data,
        options,
        option_bearing,
        reports: _,
    } = process_datagram(&received, &mut ReassemblyCache::new(), Instant::now())?
    else {
        panic!("malformed surplus should still deliver the UDP payload");
    };
    assert_eq!(data, b"bad");
    assert!(option_bearing);
    assert!(options.is_empty());

    Ok(())
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
            eprintln!("skipping loopback integration test: CAP_NET_RAW/root is unavailable");
            Ok(None)
        }
        Err(error) => Err(Box::new(error)),
    }
}

fn receiver(src_port: u16, dst_port: u16) -> Result<RawReceiver, Box<dyn Error>> {
    let receiver = RawReceiver::bind(dst_port, Some(src_port), None)?;
    receiver.set_read_timeout(Some(RECV_TIMEOUT))?;
    Ok(receiver)
}

fn addrs(src_port: u16, dst_port: u16) -> DatagramAddrs {
    DatagramAddrs {
        src: LOOPBACK,
        dst: LOOPBACK,
        src_port,
        dst_port,
    }
}

fn send_all(sender: &RawSender, datagrams: &[Vec<u8>]) -> Result<(), Box<dyn Error>> {
    for datagram in datagrams {
        assert_eq!(sender.send(LOOPBACK, datagram)?, datagram.len());
    }
    Ok(())
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

fn distinct_ports() -> (u16, u16) {
    loop {
        let src = unused_port();
        let dst = unused_port();
        if src != dst {
            return (src, dst);
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
