//! The raw receive path (Linux, `SOCK_RAW` `IPPROTO_UDP`).
//!
//! Added in Step 8: read full IP datagrams with the surplus area intact, filter by destination port,
//! and hand the bytes to the receive pipeline. Mitigates raw-socket noise (own-source copies and
//! ICMP port-unreachable when no normal UDP socket is bound).

use std::net::Ipv4Addr;

use crate::error::HeaderError;
use crate::recv::pipeline::warn_udp_length_below_min;
use crate::wire::ip::IpRepr;
use crate::wire::udp::UdpHeader;

/// The userspace demux decision for one raw datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
enum FilterVerdict {
    /// The datagram matches the filters; deliver its first `len` bytes (the IPv4 Total Length).
    Deliver { len: usize },
    /// Noise: unparseable headers, an own-source copy, or a port mismatch. A raw `IPPROTO_UDP`
    /// socket sees every UDP datagram on the host, so on a public host this is the common case;
    /// it must never end a receive call the way a timeout does.
    Filtered,
}

/// Applies the userspace demux filters to one raw IPv4 datagram.
///
/// Only enough header state is parsed to demux; the UDP checksum, the OCS, and option semantics
/// stay with the pure receive pipeline. A UDP Length below eight is sampled-logged here because it
/// cannot safely reach that pipeline.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn filter_datagram(data: &[u8], dst_port: u16, src_port: Option<u16>, own_src: Option<Ipv4Addr>) -> FilterVerdict {
    let Ok((ip, udp_at)) = IpRepr::parse(data) else {
        return FilterVerdict::Filtered;
    };
    let udp = match UdpHeader::parse(&data[udp_at..]) {
        Ok(udp) => udp,
        Err(HeaderError::UdpLengthInvalid { length }) => {
            warn_udp_length_below_min(length);
            return FilterVerdict::Filtered;
        }
        Err(_) => return FilterVerdict::Filtered,
    };
    if own_src == Some(ip.src) {
        return FilterVerdict::Filtered;
    }
    if udp.dst_port != dst_port {
        return FilterVerdict::Filtered;
    }
    if src_port.is_some_and(|src_port| udp.src_port != src_port) {
        return FilterVerdict::Filtered;
    }
    FilterVerdict::Deliver {
        len: usize::from(ip.total_len),
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::time::{Duration, Instant};

    use socket2::{Domain, Protocol, Socket, Type};

    use super::{FilterVerdict, filter_datagram};
    use crate::error::SocketError;
    use crate::socket::map_socket_error;

    const RECV_BUF_LEN: usize = u16::MAX as usize;

    /// Lower bound for the per-read `SO_RCVTIMEO` while a deadline is pending: a zero timeout
    /// means "block forever" to the kernel.
    const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

    /// Raw IPv4 receiver for UDP datagrams, with userspace port filtering.
    #[derive(Debug)]
    pub struct RawReceiver {
        socket: Socket,
        _icmp_sink: UdpSocket,
        dst_port: u16,
        src_port: Option<u16>,
        own_src: Option<Ipv4Addr>,
    }

    impl RawReceiver {
        /// Opens an `AF_INET SOCK_RAW IPPROTO_UDP` receiver and binds a dummy UDP socket on
        /// `dst_port` to suppress kernel ICMP port-unreachable noise.
        pub fn bind(dst_port: u16, src_port: Option<u16>, own_src: Option<Ipv4Addr>) -> Result<Self, SocketError> {
            let socket =
                Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::UDP)).map_err(map_socket_error)?;
            let icmp_sink =
                UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, dst_port)).map_err(map_socket_error)?;
            Ok(Self {
                socket,
                _icmp_sink: icmp_sink,
                dst_port,
                src_port,
                own_src,
            })
        }

        /// Configures the raw receive timeout: the total deadline one [`Self::recv`] call may
        /// spend waiting, including time spent skipping filtered datagrams.
        ///
        /// `Some(Duration::ZERO)` is indistinguishable from `None` at the `SO_RCVTIMEO` level
        /// and therefore also means "block forever".
        pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), SocketError> {
            self.socket.set_read_timeout(timeout).map_err(map_socket_error)
        }

        /// Receives raw datagrams until one matches the userspace demux filters; `Ok(None)` means
        /// the configured read timeout expired without a match.
        ///
        /// Filtered datagrams (unparseable headers, own-source copies, port mismatches) never end
        /// the call: the loop keeps reading through them. The configured timeout bounds the whole
        /// call as one deadline, including the time spent skipping filtered datagrams:
        /// `SO_RCVTIMEO` is re-armed with the remaining time before each raw read, so steady
        /// unrelated traffic cannot extend the wait indefinitely. Without a configured timeout the
        /// call blocks until a match arrives. Concurrent `recv` calls on a shared reference are
        /// unsupported: the deadline re-arms `SO_RCVTIMEO` on the shared socket (the repository
        /// is single-threaded by contract).
        ///
        /// This method only parses enough header state to apply the userspace demux filters. It does
        /// not validate the UDP checksum, OCS, or option semantics; the pure receive pipeline owns
        /// those decisions in Step 10. A UDP Length below eight is dropped here and emitted through
        /// the `log` facade because it cannot safely reach that pipeline; applications embedding the
        /// library must install a logger to retain this required diagnostic.
        pub fn recv(&self) -> Result<Option<Vec<u8>>, SocketError> {
            let configured = self.socket.read_timeout().map_err(map_socket_error)?;
            // A timeout too large for the monotonic clock is as good as no deadline.
            let Some(deadline) = configured.and_then(|timeout| Instant::now().checked_add(timeout)) else {
                return self.recv_with_deadline(None);
            };
            let result = self.recv_with_deadline(Some(deadline));
            // recv_with_deadline shrinks SO_RCVTIMEO towards the deadline; restore the configured
            // value so the next call starts from a full timeout again. If the restore fails, the
            // error is surfaced and the socket may keep the shrunk value until the next
            // successful set_read_timeout.
            let restored = self.socket.set_read_timeout(configured).map_err(map_socket_error);
            match (result, restored) {
                (Ok(value), Ok(())) => Ok(value),
                (Err(error), _) | (Ok(_), Err(error)) => Err(error),
            }
        }

        fn recv_with_deadline(&self, deadline: Option<Instant>) -> Result<Option<Vec<u8>>, SocketError> {
            let mut buf = [MaybeUninit::<u8>::uninit(); RECV_BUF_LEN];
            loop {
                if let Some(deadline) = deadline {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Ok(None);
                    }
                    self.socket
                        .set_read_timeout(Some(remaining.max(MIN_READ_TIMEOUT)))
                        .map_err(map_socket_error)?;
                }
                let n = match self.socket.recv(&mut buf) {
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                        return Ok(None);
                    }
                    Err(e) => return Err(map_socket_error(e)),
                };

                // SAFETY: `socket2::Socket::recv` initialized exactly the first `n` bytes.
                let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
                match filter_datagram(data, self.dst_port, self.src_port, self.own_src) {
                    FilterVerdict::Deliver { len } => return Ok(Some(data[..len].to_vec())),
                    FilterVerdict::Filtered => {}
                }
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::io;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::error::SocketError;

    /// Raw IPv4 receiver for UDP datagrams, with userspace port filtering.
    #[derive(Debug, Default)]
    pub struct RawReceiver;

    impl RawReceiver {
        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn bind(_dst_port: u16, _src_port: Option<u16>, _own_src: Option<Ipv4Addr>) -> Result<Self, SocketError> {
            Err(SocketError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options receive is supported on Linux only",
            )))
        }

        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<(), SocketError> {
            Err(SocketError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options receive is supported on Linux only",
            )))
        }

        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn recv(&self) -> Result<Option<Vec<u8>>, SocketError> {
            Err(SocketError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options receive is supported on Linux only",
            )))
        }
    }
}

pub use platform::RawReceiver;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{FilterVerdict, filter_datagram};
    use crate::wire::ip::IpRepr;
    use crate::wire::udp::{HEADER_LEN, UdpHeader};

    const SRC: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const DST: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
    const SRC_PORT: u16 = 40_000;
    const DST_PORT: u16 = 40_001;

    fn datagram(src: Ipv4Addr, src_port: u16, dst_port: u16, user_data: &[u8]) -> Vec<u8> {
        let udp_len = HEADER_LEN + user_data.len();
        let total_len = 20 + udp_len;
        let ip = IpRepr {
            src,
            dst: DST,
            ihl: 5,
            total_len: u16::try_from(total_len).expect("test datagram fits in u16"),
        };
        let mut out = vec![0u8; total_len];
        ip.write(&mut out);
        UdpHeader {
            src_port,
            dst_port,
            length: u16::try_from(udp_len).expect("test UDP length fits in u16"),
            checksum: 0,
        }
        .write(&mut out[20..]);
        out[28..].copy_from_slice(user_data);
        out
    }

    #[test]
    fn matching_datagram_is_delivered_truncated_to_ip_total_len() {
        let mut data = datagram(SRC, SRC_PORT, DST_PORT, b"hello");
        let total_len = data.len();
        data.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            filter_datagram(&data, DST_PORT, Some(SRC_PORT), None),
            FilterVerdict::Deliver { len: total_len }
        );
    }

    #[test]
    fn absent_src_port_filter_accepts_any_source_port() {
        let data = datagram(SRC, 55_555, DST_PORT, b"x");
        let len = data.len();
        assert_eq!(
            filter_datagram(&data, DST_PORT, None, None),
            FilterVerdict::Deliver { len }
        );
    }

    #[test]
    fn foreign_traffic_is_filtered() {
        // The public-host regression: each of these datagrams ended `udpopt-recv` silently.
        let wrong_dst = datagram(SRC, SRC_PORT, DST_PORT + 1, b"scan");
        assert_eq!(
            filter_datagram(&wrong_dst, DST_PORT, Some(SRC_PORT), None),
            FilterVerdict::Filtered
        );

        let wrong_src = datagram(SRC, SRC_PORT + 1, DST_PORT, b"scan");
        assert_eq!(
            filter_datagram(&wrong_src, DST_PORT, Some(SRC_PORT), None),
            FilterVerdict::Filtered
        );

        let own_copy = datagram(SRC, SRC_PORT, DST_PORT, b"echo");
        assert_eq!(
            filter_datagram(&own_copy, DST_PORT, Some(SRC_PORT), Some(SRC)),
            FilterVerdict::Filtered
        );
    }

    #[test]
    fn unparseable_headers_are_filtered() {
        assert_eq!(filter_datagram(&[], DST_PORT, None, None), FilterVerdict::Filtered);

        let valid = datagram(SRC, SRC_PORT, DST_PORT, b"ok");
        assert_eq!(
            filter_datagram(&valid[..19], DST_PORT, None, None),
            FilterVerdict::Filtered
        );

        let mut ip_only = vec![0u8; 20];
        IpRepr {
            src: SRC,
            dst: DST,
            ihl: 5,
            total_len: 20,
        }
        .write(&mut ip_only);
        assert_eq!(filter_datagram(&ip_only, DST_PORT, None, None), FilterVerdict::Filtered);

        let mut bad_udp_len = datagram(SRC, SRC_PORT, DST_PORT, b"");
        bad_udp_len[24..26].copy_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            filter_datagram(&bad_udp_len, DST_PORT, None, None),
            FilterVerdict::Filtered
        );
    }
}
