//! The raw receive path (Linux, `SOCK_RAW` `IPPROTO_UDP`).
//!
//! Added in Step 8: read full IP datagrams with the surplus area intact, filter by destination port,
//! and hand the bytes to the receive pipeline. Mitigates raw-socket noise (own-source copies and
//! ICMP port-unreachable when no normal UDP socket is bound).

#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
    use std::time::Duration;

    use socket2::{Domain, Protocol, Socket, Type};

    use crate::error::RecvError;
    use crate::socket::map_socket_error;
    use crate::wire::ip::IpRepr;
    use crate::wire::udp::UdpHeader;

    const RECV_BUF_LEN: usize = u16::MAX as usize;

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
        pub fn bind(dst_port: u16, src_port: Option<u16>, own_src: Option<Ipv4Addr>) -> Result<Self, RecvError> {
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

        /// Configures the raw receive timeout.
        pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), RecvError> {
            self.socket.set_read_timeout(timeout).map_err(map_socket_error)
        }

        /// Receives one matching raw IPv4 datagram, or `Ok(None)` for timeouts and filtered packets.
        ///
        /// This method only parses enough header state to apply the userspace demux filters. It does
        /// not validate the UDP checksum, OCS, or option semantics; the pure receive pipeline owns
        /// those decisions in Step 10.
        pub fn recv(&self) -> Result<Option<Vec<u8>>, RecvError> {
            let mut buf = [MaybeUninit::<u8>::uninit(); RECV_BUF_LEN];
            let n = match self.socket.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut => {
                    return Ok(None);
                }
                Err(e) => return Err(map_socket_error(e)),
            };

            // SAFETY: `socket2::Socket::recv` initialized exactly the first `n` bytes.
            let data = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), n) };
            let Ok((ip, udp_at)) = IpRepr::parse(data) else {
                return Ok(None);
            };
            if self.own_src == Some(ip.src) {
                return Ok(None);
            }

            let Ok(udp) = UdpHeader::parse(&data[udp_at..]) else {
                return Ok(None);
            };
            if udp.dst_port != self.dst_port {
                return Ok(None);
            }
            if self.src_port.is_some_and(|src_port| udp.src_port != src_port) {
                return Ok(None);
            }

            let datagram_len = usize::from(ip.total_len);
            Ok(Some(data[..datagram_len].to_vec()))
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::io;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use crate::error::RecvError;

    /// Raw IPv4 receiver for UDP datagrams, with userspace port filtering.
    #[derive(Debug, Default)]
    pub struct RawReceiver;

    impl RawReceiver {
        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn bind(_dst_port: u16, _src_port: Option<u16>, _own_src: Option<Ipv4Addr>) -> Result<Self, RecvError> {
            Err(RecvError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options receive is supported on Linux only",
            )))
        }

        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn set_read_timeout(&self, _timeout: Option<Duration>) -> Result<(), RecvError> {
            Err(RecvError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options receive is supported on Linux only",
            )))
        }

        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn recv(&self) -> Result<Option<Vec<u8>>, RecvError> {
            Err(RecvError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options receive is supported on Linux only",
            )))
        }
    }
}

pub use platform::RawReceiver;
