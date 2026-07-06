//! The raw send path (Linux, `IP_HDRINCL`).
//!
//! Added in Step 8: build the IP header, UDP header (with UDP Length < IP Total Length to create the
//! surplus area), and the surplus area; compute the UDP checksum and the OCS by hand; and transmit.

use std::net::Ipv4Addr;

use crate::model::length;
use crate::options::ocs;
use crate::wire::ip::IpRepr;
use crate::wire::udp::{self, UdpHeader};

/// Builds one complete IPv4 datagram, optionally carrying UDP options in the surplus area.
///
/// `options_body` must be the OCS-led body returned by [`crate::options::serialize::OptionsBuilder`]
/// with its OCS placeholder still zero, or empty to emit a plain datagram with no surplus area. This
/// function copies a non-empty body into the datagram and patches the OCS in place. It never mutates
/// the caller's slice.
///
/// # Panics
///
/// Panics if the UDP length, surplus length, or IPv4 total length cannot be represented in the
/// corresponding 16-bit wire fields, or if a non-empty `options_body` is too short to hold the OCS
/// field.
pub fn assemble_datagram(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    user_data: &[u8],
    options_body: &[u8],
) -> Vec<u8> {
    assert!(
        options_body.is_empty() || options_body.len() >= usize::from(length::OCS),
        "non-empty options body must include the OCS field"
    );

    let udp_len = udp::HEADER_LEN
        .checked_add(user_data.len())
        .expect("UDP length arithmetic overflow");
    let udp_len = u16::try_from(udp_len).expect("UDP length exceeds the 16-bit UDP Length field");
    let natural_start = usize::from(length::UDP_HEADER) + 20 + user_data.len();
    let needs_pad = !options_body.is_empty() && natural_start % 2 == 1;
    let surplus_len = if options_body.is_empty() {
        0
    } else {
        usize::from(needs_pad)
            .checked_add(options_body.len())
            .expect("surplus length arithmetic overflow")
    };
    let surplus_len_u16 = u16::try_from(surplus_len).expect("surplus length exceeds the 16-bit OCS input");
    let total_len = 20usize
        .checked_add(usize::from(udp_len))
        .and_then(|len| len.checked_add(surplus_len))
        .expect("IPv4 total length arithmetic overflow");
    let total_len_u16 = u16::try_from(total_len).expect("IPv4 total length exceeds the 16-bit Total Length field");

    let ip = IpRepr {
        src,
        dst,
        ihl: 5,
        total_len: total_len_u16,
    };
    let mut datagram = vec![0u8; total_len];
    ip.write(&mut datagram[..20]);

    let mut udp_header = UdpHeader {
        src_port,
        dst_port,
        length: udp_len,
        checksum: 0,
    };
    udp_header.checksum = udp_header.compute_checksum(&ip, user_data);
    udp_header.write(&mut datagram[20..20 + udp::HEADER_LEN]);

    let user_at = 20 + udp::HEADER_LEN;
    datagram[user_at..user_at + user_data.len()].copy_from_slice(user_data);
    let ocs_at = natural_start + usize::from(needs_pad);
    if !options_body.is_empty() {
        datagram[ocs_at..ocs_at + options_body.len()].copy_from_slice(options_body);
        ocs::compute(&mut datagram[ocs_at..ocs_at + options_body.len()], surplus_len_u16);
    }

    debug_assert_eq!(datagram.len(), usize::from(ip.total_len));
    if options_body.is_empty() {
        debug_assert_eq!(usize::from(udp_len), total_len - 20);
    } else {
        debug_assert!(usize::from(udp_len) < total_len);
    }
    datagram
}

#[cfg(target_os = "linux")]
mod platform {
    use std::io;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::AsRawFd;

    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use crate::error::SocketError;
    use crate::socket::map_socket_error;

    /// Raw IPv4 sender for UDP-options datagrams.
    #[derive(Debug)]
    pub struct RawSender {
        socket: Socket,
    }

    impl RawSender {
        /// Opens an `AF_INET SOCK_RAW IPPROTO_UDP` socket and enables `IP_HDRINCL`.
        pub fn new() -> Result<Self, SocketError> {
            let socket =
                Socket::new(Domain::IPV4, Type::from(libc::SOCK_RAW), Some(Protocol::UDP)).map_err(map_socket_error)?;
            set_hdrincl(&socket).map_err(map_socket_error)?;
            Ok(Self { socket })
        }

        /// Sends one already assembled IPv4 datagram.
        pub fn send(&self, dst: Ipv4Addr, datagram: &[u8]) -> Result<usize, SocketError> {
            let addr = SockAddr::from(SocketAddrV4::new(dst, 0));
            self.socket.send_to(datagram, &addr).map_err(map_socket_error)
        }
    }

    fn set_hdrincl(socket: &Socket) -> io::Result<()> {
        let one: libc::c_int = 1;
        // SAFETY: `socket` is a valid raw IPv4 socket; the option pointer and length match
        // `IP_HDRINCL`'s expected `c_int` payload.
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                std::ptr::addr_of!(one).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::io;
    use std::net::Ipv4Addr;

    use crate::error::SocketError;

    /// Raw IPv4 sender for UDP-options datagrams.
    #[derive(Debug, Default)]
    pub struct RawSender;

    impl RawSender {
        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn new() -> Result<Self, SocketError> {
            Err(SocketError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options send is supported on Linux only",
            )))
        }

        /// Returns [`io::ErrorKind::Unsupported`] on non-Linux hosts.
        pub fn send(&self, _dst: Ipv4Addr, _datagram: &[u8]) -> Result<usize, SocketError> {
            Err(SocketError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "raw UDP-options send is supported on Linux only",
            )))
        }
    }
}

pub use platform::RawSender;
