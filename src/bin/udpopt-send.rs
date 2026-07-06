//! Example sender peer.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::Parser;
use udp_transport_options::api::{DatagramAddrs, FragmentationMode, SendConfig, SendOptions, build_outgoing_datagrams};
use udp_transport_options::error::{SendError, SocketError};
use udp_transport_options::frag::split::{IdentificationGenerator, PeerFragmentLimits};
use udp_transport_options::options::typed::{Mds, Mrds, Req, Res};
use udp_transport_options::socket::send::RawSender;

#[derive(Debug, Parser)]
#[command(version, about = "Send RFC 9868 UDP-options datagrams over a Linux raw socket")]
struct Args {
    /// Source IPv4 address to write into the packet.
    #[arg(long, default_value = "127.0.0.1")]
    src: Ipv4Addr,

    /// Destination IPv4 address.
    #[arg(long, default_value = "127.0.0.1")]
    dst: Ipv4Addr,

    /// Source UDP port.
    #[arg(long, default_value_t = 40_000)]
    src_port: u16,

    /// Destination UDP port.
    #[arg(long, default_value_t = 40_001)]
    dst_port: u16,

    /// UTF-8 payload. Ignored when --payload-hex or --payload-size is set.
    #[arg(long, default_value = "hello from udpopt-send")]
    payload: String,

    /// Payload as hex bytes, with or without spaces/colons.
    #[arg(long)]
    payload_hex: Option<String>,

    /// Generate a deterministic payload of this size. The first eight bytes carry the sequence.
    #[arg(long)]
    payload_size: Option<usize>,

    /// Number of logical datagrams to send.
    #[arg(long, default_value_t = 1)]
    count: usize,

    /// First sequence number used for generated payloads and manifest rows.
    #[arg(long, default_value_t = 0)]
    seq_start: u64,

    /// Add an automatically computed APC option.
    #[arg(long)]
    apc: bool,

    /// Add an MDS option with the given UDP payload capacity (IP MTU minus fixed IPv4/UDP headers).
    #[arg(long)]
    mds: Option<u16>,

    /// Add an MRDS option with this maximum reassembled datagram size.
    #[arg(long)]
    mrds_size: Option<u16>,

    /// MRDS maximum segment count.
    #[arg(long, default_value_t = 2)]
    mrds_segments: u8,

    /// Add a REQ option with a 4-byte hex token.
    #[arg(long)]
    req: Option<String>,

    /// Add a RES option with a 4-byte hex token.
    #[arg(long)]
    res: Option<String>,

    /// Maximum IPv4 datagram length to emit, including the IPv4 header.
    #[arg(long, default_value_t = 1500)]
    max_datagram_len: usize,

    /// Disable RFC 9868 FRAG auto-fragmentation for oversized sends.
    #[arg(long)]
    no_frag: bool,

    /// Peer MRDS reassembled-size limit used by auto-fragmentation.
    #[arg(long, default_value_t = udp_transport_options::model::limits::MRDS_DEFAULT_IPV4)]
    peer_mrds_size: u16,

    /// Peer MRDS segment-count limit used by auto-fragmentation.
    #[arg(long, default_value_t = udp_transport_options::model::limits::MIN_REASSEMBLY_SEGMENTS)]
    peer_mrds_segments: u8,

    /// First FRAG Identification value. Defaults to an OS-random seed.
    #[arg(long)]
    identification: Option<u32>,

    /// Print each emitted IPv4 datagram as hex.
    #[arg(long)]
    hexdump: bool,

    /// Append JSONL send metadata to this file.
    #[arg(long)]
    manifest: Option<PathBuf>,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Permission) => {
            eprintln!("udpopt-send: operation requires CAP_NET_RAW or root privileges");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("udpopt-send: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Args) -> Result<(), CliError> {
    if args.count == 0 {
        return Err(CliError::Message("count must be at least 1".into()));
    }

    let addrs = DatagramAddrs {
        src: args.src,
        dst: args.dst,
        src_port: args.src_port,
        dst_port: args.dst_port,
    };
    let first_identification = args.identification.unwrap_or_else(|| default_identification(&addrs));
    let base_config = SendConfig {
        max_datagram_len: args.max_datagram_len,
        peer: PeerFragmentLimits {
            max_reassembled_size: args.peer_mrds_size,
            max_segments: args.peer_mrds_segments,
        },
        fragmentation: if args.no_frag {
            FragmentationMode::Disabled
        } else {
            FragmentationMode::Auto
        },
        identification: first_identification,
    };
    let sender = RawSender::new().map_err(CliError::from_socket)?;
    let mut identifications = IdentificationGenerator::new(first_identification);
    let mut manifest = match &args.manifest {
        Some(path) => Some(OpenOptions::new().create(true).append(true).open(path)?),
        None => None,
    };

    for index in 0..args.count {
        let seq = args
            .seq_start
            .checked_add(u64::try_from(index).expect("usize index fits u64"))
            .ok_or_else(|| CliError::Message("sequence number overflow".into()))?;
        let payload = payload_for(&args, seq)?;
        let options = send_options(&args)?;
        let identification = identifications.next_id().map_err(SendError::from)?;
        let config = SendConfig {
            identification,
            ..base_config
        };
        let datagrams = build_outgoing_datagrams(addrs, &payload, options, config)?;
        let mut sent_bytes = 0usize;
        for (datagram_index, datagram) in datagrams.iter().enumerate() {
            sent_bytes = sent_bytes
                .checked_add(sender.send(args.dst, datagram).map_err(CliError::from_socket)?)
                .ok_or_else(|| CliError::Message("sent byte count overflow".into()))?;
            if args.hexdump {
                println!("datagram[{index}.{datagram_index}] {}", hex(datagram));
            }
        }
        println!(
            "sent seq={seq} payload={} datagrams={} bytes={} {}:{} -> {}:{}",
            payload.len(),
            datagrams.len(),
            sent_bytes,
            args.src,
            args.src_port,
            args.dst,
            args.dst_port
        );
        if let Some(file) = &mut manifest {
            writeln!(
                file,
                "{{\"seq\":{seq},\"src\":\"{}\",\"dst\":\"{}\",\"src_port\":{},\"dst_port\":{},\"identification\":{},\"payload_len\":{},\"datagrams\":{},\"bytes\":{}}}",
                args.src,
                args.dst,
                args.src_port,
                args.dst_port,
                identification,
                payload.len(),
                datagrams.len(),
                sent_bytes
            )?;
        }
    }

    Ok(())
}

fn default_identification(addrs: &DatagramAddrs) -> u32 {
    read_random_identification().unwrap_or_else(|_| fallback_identification(addrs))
}

fn read_random_identification() -> io::Result<u32> {
    let mut bytes = [0u8; 4];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(usable_identification(u32::from_ne_bytes(bytes)))
}

fn fallback_identification(addrs: &DatagramAddrs) -> u32 {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut seed = now.as_secs() ^ u64::from(now.subsec_nanos());
    seed ^= u64::from(std::process::id()) << 32;
    seed ^= u64::from(u32::from(addrs.src)) << 16;
    seed ^= u64::from(u32::from(addrs.dst));
    seed ^= u64::from(addrs.src_port) << 48;
    seed ^= u64::from(addrs.dst_port);
    usable_identification(mix64(seed) as u32)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 33;
    value = value.wrapping_mul(0xff51afd7ed558ccd);
    value ^= value >> 33;
    value = value.wrapping_mul(0xc4ceb9fe1a85ec53);
    value ^ (value >> 33)
}

fn usable_identification(identification: u32) -> u32 {
    if identification == u32::MAX { 0 } else { identification }
}

fn payload_for(args: &Args, seq: u64) -> Result<Vec<u8>, CliError> {
    if let Some(hex_payload) = &args.payload_hex {
        return parse_hex_vec(hex_payload);
    }
    if let Some(len) = args.payload_size {
        let mut payload = vec![0u8; len];
        let seq_bytes = seq.to_be_bytes();
        let prefix_len = payload.len().min(seq_bytes.len());
        payload[..prefix_len].copy_from_slice(&seq_bytes[..prefix_len]);
        for (index, byte) in payload.iter_mut().enumerate().skip(prefix_len) {
            *byte = (index % 256) as u8;
        }
        return Ok(payload);
    }
    Ok(args.payload.as_bytes().to_vec())
}

fn send_options(args: &Args) -> Result<SendOptions, CliError> {
    let mut options = SendOptions::new();
    if args.apc {
        options = options.with_apc();
    }
    if let Some(max_datagram_size) = args.mds {
        options.push_typed(Mds { max_datagram_size });
    }
    if let Some(max_reassembled_size) = args.mrds_size {
        options.push_typed(Mrds {
            max_reassembled_size,
            max_segments: args.mrds_segments,
        });
    }
    if let Some(token) = &args.req {
        options.push_typed(Req {
            token: parse_token(token)?,
        });
    }
    if let Some(token) = &args.res {
        options.push_typed(Res {
            token: parse_token(token)?,
        });
    }
    Ok(options)
}

fn parse_token(input: &str) -> Result<[u8; 4], CliError> {
    let bytes = parse_hex_vec(input)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| CliError::Message(format!("token must be exactly 4 bytes, got {}", bytes.len())))
}

fn parse_hex_vec(input: &str) -> Result<Vec<u8>, CliError> {
    let clean: String = input
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':' && *c != '_')
        .collect();
    if !clean.len().is_multiple_of(2) {
        return Err(CliError::Message(
            "hex input must contain an even number of digits".into(),
        ));
    }
    let mut bytes = Vec::with_capacity(clean.len() / 2);
    for pair in clean.as_bytes().chunks_exact(2) {
        let text = std::str::from_utf8(pair).expect("hex pair came from a UTF-8 string");
        let byte = u8::from_str_radix(text, 16).map_err(|_| CliError::Message(format!("invalid hex byte '{text}'")))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Send(#[from] SendError),
    #[error("permission denied")]
    Permission,
}

impl CliError {
    fn from_socket(error: SocketError) -> Self {
        match error {
            SocketError::PermissionDenied => Self::Permission,
            other => Self::Send(SendError::Socket(other)),
        }
    }
}
