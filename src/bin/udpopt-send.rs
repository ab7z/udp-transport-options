//! Example sender peer.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;

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

    /// Add a RES using a 4-byte hex token copied from a REQ received from this peer.
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

    /// First FRAG Identification value, consumed only by a fragmented send. Defaults to an OS-random seed.
    #[arg(long)]
    identification: Option<u32>,

    /// Print each emitted IPv4 datagram as hex.
    #[arg(long)]
    hexdump: bool,

    /// Append JSONL send metadata; `identification` is null for an unfragmented send.
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
    let mut identifications = match args.identification {
        Some(seed) => IdentificationGenerator::new(seed),
        None => IdentificationGenerator::from_os_random()?,
    };
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
        identification: None,
    };
    let sender = RawSender::new().map_err(CliError::from_socket)?;
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
        let (datagrams, identification) =
            build_datagrams_for_send(addrs, &payload, options, base_config, &mut identifications)?;
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
            let identification = identification.map_or_else(|| "null".to_owned(), |value| value.to_string());
            writeln!(
                file,
                "{{\"seq\":{seq},\"src\":\"{}\",\"dst\":\"{}\",\"src_port\":{},\"dst_port\":{},\"identification\":{},\"payload_len\":{},\"payload_crc32c\":{},\"datagrams\":{},\"bytes\":{}}}",
                args.src,
                args.dst,
                args.src_port,
                args.dst_port,
                identification,
                payload.len(),
                crc32c::crc32c(&payload),
                datagrams.len(),
                sent_bytes
            )?;
        }
    }

    Ok(())
}

fn build_datagrams_for_send(
    addrs: DatagramAddrs,
    payload: &[u8],
    options: SendOptions,
    config: SendConfig,
    identifications: &mut IdentificationGenerator,
) -> Result<(Vec<Vec<u8>>, Option<u32>), SendError> {
    debug_assert!(config.identification.is_none());
    match build_outgoing_datagrams(addrs, payload, options.clone(), config) {
        Err(SendError::FragmentIdentificationRequired) => {
            let identification = identifications.next_id()?;
            let datagrams = build_outgoing_datagrams(
                addrs,
                payload,
                options,
                SendConfig {
                    identification: Some(identification),
                    ..config
                },
            )?;
            Ok((datagrams, Some(identification)))
        }
        result => result.map(|datagrams| (datagrams, None)),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs() -> DatagramAddrs {
        DatagramAddrs {
            src: Ipv4Addr::new(192, 0, 2, 1),
            dst: Ipv4Addr::new(198, 51, 100, 2),
            src_port: 12_345,
            dst_port: 54_321,
        }
    }

    #[test]
    fn unfragmented_send_does_not_consume_or_report_an_identification() {
        let mut identifications = IdentificationGenerator::new(u32::MAX);
        let (datagrams, identification) = build_datagrams_for_send(
            addrs(),
            b"small",
            SendOptions::new(),
            SendConfig::default(),
            &mut identifications,
        )
        .unwrap();

        assert_eq!(datagrams.len(), 1);
        assert_eq!(identification, None);
        assert_eq!(identifications.next_id(), Ok(u32::MAX));
    }

    #[test]
    fn fragmented_send_consumes_and_reports_exactly_one_identification() {
        let mut identifications = IdentificationGenerator::new(u32::MAX);
        let config = SendConfig {
            max_datagram_len: 64,
            peer: PeerFragmentLimits {
                max_reassembled_size: 256,
                max_segments: 8,
            },
            ..SendConfig::default()
        };
        let (datagrams, identification) =
            build_datagrams_for_send(addrs(), &[0x5a; 80], SendOptions::new(), config, &mut identifications).unwrap();

        assert!(datagrams.len() > 1);
        assert_eq!(identification, Some(u32::MAX));
        assert!(identifications.next_id().is_err());
    }
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
