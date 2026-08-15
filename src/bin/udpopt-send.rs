//! Example sender peer.

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::thread::sleep;
use std::time::Duration;

use clap::Parser;
use udp_transport_options::api::{DatagramAddrs, FragmentationMode, SendConfig, SendOptions, build_outgoing_datagrams};
use udp_transport_options::error::{SendError, SocketError};
use udp_transport_options::frag::split::{IdentificationGenerator, PeerFragmentLimits};
use udp_transport_options::model::length;
use udp_transport_options::options::typed::{Mds, Mrds, Req, Res};
use udp_transport_options::socket::send::{RawSender, assemble_datagram};

const IPV4_HEADER_LEN: usize = 20;
const UDP_LENGTH_AT: usize = IPV4_HEADER_LEN + 4;
const UDP_CHECKSUM_AT: usize = IPV4_HEADER_LEN + 6;

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

    /// Raw surplus-area option bytes, written after the two-byte OCS field, which stays correct.
    /// Replaces the built option set and is never fragmented.
    #[arg(long)]
    raw_options_hex: Option<String>,

    /// Overwrite the two-byte OCS field after the correct value was computed.
    #[arg(long)]
    ocs_hex: Option<String>,

    /// Overwrite the surplus-area alignment pad byte, which exists only for an odd payload length.
    #[arg(long)]
    pad_hex: Option<String>,

    /// Write a zero UDP checksum field after assembly.
    #[arg(long)]
    udp_cksum_zero: bool,

    /// Emit only these datagram indices of every logical send, in this order. Repeat an index to
    /// duplicate that datagram; omit one to drop it.
    #[arg(long, value_delimiter = ',')]
    frag_emit: Option<Vec<usize>>,

    /// Wait this many milliseconds between the emitted datagrams of one logical send.
    #[arg(long, default_value_t = 0)]
    frag_gap_ms: u64,

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
    if args.raw_options_hex.is_some() && builds_options(&args) {
        return Err(CliError::Message(
            "--raw-options-hex replaces the option set; drop --apc, --mds, --mrds-size, --req and --res".into(),
        ));
    }
    let faults = WireFaults::parse(&args)?;

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
        let (mut datagrams, identification) = match &args.raw_options_hex {
            Some(body_hex) => (vec![raw_options_datagram(&args, &payload, body_hex)?], None),
            None => {
                let options = send_options(&args)?;
                build_datagrams_for_send(addrs, &payload, options, base_config, &mut identifications)?
            }
        };
        for datagram in &mut datagrams {
            faults.apply(datagram)?;
        }
        let order = emit_order(args.frag_emit.as_deref(), datagrams.len())?;
        let mut sent_bytes = 0usize;
        for (position, datagram_index) in order.iter().copied().enumerate() {
            if position > 0 && args.frag_gap_ms > 0 {
                sleep(Duration::from_millis(args.frag_gap_ms));
            }
            let datagram = &datagrams[datagram_index];
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
            order.len(),
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
                order.len(),
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

/// Builds one datagram whose surplus area carries caller-supplied option bytes verbatim.
///
/// The OCS stays correct, so a receiver rejecting the datagram rejects the option bytes themselves
/// and not their checksum. Use `--ocs-hex` to break the OCS on purpose.
fn raw_options_datagram(args: &Args, payload: &[u8], body_hex: &str) -> Result<Vec<u8>, CliError> {
    let mut body = vec![0u8; usize::from(length::OCS)];
    body.extend_from_slice(&parse_hex_vec(body_hex)?);
    let upper_bound = IPV4_HEADER_LEN + usize::from(length::UDP_HEADER) + payload.len() + 1 + body.len();
    if upper_bound > usize::from(u16::MAX) {
        return Err(CliError::Message(format!(
            "raw-options datagram exceeds the 16-bit length fields: up to {upper_bound} bytes"
        )));
    }

    let datagram = assemble_datagram(args.src, args.dst, args.src_port, args.dst_port, payload, &body);
    if datagram.len() > args.max_datagram_len {
        return Err(CliError::Message(format!(
            "raw-options datagram is too large: {} bytes, max {} bytes",
            datagram.len(),
            args.max_datagram_len
        )));
    }
    Ok(datagram)
}

/// Where the surplus area of an assembled datagram begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SurplusLayout {
    starts_at: usize,
    needs_pad: bool,
}

impl SurplusLayout {
    fn ocs_at(self) -> usize {
        self.starts_at + usize::from(self.needs_pad)
    }
}

fn surplus_layout(datagram: &[u8]) -> Option<SurplusLayout> {
    if datagram.len() < IPV4_HEADER_LEN + usize::from(length::UDP_HEADER) {
        return None;
    }
    let udp_len = usize::from(u16::from_be_bytes([
        datagram[UDP_LENGTH_AT],
        datagram[UDP_LENGTH_AT + 1],
    ]));
    let starts_at = IPV4_HEADER_LEN.checked_add(udp_len)?;
    (starts_at < datagram.len()).then_some(SurplusLayout {
        starts_at,
        needs_pad: !starts_at.is_multiple_of(2),
    })
}

/// Deliberate wire faults applied to every assembled datagram.
#[derive(Debug, Default)]
struct WireFaults {
    ocs: Option<[u8; 2]>,
    pad: Option<u8>,
    zero_udp_checksum: bool,
}

impl WireFaults {
    fn parse(args: &Args) -> Result<Self, CliError> {
        Ok(Self {
            ocs: args.ocs_hex.as_deref().map(parse_ocs_field).transpose()?,
            pad: args.pad_hex.as_deref().map(parse_pad_byte).transpose()?,
            zero_udp_checksum: args.udp_cksum_zero,
        })
    }

    fn apply(&self, datagram: &mut [u8]) -> Result<(), CliError> {
        if self.zero_udp_checksum {
            datagram[UDP_CHECKSUM_AT..UDP_CHECKSUM_AT + 2].fill(0);
        }
        if self.ocs.is_none() && self.pad.is_none() {
            return Ok(());
        }

        let layout = surplus_layout(datagram)
            .ok_or_else(|| CliError::Message("--ocs-hex and --pad-hex need a datagram with a surplus area".into()))?;
        if let Some(pad) = self.pad {
            if !layout.needs_pad {
                return Err(CliError::Message(
                    "--pad-hex needs an alignment pad, which only an odd payload length creates".into(),
                ));
            }
            datagram[layout.starts_at] = pad;
        }
        if let Some(ocs) = self.ocs {
            datagram[layout.ocs_at()..layout.ocs_at() + ocs.len()].copy_from_slice(&ocs);
        }
        Ok(())
    }
}

fn emit_order(requested: Option<&[usize]>, built: usize) -> Result<Vec<usize>, CliError> {
    let Some(requested) = requested else {
        return Ok((0..built).collect());
    };
    if requested.is_empty() {
        return Err(CliError::Message(
            "--frag-emit needs at least one datagram index".into(),
        ));
    }
    if let Some(index) = requested.iter().find(|index| **index >= built) {
        return Err(CliError::Message(format!(
            "--frag-emit index {index} is out of range; this send built {built} datagram(s)"
        )));
    }
    Ok(requested.to_vec())
}

fn builds_options(args: &Args) -> bool {
    args.apc || args.mds.is_some() || args.mrds_size.is_some() || args.req.is_some() || args.res.is_some()
}

fn parse_ocs_field(input: &str) -> Result<[u8; 2], CliError> {
    parse_hex_vec(input)?
        .try_into()
        .map_err(|bytes: Vec<u8>| CliError::Message(format!("--ocs-hex must be exactly 2 bytes, got {}", bytes.len())))
}

fn parse_pad_byte(input: &str) -> Result<u8, CliError> {
    match parse_hex_vec(input)?[..] {
        [byte] => Ok(byte),
        ref bytes => Err(CliError::Message(format!(
            "--pad-hex must be exactly 1 byte, got {}",
            bytes.len()
        ))),
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
    use udp_transport_options::error::ParseError;
    use udp_transport_options::options::ocs::{self, OcsCheck};

    fn args_from(extra: &[&str]) -> Args {
        let mut argv = vec!["udpopt-send", "--src", "192.0.2.1", "--dst", "198.51.100.2"];
        argv.extend_from_slice(extra);
        Args::parse_from(argv)
    }

    fn udp_checksum_field(datagram: &[u8]) -> u16 {
        u16::from_be_bytes([datagram[UDP_CHECKSUM_AT], datagram[UDP_CHECKSUM_AT + 1]])
    }

    fn validate_ocs(datagram: &[u8]) -> OcsCheck {
        let layout = surplus_layout(datagram).expect("assembled datagram carries a surplus area");
        let surplus_len = u16::try_from(datagram.len() - layout.starts_at).expect("surplus length fits u16");
        ocs::validate(&datagram[layout.ocs_at()..], surplus_len, udp_checksum_field(datagram))
    }

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

    #[test]
    fn raw_option_bytes_reach_the_wire_under_a_correct_ocs() {
        // A deliberately malformed MDS: Kind 4 with Length 200 overruns the surplus area.
        let args = args_from(&["--raw-options-hex", "04c80000"]);
        let datagram = raw_options_datagram(&args, b"even", "04c80000").unwrap();

        let layout = surplus_layout(&datagram).unwrap();
        assert!(!layout.needs_pad);
        assert_eq!(
            &datagram[layout.ocs_at() + usize::from(length::OCS)..],
            &[0x04, 0xc8, 0x00, 0x00]
        );
        assert_eq!(validate_ocs(&datagram), OcsCheck::Valid);
    }

    #[test]
    fn an_odd_payload_creates_the_pad_that_pad_hex_corrupts() {
        let args = args_from(&["--raw-options-hex", "0a020000", "--pad-hex", "ff"]);
        let mut datagram = raw_options_datagram(&args, b"odd", "0a020000").unwrap();
        let layout = surplus_layout(&datagram).unwrap();
        assert!(layout.needs_pad);

        WireFaults::parse(&args).unwrap().apply(&mut datagram).unwrap();

        assert_eq!(datagram[layout.starts_at], 0xff);
        // The pad sits outside the OCS fold, so only the receiver's pad check can catch it.
        assert_eq!(validate_ocs(&datagram), OcsCheck::Valid);
    }

    #[test]
    fn pad_hex_is_rejected_when_the_datagram_has_no_pad() {
        let args = args_from(&["--raw-options-hex", "0a020000", "--pad-hex", "ff"]);
        let mut datagram = raw_options_datagram(&args, b"even", "0a020000").unwrap();

        let error = WireFaults::parse(&args).unwrap().apply(&mut datagram).unwrap_err();

        assert!(error.to_string().contains("alignment pad"));
    }

    #[test]
    fn ocs_hex_overwrites_the_computed_checksum() {
        let args = args_from(&["--raw-options-hex", "0a020000", "--ocs-hex", "dead"]);
        let mut datagram = raw_options_datagram(&args, b"even", "0a020000").unwrap();
        assert_eq!(validate_ocs(&datagram), OcsCheck::Valid);

        WireFaults::parse(&args).unwrap().apply(&mut datagram).unwrap();

        let layout = surplus_layout(&datagram).unwrap();
        assert_eq!(&datagram[layout.ocs_at()..layout.ocs_at() + 2], &[0xde, 0xad]);
        assert_eq!(validate_ocs(&datagram), OcsCheck::Error(ParseError::OcsMismatch));
    }

    #[test]
    fn a_zero_ocs_under_a_zero_udp_checksum_is_the_unused_disposition() {
        let args = args_from(&["--raw-options-hex", "0a020000", "--ocs-hex", "0000", "--udp-cksum-zero"]);
        let mut datagram = raw_options_datagram(&args, b"even", "0a020000").unwrap();
        assert_ne!(udp_checksum_field(&datagram), 0);

        WireFaults::parse(&args).unwrap().apply(&mut datagram).unwrap();

        assert_eq!(udp_checksum_field(&datagram), 0);
        assert_eq!(validate_ocs(&datagram), OcsCheck::Unused);
    }

    #[test]
    fn a_zero_ocs_under_a_live_udp_checksum_orders_the_options_ignored() {
        let args = args_from(&["--raw-options-hex", "0a020000", "--ocs-hex", "0000"]);
        let mut datagram = raw_options_datagram(&args, b"even", "0a020000").unwrap();

        WireFaults::parse(&args).unwrap().apply(&mut datagram).unwrap();

        assert_ne!(udp_checksum_field(&datagram), 0);
        assert_eq!(validate_ocs(&datagram), OcsCheck::IgnoreOptions);
    }

    #[test]
    fn frag_emit_drops_duplicates_and_reorders_datagrams() {
        assert_eq!(emit_order(None, 3).unwrap(), vec![0, 1, 2]);
        assert_eq!(emit_order(Some(&[0]), 2).unwrap(), vec![0]);
        assert_eq!(emit_order(Some(&[0, 0, 1]), 2).unwrap(), vec![0, 0, 1]);
        assert_eq!(emit_order(Some(&[1, 0]), 2).unwrap(), vec![1, 0]);
    }

    #[test]
    fn frag_emit_rejects_an_empty_list_and_out_of_range_indices() {
        assert!(
            emit_order(Some(&[]), 2)
                .unwrap_err()
                .to_string()
                .contains("at least one")
        );
        assert!(
            emit_order(Some(&[0, 2]), 2)
                .unwrap_err()
                .to_string()
                .contains("index 2 is out of range")
        );
    }

    #[test]
    fn raw_options_and_built_options_are_mutually_exclusive() {
        assert!(builds_options(&args_from(&["--apc"])));
        assert!(builds_options(&args_from(&["--mds", "1200"])));
        assert!(!builds_options(&args_from(&["--raw-options-hex", "0a020000"])));
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
