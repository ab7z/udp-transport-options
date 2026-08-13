//! Example receiver peer.

use std::io;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use clap::Parser;
use log::{LevelFilter, Log, Metadata, Record};
use udp_transport_options::error::{RecvError, SocketError};
use udp_transport_options::frag::reassembly::{ReassemblyCache, ReassemblyLimits};
use udp_transport_options::options::RawOption;
use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::recv::pipeline::{
    Delivery, OcsReport, OcsStatus, OptionReport, OptionSource, OptionStatus, process_datagram,
};
use udp_transport_options::socket::recv::RawReceiver;
use udp_transport_options::wire::ip::IpRepr;
use udp_transport_options::wire::surplus::locate_surplus;
use udp_transport_options::wire::udp::UdpHeader;

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Receive and decode RFC 9868 UDP-options datagrams over a Linux raw socket"
)]
struct Args {
    /// Destination UDP port to receive.
    #[arg(long, default_value_t = 40_001)]
    dst_port: u16,

    /// Optional source UDP port filter.
    #[arg(long)]
    src_port: Option<u16>,

    /// Optional own-source IPv4 address to suppress locally echoed raw packets.
    #[arg(long)]
    own_src: Option<Ipv4Addr>,

    /// Receive timeout in milliseconds; 0 waits forever.
    #[arg(long, default_value_t = 2000)]
    timeout_ms: u64,

    /// Number of matching raw datagrams to process before exiting.
    #[arg(long, default_value_t = 1)]
    count: usize,

    /// Maximum reconstructed UDP datagram size, including the UDP header.
    #[arg(long, default_value_t = usize::from(udp_transport_options::model::limits::MRDS_DEFAULT_IPV4))]
    max_reassembled_size: usize,

    /// Maximum accepted fragment count for one reconstructed datagram.
    #[arg(long, default_value_t = usize::from(udp_transport_options::model::limits::MIN_REASSEMBLY_SEGMENTS))]
    max_segments: usize,

    /// Maximum number of incomplete datagrams retained by the cache.
    #[arg(long, default_value_t = udp_transport_options::model::limits::REASSEMBLY_MAX_PENDING_PARTIALS)]
    max_pending_partials: usize,

    /// Reassembly timeout in milliseconds.
    #[arg(long, default_value_t = 120_000)]
    reassembly_timeout_ms: u64,

    /// Print raw IPv4 datagrams as hex.
    #[arg(long)]
    hexdump: bool,

    /// Print machine-readable JSONL instead of compact text.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Clone, Copy)]
struct WireSummary {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    ip_total_len: u16,
    udp_len: u16,
    surplus_len: usize,
}

struct StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.level() <= log::Level::Warn
    }

    fn log(&self, record: &Record<'_>) {
        if self.enabled(record.metadata()) {
            eprintln!("udpopt-recv: {}: {}", record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

static LOGGER: StderrLogger = StderrLogger;

fn main() -> ExitCode {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(LevelFilter::Warn);
    }
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(CliError::Permission) => {
            eprintln!("udpopt-recv: operation requires CAP_NET_RAW or root privileges");
            ExitCode::from(2)
        }
        Err(error) => {
            eprintln!("udpopt-recv: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: Args) -> Result<(), CliError> {
    if args.count == 0 {
        return Err(CliError::Message("count must be at least 1".into()));
    }

    let receiver = RawReceiver::bind(args.dst_port, args.src_port, args.own_src).map_err(CliError::from_socket)?;
    let timeout = (args.timeout_ms > 0).then(|| Duration::from_millis(args.timeout_ms));
    receiver.set_read_timeout(timeout).map_err(CliError::from_socket)?;
    let mut cache = ReassemblyCache::with_limits(ReassemblyLimits {
        max_reassembled_size: args.max_reassembled_size,
        max_segments: args.max_segments,
        max_pending_partials: args.max_pending_partials,
        timeout: Duration::from_millis(args.reassembly_timeout_ms),
    });

    let mut received = 0usize;
    let mut processing_error = false;
    while received < args.count {
        let Some(datagram) = receiver.recv().map_err(CliError::from_socket)? else {
            break;
        };
        received += 1;
        if args.hexdump {
            println!("datagram[{received}] {}", hex(&datagram));
        }

        let summary = summarize(&datagram);
        let delivery = process_datagram(&datagram, &mut cache, Instant::now());
        processing_error |= summary.is_err() || delivery.is_err();
        if args.json {
            print_json(received, summary, delivery.as_ref());
        } else {
            print_text(received, summary, delivery.as_ref());
        }
    }

    if received < args.count {
        log::warn!(
            "receive timeout: stopped after {received} of {} matching datagrams",
            args.count
        );
    }

    if processing_error {
        Err(CliError::Message(
            "one or more received datagrams failed header, checksum, or option processing".into(),
        ))
    } else {
        Ok(())
    }
}

fn summarize(datagram: &[u8]) -> Result<WireSummary, RecvError> {
    let (ip, udp_at) = IpRepr::parse(datagram)?;
    let udp = UdpHeader::parse(&datagram[udp_at..])?;
    Ok(WireSummary {
        src: ip.src,
        dst: ip.dst,
        src_port: udp.src_port,
        dst_port: udp.dst_port,
        ip_total_len: ip.total_len,
        udp_len: udp.length,
        surplus_len: locate_surplus(&ip, &udp).map_or(0, |layout| layout.len),
    })
}

fn print_text(index: usize, summary: Result<WireSummary, RecvError>, delivery: Result<&Delivery, &RecvError>) {
    match (summary, delivery) {
        (
            Ok(wire),
            Ok(Delivery::Payload {
                data,
                options,
                option_bearing,
                reports,
                ocs_reports,
            }),
        ) => {
            println!(
                "recv[{index}] payload={} payload_len={} option_bearing={} options={} reports={} ocs_reports={} surplus={} {}:{} -> {}:{}",
                hex(data),
                data.len(),
                option_bearing,
                option_list(options),
                report_list(reports),
                ocs_report_list(ocs_reports),
                wire.surplus_len,
                wire.src,
                wire.src_port,
                wire.dst,
                wire.dst_port
            );
        }
        (Ok(wire), Ok(Delivery::Buffered)) => {
            println!(
                "recv[{index}] buffered surplus={} {}:{} -> {}:{}",
                wire.surplus_len, wire.src, wire.src_port, wire.dst, wire.dst_port
            );
        }
        (Ok(wire), Ok(Delivery::Dropped)) => {
            println!(
                "recv[{index}] dropped surplus={} {}:{} -> {}:{}",
                wire.surplus_len, wire.src, wire.src_port, wire.dst, wire.dst_port
            );
        }
        (_, Err(error)) => println!("recv[{index}] error={error}"),
        (Err(error), _) => println!("recv[{index}] error={error}"),
    }
}

fn print_json(index: usize, summary: Result<WireSummary, RecvError>, delivery: Result<&Delivery, &RecvError>) {
    match (summary, delivery) {
        (
            Ok(wire),
            Ok(Delivery::Payload {
                data,
                options,
                option_bearing,
                reports,
                ocs_reports,
            }),
        ) => {
            println!(
                "{{\"index\":{index},\"delivery\":\"payload\",\"src\":\"{}\",\"dst\":\"{}\",\"src_port\":{},\"dst_port\":{},\"ip_total_len\":{},\"udp_len\":{},\"surplus_len\":{},\"payload_len\":{},\"payload_crc32c\":{},\"payload_hex\":\"{}\",\"option_bearing\":{},\"options\":\"{}\",\"reports\":\"{}\",\"ocs_reports\":\"{}\"}}",
                wire.src,
                wire.dst,
                wire.src_port,
                wire.dst_port,
                wire.ip_total_len,
                wire.udp_len,
                wire.surplus_len,
                data.len(),
                crc32c::crc32c(data),
                hex(data),
                option_bearing,
                json_escape(&option_list(options)),
                json_escape(&report_list(reports)),
                json_escape(&ocs_report_list(ocs_reports))
            );
        }
        (Ok(wire), Ok(Delivery::Buffered | Delivery::Dropped)) => {
            let kind = match delivery.expect("matched Ok above") {
                Delivery::Buffered => "buffered",
                Delivery::Dropped => "dropped",
                Delivery::Payload { .. } => unreachable!("payload matched above"),
            };
            println!(
                "{{\"index\":{index},\"delivery\":\"{kind}\",\"src\":\"{}\",\"dst\":\"{}\",\"src_port\":{},\"dst_port\":{},\"ip_total_len\":{},\"udp_len\":{},\"surplus_len\":{}}}",
                wire.src, wire.dst, wire.src_port, wire.dst_port, wire.ip_total_len, wire.udp_len, wire.surplus_len
            );
        }
        (_, Err(error)) => {
            println!(
                "{{\"index\":{index},\"delivery\":\"error\",\"error\":\"{}\"}}",
                json_escape(&error.to_string())
            );
        }
        (Err(error), _) => {
            println!(
                "{{\"index\":{index},\"delivery\":\"error\",\"error\":\"{}\"}}",
                json_escape(&error.to_string())
            );
        }
    }
}

fn option_list(options: &[RawOption]) -> String {
    options
        .iter()
        .map(|option| format!("{}:{}", kind_name(option.kind), hex(&option.value)))
        .collect::<Vec<_>>()
        .join(",")
}

fn report_list(reports: &[OptionReport]) -> String {
    reports
        .iter()
        .map(|report| {
            format!(
                "{}:{}:{}",
                kind_name(report.kind),
                status_name(report.status),
                source_name(report.source)
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn ocs_report_list(reports: &[OcsReport]) -> String {
    reports
        .iter()
        .map(|report| format!("{}:{}", ocs_status_name(report.status), source_name(report.source)))
        .collect::<Vec<_>>()
        .join(",")
}

fn ocs_status_name(status: OcsStatus) -> &'static str {
    match status {
        OcsStatus::Absent => "absent",
        OcsStatus::Valid => "valid",
        OcsStatus::Unused => "unused",
        OcsStatus::Failed => "failed",
        OcsStatus::InvalidZero => "invalid-zero",
        OcsStatus::Unobserved => "unobserved",
    }
}

fn kind_name(kind: OptionKind) -> String {
    match kind {
        OptionKind::Eol => "EOL".into(),
        OptionKind::Nop => "NOP".into(),
        OptionKind::Apc => "APC".into(),
        OptionKind::Frag => "FRAG".into(),
        OptionKind::Mds => "MDS".into(),
        OptionKind::Mrds => "MRDS".into(),
        OptionKind::Req => "REQ".into(),
        OptionKind::Res => "RES".into(),
        OptionKind::Other(byte) => format!("0x{byte:02x}"),
    }
}

fn status_name(status: OptionStatus) -> &'static str {
    match status {
        OptionStatus::Success => "success",
        OptionStatus::Failed => "failed",
        OptionStatus::Ignored => "ignored",
    }
}

fn source_name(source: OptionSource) -> &'static str {
    match source {
        OptionSource::Datagram => "datagram",
        OptionSource::FragmentSet => "fragment-set",
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

fn json_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
}

#[derive(Debug, thiserror::Error)]
enum CliError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("permission denied")]
    Permission,
}

impl CliError {
    fn from_socket(error: SocketError) -> Self {
        match error {
            SocketError::PermissionDenied => Self::Permission,
            SocketError::Io(error) => Self::Io(error),
        }
    }
}
