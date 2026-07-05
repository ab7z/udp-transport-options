//! The public two-tier API.
//!
//! The low-level helpers build and decode individual datagrams with explicit options. The high-level
//! [`Peer`] wraps raw sockets, transparent OCS handling, optional FRAG splitting, receive reassembly,
//! and receive-side option policy. The API layer does not reimplement wire rules; it composes the
//! pure modules and the thin socket wrappers.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::error::{ReceivePolicyError, RecvError, SendError};
use crate::frag::reassembly::ReassemblyCache;
use crate::frag::split::{IdentificationGenerator, PeerFragmentLimits, SplitConfig, split_datagram};
use crate::model::length;
use crate::options::RawOption;
use crate::options::kind::OptionKind;
use crate::options::parse::OptionsIter;
use crate::options::serialize::OptionsBuilder;
use crate::options::typed::{Apc, TypedOption};
use crate::recv::pipeline::{Delivery, process_datagram};
use crate::socket::recv::RawReceiver;
use crate::socket::send::{RawSender, assemble_datagram};
use crate::wire::ip::IpRepr;
use crate::wire::udp::UdpHeader;

pub use crate::recv::pipeline::{OptionReport, OptionSource, OptionStatus};

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = length::UDP_HEADER as usize;
const IPV4_DATAGRAM_LEN_MAX: usize = u16::MAX as usize;
const DEFAULT_MAX_DATAGRAM_LEN: usize = 1500;
const POLICY_WARN_SAMPLE_INTERVAL: u64 = 64;

/// Addresses and ports for one outbound UDP-options datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatagramAddrs {
    /// Source IPv4 address.
    pub src: Ipv4Addr,
    /// Destination IPv4 address.
    pub dst: Ipv4Addr,
    /// Source UDP port.
    pub src_port: u16,
    /// Destination UDP port.
    pub dst_port: u16,
}

/// Whether the high-level send path may use FRAG when one datagram is too small.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentationMode {
    /// Automatically split oversized payloads with FRAG.
    Auto,
    /// Reject oversized payloads instead of using FRAG.
    Disabled,
}

/// Per-send option selection.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SendOptions {
    raw_options: Vec<RawOption>,
    include_apc: bool,
}

impl SendOptions {
    /// Creates an empty send option set.
    pub const fn new() -> Self {
        Self {
            raw_options: Vec::new(),
            include_apc: false,
        }
    }

    /// Adds an owned raw option value.
    pub fn push_raw(&mut self, option: RawOption) -> &mut Self {
        self.raw_options.push(option);
        self
    }

    /// Adds a typed option by converting it into its owned raw value.
    pub fn push_typed<T: TypedOption>(&mut self, option: T) -> &mut Self {
        self.raw_options.push(raw_from_typed(option));
        self
    }

    /// Enables automatic APC generation over the UDP user data.
    pub const fn with_apc(mut self) -> Self {
        self.include_apc = true;
        self
    }

    /// Returns the explicit raw options that will be passed to the serializer.
    pub fn raw_options(&self) -> &[RawOption] {
        &self.raw_options
    }

    /// Returns whether APC generation is enabled.
    pub const fn includes_apc(&self) -> bool {
        self.include_apc
    }
}

/// High-level send configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendConfig {
    /// Maximum IPv4 datagram length to emit, including the IPv4 header.
    pub max_datagram_len: usize,
    /// Peer-side MRDS limits.
    pub peer: PeerFragmentLimits,
    /// FRAG behavior for oversized sends.
    pub fragmentation: FragmentationMode,
    /// FRAG Identification to use for this send.
    pub identification: u32,
}

impl Default for SendConfig {
    fn default() -> Self {
        Self {
            max_datagram_len: DEFAULT_MAX_DATAGRAM_LEN,
            peer: PeerFragmentLimits::default_ipv4(),
            fragmentation: FragmentationMode::Auto,
            identification: 1,
        }
    }
}

/// Receive-side option policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceivePolicy {
    required_options: Vec<OptionKind>,
    drop_all_option_bearing: bool,
}

impl ReceivePolicy {
    /// Creates the default policy: process option-bearing datagrams normally and require no options.
    pub const fn new() -> Self {
        Self {
            required_options: Vec::new(),
            drop_all_option_bearing: false,
        }
    }

    /// Requires a reportable option to be present and successfully processed.
    pub fn require_option(mut self, kind: OptionKind) -> Result<Self, ReceivePolicyError> {
        if !is_required_reportable_kind(kind) {
            return Err(ReceivePolicyError::UnsupportedRequiredOption { kind: kind.to_byte() });
        }
        if !self.required_options.contains(&kind) {
            self.required_options.push(kind);
        }
        Ok(self)
    }

    /// Configures whether all option-bearing datagrams are filtered out.
    pub const fn drop_all_option_bearing(mut self, drop: bool) -> Self {
        self.drop_all_option_bearing = drop;
        self
    }

    /// Returns the required option Kinds.
    pub fn required_options(&self) -> &[OptionKind] {
        &self.required_options
    }

    /// Returns whether all option-bearing datagrams are filtered out.
    pub const fn drops_all_option_bearing(&self) -> bool {
        self.drop_all_option_bearing
    }
}

/// One datagram accepted by the API receive policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedDatagram {
    /// UDP user data.
    pub data: Vec<u8>,
    /// Successfully processed options exposed to the user.
    pub options: Vec<RawOption>,
    /// Processing status for visible options.
    pub reports: Vec<OptionReport>,
}

/// Result of decoding one raw datagram through the API policy layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiDelivery {
    /// A user datagram is ready.
    Received(ReceivedDatagram),
    /// A fragment was buffered and no user datagram is ready yet.
    Buffered,
    /// The pipeline dropped this datagram or fragment set.
    Dropped,
    /// The API receive policy filtered out an otherwise delivered datagram.
    Filtered,
}

/// Summary of a high-level send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendOutcome {
    /// Number of IPv4 datagrams written to the raw socket.
    pub datagrams: usize,
    /// Total bytes reported as sent by the socket.
    pub bytes: usize,
}

/// Configuration for a synchronous high-level peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    /// Local-to-remote send addresses and ports.
    pub addrs: DatagramAddrs,
    /// Send behavior.
    pub send: SendConfig,
    /// Receive policy.
    pub receive: ReceivePolicy,
    /// Raw receive timeout.
    pub read_timeout: Option<Duration>,
}

impl PeerConfig {
    /// Creates a peer config with default send behavior and receive policy.
    pub fn new(addrs: DatagramAddrs) -> Self {
        Self {
            addrs,
            send: SendConfig::default(),
            receive: ReceivePolicy::default(),
            read_timeout: None,
        }
    }
}

/// Synchronous high-level UDP-options peer.
#[derive(Debug)]
pub struct Peer {
    sender: RawSender,
    receiver: RawReceiver,
    cache: ReassemblyCache,
    addrs: DatagramAddrs,
    send: SendConfig,
    receive: ReceivePolicy,
    identifications: IdentificationGenerator,
}

impl Peer {
    /// Opens the raw sender and receiver for one socket pair.
    pub fn bind(config: PeerConfig) -> Result<Self, RecvError> {
        let sender = RawSender::new()?;
        let receiver = RawReceiver::bind(config.addrs.src_port, Some(config.addrs.dst_port), None)?;
        receiver.set_read_timeout(config.read_timeout)?;
        Ok(Self {
            sender,
            receiver,
            cache: ReassemblyCache::new(),
            addrs: config.addrs,
            send: config.send,
            receive: config.receive,
            identifications: IdentificationGenerator::new(config.send.identification),
        })
    }

    /// Sends one logical UDP datagram, fragmenting when configured and needed.
    pub fn send(&mut self, payload: &[u8], options: SendOptions) -> Result<SendOutcome, SendError> {
        let mut config = self.send;
        config.identification = self.identifications.next_id()?;
        let datagrams = build_outgoing_datagrams(self.addrs, payload, options, config)?;

        let mut bytes = 0usize;
        for datagram in &datagrams {
            bytes = bytes
                .checked_add(self.sender.send(self.addrs.dst, datagram)?)
                .ok_or(SendError::InvalidConfig {
                    reason: "sent byte count overflow",
                })?;
        }

        Ok(SendOutcome {
            datagrams: datagrams.len(),
            bytes,
        })
    }

    /// Receives and processes one matching raw datagram.
    pub fn recv(&mut self) -> Result<Option<ReceivedDatagram>, RecvError> {
        let Some(datagram) = self.receiver.recv()? else {
            return Ok(None);
        };
        let delivery = match decode_datagram(&datagram, &mut self.cache, Instant::now(), &self.receive) {
            Ok(delivery) => delivery,
            Err(RecvError::Socket(error)) => return Err(RecvError::Socket(error)),
            Err(_) => return Ok(None),
        };
        match delivery {
            ApiDelivery::Received(datagram) => Ok(Some(datagram)),
            ApiDelivery::Buffered | ApiDelivery::Dropped | ApiDelivery::Filtered => Ok(None),
        }
    }

    /// Runs caller-driven reassembly garbage collection.
    pub fn gc(&mut self, now: Instant) {
        self.cache.gc(now);
    }
}

/// Builds one IPv4 datagram from explicit raw options.
pub fn build_datagram(addrs: DatagramAddrs, payload: &[u8], raw_options: &[RawOption]) -> Result<Vec<u8>, SendError> {
    validate_low_level_options(payload, raw_options)?;
    let mut builder = OptionsBuilder::new();
    builder.extend_raw(raw_options.iter().cloned());
    let body = builder.finish()?;
    assemble_checked(addrs, payload, &body, IPV4_DATAGRAM_LEN_MAX)
}

/// Builds all IPv4 datagrams needed for one logical high-level send.
pub fn build_outgoing_datagrams(
    addrs: DatagramAddrs,
    payload: &[u8],
    options: SendOptions,
    config: SendConfig,
) -> Result<Vec<Vec<u8>>, SendError> {
    validate_send_config(config)?;
    validate_send_options(&options)?;
    let body = options_body(payload, &options)?;
    let single_len = datagram_len(payload.len(), body.len()).ok_or(SendError::DatagramTooLarge {
        len: usize::MAX,
        max: config.max_datagram_len,
    })?;

    if single_len <= config.max_datagram_len {
        return Ok(vec![assemble_checked(addrs, payload, &body, config.max_datagram_len)?]);
    }

    if config.fragmentation == FragmentationMode::Disabled {
        return Err(SendError::DatagramTooLarge {
            len: single_len,
            max: config.max_datagram_len,
        });
    }

    let fragments = split_datagram(
        payload,
        &body,
        SplitConfig {
            max_fragment_surplus_len: fragment_surplus_budget(config)?,
            peer: config.peer,
            identification: config.identification,
        },
    )?;

    fragments
        .iter()
        .map(|fragment| assemble_checked(addrs, &[], &fragment.surplus_body, config.max_datagram_len))
        .collect()
}

/// Decodes one raw IPv4 datagram through the receive pipeline and API policy.
pub fn decode_datagram(
    datagram: &[u8],
    cache: &mut ReassemblyCache,
    now: Instant,
    policy: &ReceivePolicy,
) -> Result<ApiDelivery, RecvError> {
    if policy.drop_all_option_bearing && wire_option_bearing(datagram)? {
        warn_policy_sampled(
            &DROP_ALL_WARNINGS,
            "dropping UDP datagram because receive policy rejects all option-bearing packets",
        );
        return Ok(ApiDelivery::Filtered);
    }

    match process_datagram(datagram, cache, now)? {
        Delivery::Payload {
            data,
            options,
            option_bearing,
            reports,
        } => {
            if policy.drop_all_option_bearing && option_bearing {
                warn_policy_sampled(
                    &DROP_ALL_WARNINGS,
                    "dropping UDP datagram because receive policy rejects all option-bearing packets",
                );
                return Ok(ApiDelivery::Filtered);
            }
            if let Some(missing) = missing_required_option(policy, &reports) {
                warn_policy_sampled(
                    &REQUIRED_OPTION_WARNINGS,
                    &format!(
                        "dropping UDP datagram because required option kind {:#04x} is missing or failed",
                        missing.to_byte()
                    ),
                );
                return Ok(ApiDelivery::Filtered);
            }
            Ok(ApiDelivery::Received(ReceivedDatagram { data, options, reports }))
        }
        Delivery::Buffered => Ok(ApiDelivery::Buffered),
        Delivery::Dropped => Ok(ApiDelivery::Dropped),
    }
}

fn options_body(payload: &[u8], options: &SendOptions) -> Result<Vec<u8>, SendError> {
    let mut builder = OptionsBuilder::new();
    if options.include_apc {
        let apc = Apc::compute(payload);
        builder.push(OptionKind::Apc, apc.crc32c.to_be_bytes());
    }
    builder.extend_raw(options.raw_options.iter().cloned());
    Ok(builder.finish()?)
}

fn raw_from_typed<T: TypedOption>(option: T) -> RawOption {
    let mut bytes = Vec::new();
    option.encode(&mut bytes);
    let parsed = OptionsIter::new(&bytes)
        .next()
        .expect("typed option encoder emits one TLV")
        .expect("typed option encoder emits a valid TLV");
    RawOption::from(parsed)
}

fn assemble_checked(
    addrs: DatagramAddrs,
    payload: &[u8],
    options_body: &[u8],
    max_datagram_len: usize,
) -> Result<Vec<u8>, SendError> {
    let len = datagram_len(payload.len(), options_body.len()).ok_or(SendError::DatagramTooLarge {
        len: usize::MAX,
        max: max_datagram_len,
    })?;
    if len > max_datagram_len {
        return Err(SendError::DatagramTooLarge {
            len,
            max: max_datagram_len,
        });
    }
    if len > IPV4_DATAGRAM_LEN_MAX {
        return Err(SendError::DatagramTooLarge {
            len,
            max: IPV4_DATAGRAM_LEN_MAX,
        });
    }
    Ok(assemble_datagram(
        addrs.src,
        addrs.dst,
        addrs.src_port,
        addrs.dst_port,
        payload,
        options_body,
    ))
}

fn datagram_len(payload_len: usize, options_body_len: usize) -> Option<usize> {
    let udp_len = UDP_HEADER_LEN.checked_add(payload_len)?;
    let natural_start = IPV4_HEADER_LEN.checked_add(udp_len)?;
    let needs_pad = natural_start % 2 == 1;
    natural_start
        .checked_add(usize::from(needs_pad))?
        .checked_add(options_body_len)
}

fn validate_send_config(config: SendConfig) -> Result<(), SendError> {
    if config.max_datagram_len > IPV4_DATAGRAM_LEN_MAX {
        return Err(SendError::InvalidConfig {
            reason: "max_datagram_len exceeds IPv4 Total Length",
        });
    }
    if config.max_datagram_len < IPV4_HEADER_LEN + UDP_HEADER_LEN + usize::from(length::OCS) {
        return Err(SendError::InvalidConfig {
            reason: "max_datagram_len cannot fit IPv4, UDP, and OCS",
        });
    }
    Ok(())
}

fn validate_send_options(options: &SendOptions) -> Result<(), SendError> {
    if options.raw_options.iter().any(|option| option.kind == OptionKind::Frag) {
        return Err(SendError::InvalidConfig {
            reason: "high-level send options cannot include FRAG",
        });
    }
    if options.include_apc && options.raw_options.iter().any(|option| option.kind == OptionKind::Apc) {
        return Err(SendError::InvalidConfig {
            reason: "automatic APC cannot be combined with a raw APC option",
        });
    }
    Ok(())
}

fn validate_low_level_options(payload: &[u8], raw_options: &[RawOption]) -> Result<(), SendError> {
    if !payload.is_empty() && raw_options.iter().any(|option| option.kind == OptionKind::Frag) {
        return Err(SendError::InvalidConfig {
            reason: "FRAG requires empty UDP user data",
        });
    }
    Ok(())
}

fn fragment_surplus_budget(config: SendConfig) -> Result<usize, SendError> {
    config
        .max_datagram_len
        .checked_sub(IPV4_HEADER_LEN + UDP_HEADER_LEN)
        .ok_or(SendError::InvalidConfig {
            reason: "max_datagram_len cannot fit a UDP fragment",
        })
}

fn missing_required_option(policy: &ReceivePolicy, reports: &[OptionReport]) -> Option<OptionKind> {
    policy.required_options.iter().copied().find(|required| {
        !reports.iter().any(|report| {
            report.kind == *required
                && report.status == OptionStatus::Success
                && report.source == OptionSource::Datagram
        })
    })
}

fn wire_option_bearing(datagram: &[u8]) -> Result<bool, RecvError> {
    let (ip, udp_at) = IpRepr::parse(datagram)?;
    let ip_end = ip.header_len() + ip.transport_payload_len();
    let udp = UdpHeader::parse(&datagram[udp_at..ip_end])?;
    let udp_len = usize::from(udp.length);
    if udp_len > ip.transport_payload_len() {
        return Err(RecvError::UdpLengthExceedsIpPayload {
            udp_len: udp.length,
            transport_payload_len: ip.transport_payload_len(),
        });
    }
    let user_data_at = udp_at + UDP_HEADER_LEN;
    let surplus_start = udp_at + udp_len;
    let user_data = &datagram[user_data_at..surplus_start];
    if udp.checksum != 0 {
        let expected = UdpHeader { checksum: 0, ..udp }.compute_checksum(&ip, user_data);
        if expected != udp.checksum {
            return Err(RecvError::UdpChecksumMismatch {
                expected,
                actual: udp.checksum,
            });
        }
    }
    Ok(udp_len < ip.transport_payload_len())
}

fn is_required_reportable_kind(kind: OptionKind) -> bool {
    matches!(
        kind,
        OptionKind::Apc | OptionKind::Mds | OptionKind::Mrds | OptionKind::Req | OptionKind::Res
    )
}

static DROP_ALL_WARNINGS: AtomicU64 = AtomicU64::new(0);
static REQUIRED_OPTION_WARNINGS: AtomicU64 = AtomicU64::new(0);

fn warn_policy_sampled(counter: &AtomicU64, message: &str) {
    let sample = counter.fetch_add(1, Ordering::Relaxed) + 1;
    if sample == 1 || sample.is_multiple_of(POLICY_WARN_SAMPLE_INTERVAL) {
        if sample == 1 {
            log::warn!("{message}");
        } else {
            log::warn!("{message} (sample #{sample}; repeated warnings in this category are sampled)");
        }
    }
}
