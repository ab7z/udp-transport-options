//! The public two-tier API.
//!
//! The low-level helpers build and decode individual datagrams with explicit options. The high-level
//! [`Peer`] wraps raw sockets, transparent OCS handling, optional FRAG splitting, receive reassembly,
//! and receive-side option policy. The API layer does not reimplement wire rules; it composes the
//! pure modules and the thin socket wrappers.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::error::{HeaderError, ReceivePolicyError, RecvError, SendError, SocketError};
use crate::frag::reassembly::ReassemblyCache;
use crate::frag::split::{IdentificationGenerator, PeerFragmentLimits, SplitConfig, split_datagram};
use crate::model::{kind, length};
use crate::options::RawOption;
use crate::options::kind::OptionKind;
use crate::options::parse::OptionsIter;
use crate::options::serialize::OptionsBuilder;
use crate::options::typed::{Apc, TypedOption};
use crate::recv::pipeline::{Delivery, process_datagram, warn_udp_length_below_min, warn_udp_length_exceeds_ip};
use crate::socket::recv::RawReceiver;
use crate::socket::send::{RawSender, assemble_datagram};
use crate::wire::ip::IpRepr;
use crate::wire::surplus::locate_surplus;
use crate::wire::udp::UdpHeader;

pub use crate::recv::pipeline::{OcsReport, OcsStatus, OptionReport, OptionSource, OptionStatus};

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
    ///
    /// For RES, the caller must supply a token copied from a previously received REQ. The API
    /// deliberately delegates this RFC 9868 provenance precondition instead of maintaining hidden
    /// request state.
    pub fn push_raw(&mut self, option: RawOption) -> &mut Self {
        self.raw_options.push(option);
        self
    }

    /// Adds a typed option by converting it into its owned raw value.
    ///
    /// A typed [`crate::options::typed::Res`] has the same caller-enforced token provenance
    /// precondition as [`Self::push_raw`].
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
    /// FRAG Identification to use when this configuration is passed directly to
    /// [`build_outgoing_datagrams`].
    ///
    /// Low-level callers must provide `Some` when the send requires fragmentation. [`Peer`] treats
    /// `Some` as the first value of its per-peer generator and `None` as a request for an
    /// operating-system-random seed.
    pub identification: Option<u32>,
}

impl Default for SendConfig {
    fn default() -> Self {
        Self {
            max_datagram_len: DEFAULT_MAX_DATAGRAM_LEN,
            peer: PeerFragmentLimits::default_ipv4(),
            fragmentation: FragmentationMode::Auto,
            identification: None,
        }
    }
}

/// Receive-side option policy.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReceivePolicy {
    required_options: Vec<OptionKind>,
    drop_all_option_bearing: bool,
    ocs_required: bool,
}

impl ReceivePolicy {
    /// Creates the default policy: process option-bearing datagrams normally and require no options.
    pub const fn new() -> Self {
        Self {
            required_options: Vec::new(),
            drop_all_option_bearing: false,
            ocs_required: false,
        }
    }

    /// Requires a reportable option to be present and successfully processed.
    pub fn require_option(mut self, kind: OptionKind) -> Result<Self, ReceivePolicyError> {
        let kind = OptionKind::from_byte(kind.to_byte());
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

    /// Requires a successful OCS confirmation before delivering a datagram.
    ///
    /// Both a validated non-zero OCS and an RFC-permitted unused zero OCS satisfy this policy. For
    /// reassembled data, a successful fragment-set confirmation also satisfies it. A fragment set
    /// whose OCS state was not observed by the pipeline (because fragments entered the shared
    /// [`ReassemblyCache`] through its public insertion methods) never satisfies it.
    pub const fn require_ocs(mut self, require: bool) -> Self {
        self.ocs_required = require;
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

    /// Returns whether a successful OCS confirmation is required.
    pub const fn requires_ocs(&self) -> bool {
        self.ocs_required
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
    /// Separate OCS processing confirmations.
    pub ocs_reports: Vec<OcsReport>,
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
    /// Raw receive timeout: the total deadline one receive call may spend waiting, including
    /// time spent skipping unrelated raw datagrams.
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
        let mut send = config.send;
        let identifications = take_peer_identification_generator(&mut send)?;
        Ok(Self {
            sender,
            receiver,
            cache: ReassemblyCache::new(),
            addrs: config.addrs,
            send,
            receive: config.receive,
            identifications,
        })
    }

    /// Sends one logical UDP datagram, fragmenting when configured and needed.
    ///
    /// If `options` contains RES, its token must have been copied from a REQ previously received
    /// from this peer. The caller owns that protocol state.
    pub fn send(&mut self, payload: &[u8], options: SendOptions) -> Result<SendOutcome, SendError> {
        let datagrams =
            build_peer_outgoing_datagrams(self.addrs, payload, options, self.send, &mut self.identifications)?;

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
    ///
    /// Receive diagnostics are emitted through the `log` facade. Applications embedding `Peer`
    /// must install a logger if those diagnostics are to be retained; the bundled receiver CLI
    /// installs a warning-level stderr logger.
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
///
/// If `raw_options` contains RES, its token must have been copied from a REQ received from the
/// destination peer. This stateless low-level function delegates that provenance check to the
/// caller.
pub fn build_datagram(addrs: DatagramAddrs, payload: &[u8], raw_options: &[RawOption]) -> Result<Vec<u8>, SendError> {
    validate_low_level_options(payload, raw_options)?;
    let body = raw_options_body(raw_options)?;
    assemble_checked(addrs, payload, &body, IPV4_DATAGRAM_LEN_MAX)
}

/// Builds all IPv4 datagrams needed for one logical high-level send.
///
/// If fragmentation is required, `config.identification` must be `Some`; this low-level helper
/// returns [`SendError::FragmentIdentificationRequired`] instead of allocating a value on the
/// caller's behalf.
///
/// Any RES token in `options` must have been copied from a REQ received from the destination peer;
/// token provenance is an explicit caller precondition.
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

    let identification = config.identification.ok_or(SendError::FragmentIdentificationRequired)?;
    let fragments = split_datagram(
        payload,
        &body,
        SplitConfig {
            max_fragment_surplus_len: fragment_surplus_budget(config)?,
            peer: config.peer,
            identification,
        },
    )?;

    fragments
        .iter()
        .map(|fragment| assemble_checked(addrs, &[], &fragment.surplus_body, config.max_datagram_len))
        .collect()
}

fn take_peer_identification_generator(config: &mut SendConfig) -> Result<IdentificationGenerator, SocketError> {
    match config.identification.take() {
        Some(seed) => Ok(IdentificationGenerator::new(seed)),
        None => IdentificationGenerator::from_os_random().map_err(SocketError::Io),
    }
}

fn build_peer_outgoing_datagrams(
    addrs: DatagramAddrs,
    payload: &[u8],
    options: SendOptions,
    config: SendConfig,
    identifications: &mut IdentificationGenerator,
) -> Result<Vec<Vec<u8>>, SendError> {
    match build_outgoing_datagrams(addrs, payload, options.clone(), config) {
        Err(SendError::FragmentIdentificationRequired) => {
            let config = SendConfig {
                identification: Some(identifications.next_id()?),
                ..config
            };
            build_outgoing_datagrams(addrs, payload, options, config)
        }
        result => result,
    }
}

/// Decodes one raw IPv4 datagram through the receive pipeline and API policy.
///
/// `cache` must be dedicated to the datagram's UDP source/destination address-and-port pair.
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
            ocs_reports,
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
            if policy.ocs_required && !ocs_requirement_satisfied(&ocs_reports) {
                warn_policy_sampled(
                    &REQUIRED_OCS_WARNINGS,
                    "dropping UDP datagram because a successful OCS confirmation is required",
                );
                return Ok(ApiDelivery::Filtered);
            }
            Ok(ApiDelivery::Received(ReceivedDatagram {
                data,
                options,
                reports,
                ocs_reports,
            }))
        }
        Delivery::Buffered => Ok(ApiDelivery::Buffered),
        Delivery::Dropped => Ok(ApiDelivery::Dropped),
    }
}

fn options_body(payload: &[u8], options: &SendOptions) -> Result<Vec<u8>, SendError> {
    if !options.include_apc && options.raw_options.is_empty() {
        return Ok(Vec::new());
    }
    let mut builder = OptionsBuilder::new();
    if options.include_apc {
        let apc = Apc::compute(payload);
        builder.push(OptionKind::Apc, apc.crc32c.to_be_bytes());
    }
    builder.extend_raw(options.raw_options.iter().cloned());
    Ok(builder.finish()?)
}

fn raw_options_body(raw_options: &[RawOption]) -> Result<Vec<u8>, SendError> {
    if raw_options.is_empty() {
        return Ok(Vec::new());
    }
    let mut builder = OptionsBuilder::new();
    builder.extend_raw(raw_options.iter().cloned());
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
    if options_body_len == 0 {
        return Some(natural_start);
    }
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
    if config.max_datagram_len < IPV4_HEADER_LEN + UDP_HEADER_LEN {
        return Err(SendError::InvalidConfig {
            reason: "max_datagram_len cannot fit IPv4 and UDP",
        });
    }
    Ok(())
}

fn validate_send_options(options: &SendOptions) -> Result<(), SendError> {
    if raw_options_contain_kind(&options.raw_options, kind::FRAG) {
        return Err(SendError::InvalidConfig {
            reason: "high-level send options cannot include FRAG",
        });
    }
    if options.include_apc && raw_options_contain_kind(&options.raw_options, kind::APC) {
        return Err(SendError::InvalidConfig {
            reason: "automatic APC cannot be combined with a raw APC option",
        });
    }
    if raw_options_contain_duplicate_reportable_kind(&options.raw_options) {
        return Err(SendError::InvalidConfig {
            reason: "high-level send options cannot include duplicate reportable options",
        });
    }
    Ok(())
}

fn validate_low_level_options(payload: &[u8], raw_options: &[RawOption]) -> Result<(), SendError> {
    if !payload.is_empty() && raw_options_contain_kind(raw_options, kind::FRAG) {
        return Err(SendError::InvalidConfig {
            reason: "FRAG requires empty UDP user data",
        });
    }
    Ok(())
}

fn raw_options_contain_kind(raw_options: &[RawOption], raw_kind: u8) -> bool {
    raw_options.iter().any(|option| option.kind.to_byte() == raw_kind)
}

fn raw_options_contain_duplicate_reportable_kind(raw_options: &[RawOption]) -> bool {
    let mut seen = [false; 256];
    for option in raw_options {
        let kind = option.kind.to_byte();
        if !is_high_level_unique_kind(kind) {
            continue;
        }
        if seen[usize::from(kind)] {
            return true;
        }
        seen[usize::from(kind)] = true;
    }
    false
}

fn is_high_level_unique_kind(kind: u8) -> bool {
    matches!(kind, kind::APC | kind::MDS | kind::MRDS | kind::REQ | kind::RES)
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
        let failed_fragment_set = reports.iter().any(|report| {
            report.kind == *required
                && report.status == OptionStatus::Failed
                && report.source == OptionSource::FragmentSet
        });
        if failed_fragment_set {
            return true;
        }
        !reports
            .iter()
            .any(|report| report.kind == *required && report.status == OptionStatus::Success)
    })
}

fn ocs_requirement_satisfied(reports: &[OcsReport]) -> bool {
    let has_failure = reports.iter().any(|report| {
        matches!(
            report.status,
            OcsStatus::Failed | OcsStatus::InvalidZero | OcsStatus::Unobserved
        )
    });
    !has_failure
        && reports
            .iter()
            .any(|report| matches!(report.status, OcsStatus::Valid | OcsStatus::Unused))
}

fn wire_option_bearing(datagram: &[u8]) -> Result<bool, RecvError> {
    let (ip, udp_at) = IpRepr::parse(datagram)?;
    let ip_end = ip.header_len() + ip.transport_payload_len();
    let udp = match UdpHeader::parse(&datagram[udp_at..ip_end]) {
        Ok(udp) => udp,
        Err(HeaderError::UdpLengthInvalid { length }) => {
            warn_udp_length_below_min(length);
            return Err(HeaderError::UdpLengthInvalid { length }.into());
        }
        Err(error) => return Err(error.into()),
    };
    let udp_len = usize::from(udp.length);
    if udp_len > ip.transport_payload_len() {
        warn_udp_length_exceeds_ip(udp.length, ip.transport_payload_len());
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
    Ok(locate_surplus(&ip, &udp).is_some())
}

fn is_required_reportable_kind(kind: OptionKind) -> bool {
    matches!(
        kind,
        OptionKind::Apc | OptionKind::Mds | OptionKind::Mrds | OptionKind::Req | OptionKind::Res
    )
}

static DROP_ALL_WARNINGS: AtomicU64 = AtomicU64::new(0);
static REQUIRED_OPTION_WARNINGS: AtomicU64 = AtomicU64::new(0);
static REQUIRED_OCS_WARNINGS: AtomicU64 = AtomicU64::new(0);

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
    fn explicit_peer_identification_is_consumed_as_the_generator_seed() {
        let mut config = SendConfig {
            identification: Some(73),
            ..SendConfig::default()
        };
        let mut identifications = take_peer_identification_generator(&mut config).unwrap();

        assert_eq!(config.identification, None);
        assert_eq!(identifications.next_id(), Ok(73));
    }

    #[test]
    fn peer_does_not_consume_an_identification_for_an_unfragmented_send() {
        let mut identifications = IdentificationGenerator::new(u32::MAX);
        let datagrams = build_peer_outgoing_datagrams(
            addrs(),
            b"small",
            SendOptions::new(),
            SendConfig::default(),
            &mut identifications,
        )
        .unwrap();

        assert_eq!(datagrams.len(), 1);
        assert_eq!(identifications.next_id(), Ok(u32::MAX));
    }

    #[test]
    fn peer_consumes_one_identification_when_fragmentation_is_required() {
        let mut identifications = IdentificationGenerator::new(73);
        let config = SendConfig {
            max_datagram_len: 64,
            peer: PeerFragmentLimits {
                max_reassembled_size: 256,
                max_segments: 8,
            },
            ..SendConfig::default()
        };
        let datagrams =
            build_peer_outgoing_datagrams(addrs(), &[0x5a; 80], SendOptions::new(), config, &mut identifications)
                .unwrap();

        assert!(datagrams.len() > 1);
        assert_eq!(identifications.next_id(), Ok(74));
    }
}
