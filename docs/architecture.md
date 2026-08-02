# Architecture

This document describes the internal architecture of `udp-transport-options`, a userspace reference
implementation of [RFC 9868](https://www.rfc-editor.org/rfc/rfc9868.txt) (Transport Options for UDP,
October 2025) in Rust. It goes deeper than `CLAUDE.md`: it states each module's inputs and outputs,
lists the concrete public types and method signatures, explains the four design rules
with their rationale, and walks the send and receive data flows step by step.

The companion thesis asks two research questions, and the architecture is shaped to answer them:

- **FF1:** which RFC 9868 requirements are fully, partially, or not implementable in userspace over
  raw sockets?
- **FF2:** how far does the surplus area survive along real network paths, and how do NAT and filter
  devices treat datagrams that carry it?

> Status note (2026-07-13): the in-scope endpoint implementation is present; the types and signatures
> below describe the current architecture, not the original bootstrap skeleton. Remaining limitations
> are named explicitly rather than hidden behind "planned" wording. The Step 17 harness covers local,
> controlled namespace/veth, routed, Linux NAT, and negative filter paths; it does not yet answer FF2
> over real external paths or surplus-specific middleboxes.

## 1. Overview and design goals

RFC 9868 carries transport options in the **surplus area**: the bytes between the end of the UDP
payload (delimited by the UDP Length field) and the end of the IP transport payload (IPv4 Total
Length minus the IHL x 4 header bytes) (RFC 9868 Sec. 4, Sec. 7).
A normal operating-system UDP stack delivers only the UDP-length-bounded payload and never exposes
the surplus area, so this crate reaches it with raw sockets on Linux.

```
 IP datagram
 +----------------+--------------------+--------------------------------------+
 | IP header      | UDP header (8 B)   | UDP user data | surplus area         |
 +----------------+--------------------+---------------+----------------------+
                  |<------ UDP Length ---------------->|
 |<---------------------- IP payload (Total Length - IHL*4) ------------------>|
                                                       |<-- surplus area ----->|
                                                       (OCS, then UDP options)
```

The surplus area exists only when the IP payload is larger than the UDP Length indicates (RFC 9868
Sec. 7). The UDP checksum covers only the UDP header and the UDP data, not the surplus area; the
surplus area is protected separately by the Option Checksum (OCS) (RFC 9868 Sec. 9).

Design goals, in priority order:

1. **Faithfulness to the RFC.** Byte layouts, Kind numbers, fixed lengths, the OCS algorithm, and the
   FRAG semantics follow RFC 9868 exactly. Protocol constants live in exactly one place
   (`model`) so the magic numbers are not scattered.
2. **A testable core that needs no privileges.** Everything except the two socket modules is a pure
   function over byte buffers. The receive state machine (`recv::pipeline`) and the entire
   parse/serialize/OCS/FRAG logic are unit-testable without `CAP_NET_RAW`. This is what keeps a
   green test run trustworthy and directly serves FF1: it isolates exactly which behaviour is pure
   protocol logic and which behaviour depends on the privileged socket layer.
3. **Pedagogical clarity over reuse.** The Internet checksum (RFC 1071), the TLV parser, the TLV
   serializer, and the OCS are hand-rolled rather than pulled from a crate, because they are the
   subject of the thesis. The crate deliberately avoids `nom`, `pnet`, `etherparse`, `smoltcp`,
   `bytes`, `nix`, and `zerocopy`.
4. **A single IP version: IPv4.** IPv6 is deliberately removed from scope: the RFC 9868 mechanism is
   IP-version-neutral and fully demonstrated on IPv4, while IPv6 raw-socket `IPV6_HDRINCL` semantics
   differ and add platform fragility without protocol insight.
5. **A safe boundary around `unsafe`.** All FFI lives in `src/socket/` behind safe wrappers; the
   crate sets `#![deny(unsafe_op_in_unsafe_fn)]`.

### Scope

In scope: the TLV options framework (RFC 9868 Sec. 10); the OCS (RFC 9868 Sec. 9); the must-support
options EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES; the zero-copy parser and the serializer; FRAG
fragmentation and reassembly; the two-tier API; IPv4; unit and loopback integration tests;
example peer CLIs.

Out of scope: the TIME option; the reserved AUTH/UCMP/UENC options; the RFC 9869 (DPLPMTUD)
REQ/RES-for-PMTUD use case; kernel modules; bidirectional or stateful protocols; IPv6.

### Layering

```
                +-------------------------------------------------+
   public       |                     api                         |
   surface      |  low-level (explicit options) + high-level peer |
                +------------------------+------------------------+
                                         |
        +--------------------------------+--------------------------------+
        |                                |                                |
   +----+-----+                    +-----+------+                   +-----+------+
   |  socket  |  (Linux, root)     |    recv    |  (pure)           |    frag    |  (pure)
   |  send /  |  raw I/O           |  pipeline  |  state machine    |  split /   |
   |  recv    |                    |            |                   | reassembly |
   +----+-----+                    +-----+------+                   +-----+------+
        |                                |                                |
        +--------------------------------+--------------------------------+
                                         |
            +----------------------------+----------------------------+
            |              options (kind/parse/serialize/ocs/typed)   |  (pure)
            +----------------------------+----------------------------+
                                         |
            +----------------------------+----------------------------+
            |              wire (checksum/ip/udp/surplus)             |  (pure)
            +----------------------------+----------------------------+
                                         |
                       +-----------------+-----------------+
                       |        model (constants/limits)   |  (pure)
                       +-----------------------------------+
                                         |
                       +-----------------+-----------------+
                       |        error (ParseError/RecvError)|
                       +-----------------------------------+
```

Only `socket/send` and `socket/recv` are privileged (Linux, `CAP_NET_RAW` or root). Everything else
is root-free and can be exercised on any platform.

## 2. Module responsibilities

Each subsection states what a module takes in, what it produces, and whether it is root-free (pure)
or privileged (raw-socket I/O).

### `model` (pure)

Single source of truth for the protocol constants and limits taken from RFC 9868. Three submodules:

- `model::kind`: the Kind byte values (`EOL = 0` .. `RES = 7`), the SAFE/UNSAFE boundary
  (`UNSAFE_MIN = 192`), and the extended-length sentinel (`EXTENDED_LENGTH_MARKER = 255`)
  (RFC 9868 Sec. 10).
- `model::length`: the fixed total lengths (Kind + Length + Value) of the fixed-size options
  (`APC = 6`, `FRAG_NON_TERMINAL = 10`, `FRAG_TERMINAL = 12`, `MDS = 4`, `MRDS = 5`, `REQ = 6`,
  `RES = 6`) plus `OCS = 2`.
- `model::limits`: the reassembly defaults and the DoS knobs (`MRDS_DEFAULT_IPV4 = 2926`,
  `MIN_REASSEMBLY_SEGMENTS = 2`, `REASSEMBLY_TIMEOUT_MAX = 120 s`,
  `REASSEMBLY_MAX_PENDING_PARTIALS = 64`, `NOP_RUN_DOS_THRESHOLD = 7`).

Inputs: none (compile-time constants). Outputs: constants consumed by every higher layer.

### `error` (pure)

Defines `ParseError` (why the surplus area or its options were rejected), `HeaderError` (why an IP
or UDP header invalidates the whole datagram), and `RecvError` (the pipeline and socket error type,
which wraps `ParseError`, `std::io::Error`, and a permission error).
Inputs: none. Outputs: the error enums used across the crate.

### `wire/checksum` (pure, hand-rolled)

The one's-complement Internet checksum (RFC 1071). This single primitive backs both the UDP checksum
and the OCS, so it is hand-rolled rather than taken from a crate. Inputs: a byte slice (and,
optionally, a running seed for the pseudo-header). Output: a 16-bit checksum (or a running sum to be
folded later). Root-free.

### `wire/ip` (pure)

`IpRepr`, the view of the IPv4 header fields the UDP-options layer needs (addresses,
the transport-payload length, and a pseudo-header seed for the UDP checksum), plus IPv4
header parse/build. The surplus math, the UDP pseudo-header, and the FRAG keying are written
against this type. Inputs (parse): the leading bytes of an IP datagram. Outputs: an
`IpRepr` and the offset of the transport payload; or, on build, header bytes. Root-free.

### `wire/udp` (pure)

`UdpHeader` parse/build and the UDP checksum over the pseudo-header, the UDP header, and the user data
only (not the surplus area) (RFC 9868 Sec. 9). The kernel does not compute the UDP checksum for raw
sends, so the crate computes it. Inputs: header bytes or fields plus an `IpRepr` seed. Outputs: a
`UdpHeader`, or header bytes plus the checksum. Root-free.

### `wire/surplus` (pure)

`SurplusLayout` and `locate_surplus`: given the IP and UDP lengths, compute where the surplus area
starts (any byte offset, RFC 9868 Sec. 7), where the OCS sits (aligned to the first 2-byte boundary
of the area, relative to the start of the IP datagram), whether a single zero pad byte precedes
the OCS (when the natural start is odd), and the surplus length (RFC 9868 Sec. 7, Sec. 8). Inputs: an
`IpRepr` and a `UdpHeader` (or their lengths). Output: a `SurplusLayout` (or "no surplus area").
Root-free.

### `options/kind` (pure)

`OptionKind` and its classification: mapping to and from the raw Kind byte, the SAFE/UNSAFE
predicate, the must-support predicate, and the framing rules (EOL/NOP are single-byte; everything
else is `Kind + Length + Value`) (RFC 9868 Sec. 10). Inputs: a Kind byte or an `OptionKind`.
Outputs: the classification answers. Root-free.

### `options/parse` (pure, hand-rolled)

The zero-copy TLV parser: `OptionRef<'a>` (a borrowed Kind plus value bytes) and the iterator that
produces it. The iterator validates each Length, checks bounds, handles the extended (2-byte) length
form, terminates on EOL, and reports a single `ParseError` on malformed input without ever panicking
(RFC 9868 Sec. 10). Input: the surplus-area bytes after the OCS. Output: a stream of `OptionRef`
borrowing those bytes, or one `ParseError`. Root-free.

Transmitters use the default form through total length 254 and the extended form above it. The parser
also rejects bounded extended encodings with total length `4..=254`; that receiver behavior is a
documented local strictness policy, not an additional literal RFC receiver MUST. Per Sec. 10 and
Erratum 8834, a claimed overrun makes the complete options area malformed.

### `options/serialize` (pure, hand-rolled)

`OptionsBuilder`: emits the OCS-led options body with a zeroed two-byte OCS placeholder, canonical
TLV options (FRAG first when present, then other must-support options, then other SAFE options), NOP
only before a real TLV that needs 2-byte alignment, EOL, and zero-fill to an even body length. The
RFC requires must-support options before other SAFE options; FRAG-first ordering inside that group
and even-length zero-fill are the builder's local canonical form. Known fixed-size options are
validated against their RFC value lengths before emission, so the sender does not manufacture a
malformed FRAG/APC/MDS/MRDS/REQ/RES TLV from raw input; FRAG is limited to one occurrence and its
Frag. Start field is patched from the final body length. Raw `Other` output is limited to the
unassigned SAFE range `10..=126`; assigned/reserved out-of-scope SAFE Kinds (TIME, AUTH, EXP, and
128..=191) are not generated. The optional pre-OCS pad byte for odd surplus starts is emitted by the
wire/send layer. Input: owned `RawOption`s. Output: the OCS-led body with the placeholder at
`body[0..2]`. Root-free.

### `options/ocs` (pure, hand-rolled)

OCS computation and validation (RFC 9868 Sec. 9). Computation is a two-pass back-patch: serialize the
OCS-aligned body with the OCS field zero, run the RFC 1071 sum from OCS through the end plus the
16-bit full surplus length, then write the one's complement of the folded sum into the OCS field (a would-be
`0x0000` is written as its one's-complement equivalent `0xFFFF`, keeping a used OCS non-zero as
Sec. 9 requires when the UDP checksum is non-zero). Validation recomputes the sum over the same
bytes (including the stored OCS) and requires the result to be the one's-complement zero. Built on `wire/checksum`. Input:
the bytes beginning at OCS and the full surplus length. The odd-start pad is checked separately for
zero; it is included only through the length addend, not prepended to the aligned checksum word stream.
Output: the OCS value, or a pass/fail verdict. Root-free.

### `options/typed` (pure)

The `TypedOption` trait and the fixed-length `Copy` structs `Apc`, `Mds`, `Mrds`, `Req`, `Res`,
`Frag`. Each decodes from, and encodes to, its wire bytes. APC carries a CRC32C over the UDP user
data and is reported only per-datagram, not per-fragment (RFC 9868 Sec. 11.3, Fig. 9). Input
(decode): an option's value bytes. Output: an owned typed value, or a `ParseError` on a wrong length.
Root-free.

### `options` (mod.rs) (pure)

`RawOption`: the owned counterpart of `OptionRef` (a Kind plus owned value bytes, no lifetime). This
is the type that crosses the public API boundary, so the parser's borrow never escapes. Root-free.

### `frag/split` (pure)

Fragmentation on the send side (RFC 9868 Sec. 11.4). Splits an oversized datagram into FRAG fragments,
each carried with empty UDP user data (UDP Length 8) and the fragment data in the surplus area after
the FRAG option. Non-terminal fragments use the 10-byte FRAG form; the terminal fragment uses the
12-byte form (carrying the RDOS). The single-fragment (atomic) case is supported with `Frag.Offset =
0`; multi-fragment payload bytes use offsets relative to the original UDP header. MDS/path MTU
selects the per-fragment surplus budget; minimal OCS+FRAG fragment bodies provide S-12/S-14 data
budgets; MRDS caps the reassembled datagram size and segment count.
Input: original UDP user data, a fully prepared OCS-led per-datagram options body whose original OCS
is zero for this path, and size/ID config. The original UDP checksum is likewise represented as zero;
each emitted fragment receives its own UDP checksum and OCS in the later send stage.
Output: an ordered list of OCS-led fragment surplus bodies ready for `assemble_datagram(..., b"",
body)`. Root-free.

### `frag/reassembly` (pure)

Reassembly on the receive side (RFC 9868 Sec. 11.4). The cache is keyed by `FragKey`, with
offset-sorted insertion, overlap detection (overlap aborts), exact duplicate suppression (bytes and
per-fragment options must both match), a configurable timeout clamped to the 120-second RFC default
maximum, caller-driven garbage collection, and per-datagram plus per-cache DoS limits. Expiry occurs
at `elapsed >= timeout`; no background task reclaims state without insertion or `gc(now)`. The
pending-partial cap limits retained incomplete state, not
immediately complete atomic fragments. A completed datagram tail is returned for one re-feed into the
pipeline together with coalesced SAFE per-fragment options
(currently MDS/MRDS minima and the most recently received REQ/RES tokens). A FRAG reappearing there
with non-empty reassembled data follows the RFC 9868 Sec. 11.4 rule (all options ignored, data
delivered), and a nested FRAG with empty data is rejected as a local anti-loop policy (the RFC does not
define nested fragmentation). Input: one fragment's `FragKey`, `Frag` fields, fragment data, optional
validated per-fragment options, and caller-supplied timestamp. Output: a `ReassemblyOutcome`
(`Incomplete`, `Complete { tail, udp_length, fragment_options, fragment_option_failures,
fragment_ocs_nonzero }`, or `Abort(reason)`). Root-free.

One cache instance is scoped to one source/destination address-and-port pair. `Peer` enforces this by
ownership; low-level callers must do the same because sharing one cache would share its pending-state
budget across socket pairs, contrary to the Sec. 11.4 resource-isolation SHOULD NOT.

### `recv/pipeline` (pure)

`process_datagram`: the pure receive state machine that implements the RFC 9868 processing order
(RFC 9868 Sec. 14). It takes a full IP datagram as bytes and returns a `Delivery`. It performs no I/O,
so it is fully unit-testable without privileges; this module holds the bulk of the receive-side
correctness. Input: the raw IP-datagram bytes plus a mutable `ReassemblyCache` and caller-supplied
`Instant`. Output: a `Delivery` (`Payload { data, options }`, `Buffered`, or `Dropped`), or a
`RecvError`. Root-free.

### `socket/send` (privileged: Linux, root)

The raw send path using `IP_HDRINCL` (RFC 9868 Sec. 15; locked decision). Its pure
`assemble_datagram` helper builds the IP header, the UDP header (with
`UDP Length < IPv4 Total Length - IPv4 IHL*4`, which creates the surplus area), and the surplus area;
it computes the UDP checksum and the
OCS by hand. The privileged `RawSender` wrapper only opens/configures the raw socket and transmits
the assembled bytes. Input: addresses, ports, payload, and options. Output: a sent datagram or
`SocketError`. Needs `CAP_NET_RAW`. All `unsafe` FFI is confined here behind safe wrappers.

### `socket/recv` (privileged: Linux, root)

The raw receive path using `SOCK_RAW` `IPPROTO_UDP`. It reads full IP datagrams with the surplus area
intact, filters by destination port and optionally source port in userspace, and returns the raw
bytes for the later `recv::pipeline`. It parses only the header state needed for demultiplexing and
sampled-logs `UDP Length < 8` before rejecting it because that malformed value cannot safely reach
the pipeline; UDP checksum, upper-bound, OCS, and TLV semantics remain pipeline work. It mitigates
raw-socket noise with an optional own-source skip
and by holding a dummy `SOCK_DGRAM` on the destination port to absorb ICMP port-unreachable. Input:
the socket. Output: raw IP-datagram bytes for the pipeline. Needs `CAP_NET_RAW`.

### `api` (pure orchestration over privileged I/O)

The two-tier public API (RFC 9868 Sec. 15 use; locked decision):

- **low-level:** `build_datagram()` builds an individual datagram from explicit `RawOption`s, and
  `decode_datagram()` runs one raw datagram through the receive pipeline and receive policy.
  `build_datagram()` still enforces the RFC rule that FRAG cannot be combined with non-empty UDP
  user data. Empty option sets emit a plain UDP datagram with no surplus area.
- **high-level:** `Peer` wraps `RawSender`, `RawReceiver`, `ReassemblyCache`, and an
  `IdentificationGenerator`. `Peer::send()` applies the OCS through the existing serializer/send
  path whenever options are present and auto-fragments when the payload exceeds the configured
  single-datagram capacity; `Peer::recv()` reassembles transparently and returns only completed user
  datagrams.

The API logic is pure orchestration; the privileged work happens inside the socket modules it drives.
`ReceivePolicy` can require successfully processed APC/MDS/MRDS/REQ/RES options from the datagram or
the coalesced fragment set, require an acceptable OCS via `require_ocs(bool)`, or drop all datagrams
with a usable option-bearing surplus layout after
the UDP checksum boundary. Tails too short to hold the aligned OCS are delivered without options,
matching `process_datagram`.
Required-option matching is currently source-agnostic: a success from either `Datagram` or
`FragmentSet` satisfies it. The policy has no named-omission list and cannot express independent
datagram-versus-fragment-set requirements; those Sec. 15 controls remain a documented API gap.
`SendOptions` selects typed/raw options and automatic APC generation, while `SendConfig` controls the
datagram size budget, peer MRDS, FRAG enablement, and FRAG Identification.
Raw option guards are based on the canonical wire Kind byte: `OptionKind::Other(3)` is still FRAG
and `OptionKind::Other(2)` is still APC for API validation, even though callers should normally use
the named variants. High-level send rejects duplicate reportable APC/MDS/MRDS/REQ/RES Kinds instead
of emitting intentionally duplicated per-datagram options.
The API deliberately does not expose option ordering or per-fragment boundary control.
OCS status is represented separately from TLV status as `OcsReport`; the API never invents an
`OptionKind` for the fixed OCS field. Direct `Res` construction is pass-through: callers MUST ensure
that every transmitted RES token was previously received by that transmitter in REQ. The library
does not auto-respond and does not attest provenance for caller-supplied RES.

## 3. The data model

This section lists the concrete public types and method signatures filled in by the roadmap steps.
Field definitions are reproduced from source where that helps audit the public shape.

### `model` constants

```rust
pub mod kind {
    pub const EOL: u8 = 0;
    pub const NOP: u8 = 1;
    pub const APC: u8 = 2;
    pub const FRAG: u8 = 3;
    pub const MDS: u8 = 4;
    pub const MRDS: u8 = 5;
    pub const REQ: u8 = 6;
    pub const RES: u8 = 7;
    pub const UNSAFE_MIN: u8 = 192;            // 0..=191 SAFE, 192..=255 UNSAFE
    pub const EXTENDED_LENGTH_MARKER: u8 = 255; // selects the extended 2-byte length form
}

pub mod length {
    pub const APC: u8 = 6;
    pub const FRAG_NON_TERMINAL: u8 = 10;
    pub const FRAG_TERMINAL: u8 = 12;
    pub const MDS: u8 = 4;
    pub const MRDS: u8 = 5;
    pub const REQ: u8 = 6;
    pub const RES: u8 = 6;
    pub const TIME: u8 = 10;
    pub const EXP_MIN: u8 = 4;
    pub const OCS: u8 = 2;
}

pub mod limits {
    use std::time::Duration;
    pub const MRDS_DEFAULT_IPV4: u16 = 2926;
    pub const MIN_REASSEMBLY_SEGMENTS: u8 = 2;
    pub const REASSEMBLY_TIMEOUT_MAX: Duration = Duration::from_secs(120);
    pub const REASSEMBLY_MAX_PENDING_PARTIALS: usize = 64;
    pub const NOP_RUN_DOS_THRESHOLD: usize = 7;
}
```

### `wire::ip::IpRepr`

```rust
pub struct IpRepr {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub ihl: u8,
    pub total_len: u16,
}

impl IpRepr {
    // Parse the leading IP header; return the repr and the offset of the transport payload.
    // IPv4 options are skipped (never decoded) and the header checksum is verified.
    pub fn parse(bytes: &[u8]) -> Result<(IpRepr, usize), HeaderError>;
    // Emit the header bytes (20 bytes incl. back-patched header checksum, requires ihl == 5).
    pub fn write(&self, out: &mut [u8]);
    // Offset of the transport payload from IP datagram start (ihl * 4).
    pub fn header_len(&self) -> usize;
    // Length of the IP transport payload in bytes (Total Length - IHL*4).
    pub fn transport_payload_len(&self) -> usize;
    // Fold the UDP pseudo-header (addresses, protocol 17, UDP length) into a fresh RFC 1071
    // accumulator; callers continue with header + data and finish().
    pub fn pseudo_header_sum(&self, udp_len: u16) -> Checksum;
}
```

### `wire::udp::UdpHeader`

```rust
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,    // UDP header + user data; 8 when empty
    pub checksum: u16,  // covers pseudo-header + UDP header + user data only
}

impl UdpHeader {
    // Rejects UDP Length < 8; the stored checksum is not verified here (pipeline policy).
    pub fn parse(bytes: &[u8]) -> Result<UdpHeader, HeaderError>;
    pub fn write(&self, out: &mut [u8]);
    // Compute the UDP checksum over pseudo-header + header + data (RFC 9868 Sec. 9);
    // a computed zero is returned as 0xFFFF (RFC 768), so this never returns 0.
    pub fn compute_checksum(&self, ip: &IpRepr, data: &[u8]) -> u16;
}
```

### `wire::surplus::SurplusLayout`

```rust
pub struct SurplusLayout {
    pub starts_at: usize, // offset of the surplus area from IP datagram start; odd exactly when needs_pad
    pub needs_pad: bool,  // true when starts_at is odd (a single zero pad byte precedes the OCS)
    pub len: usize,       // length of the surplus area in bytes, including any pad and the OCS
}

impl SurplusLayout {
    pub fn ocs_at(&self) -> usize;       // OCS offset: starts_at plus the pad byte when present
    pub fn range(&self) -> Range<usize>; // the surplus area: starts_at..starts_at + len
}
// range() is exactly the surplus area; the pad byte, when present, is the area's first byte.

// Compute where the surplus area lives, or None when there is no usable surplus area: no surplus,
// too small for any required pad byte plus the aligned OCS, or (defensively) UDP Length larger
// than the transport payload (RFC 9868 Sec. 7, Sec. 8).
pub fn locate_surplus(ip: &IpRepr, udp: &UdpHeader) -> Option<SurplusLayout>;
```

### `options::kind::OptionKind`

```rust
pub enum OptionKind {
    Eol, Nop, Apc, Frag, Mds, Mrds, Req, Res,
    Other(u8), // any other Kind byte, assigned or not
}

impl OptionKind {
    pub const fn from_byte(b: u8) -> OptionKind;
    pub const fn to_byte(self) -> u8;
    pub const fn is_safe(self) -> bool;           // Kind <= 191
    pub const fn is_unsafe(self) -> bool;         // Kind >= 192
    pub const fn is_must_support(self) -> bool;   // Kinds 0..=7
    pub const fn framing(self) -> OptionFraming;  // single-byte vs length-delimited
    pub const fn is_single_byte(self) -> bool;    // Eol / Nop
    pub const fn fixed_tlv_lengths(self) -> &'static [u8];
}

pub enum OptionFraming {
    SingleByte,
    LengthDelimited,
}
```

### `options::parse::OptionRef` and `OptionsIter`

```rust
pub struct OptionRef<'a> {
    pub kind: OptionKind,
    pub value: &'a [u8], // value bytes, no framing; empty for EOL and NOP
}

// Borrowing iterator over the option region after the OCS; total and non-panicking; yields one
// ParseError and then halts on malformed input.
pub struct OptionsIter<'a> { /* private: remaining bytes */ }

impl<'a> OptionsIter<'a> {
    pub fn new(options_bytes: &'a [u8]) -> OptionsIter<'a>;
}
impl<'a> Iterator for OptionsIter<'a> {
    type Item = Result<OptionRef<'a>, ParseError>;
}
```

### `options::RawOption`

```rust
pub struct RawOption {
    pub kind: OptionKind,
    pub value: Vec<u8>, // owned value bytes, no framing; empty for EOL/NOP
}

impl<'a> From<OptionRef<'a>> for RawOption { /* copies value into a Vec */ }
```

The wire Kind byte is canonical for both serialization and public API guard checks. For example,
`OptionKind::Other(3)` serializes as a FRAG option and is rejected by API paths that forbid
caller-supplied FRAG.

### `options::typed::TypedOption` and the typed structs

```rust
pub trait TypedOption: Copy {
    const KIND: OptionKind;
    fn decode(value: &[u8]) -> Result<Self, ParseError>;
    fn encode(&self, out: &mut Vec<u8>); // appends Kind + Length + Value
}

pub struct Apc  { pub crc32c: u32 }                  // Kind 2, total length 6 (RFC 9868 Sec. 11.3, Fig. 9)
pub struct Mds  { pub max_datagram_size: u16 }       // Kind 4, total length 4
pub struct Mrds { pub max_reassembled_size: u16, pub max_segments: u8 } // Kind 5, total length 5
pub struct Req  { pub token: [u8; 4] }               // Kind 6, total length 6
pub struct Res  { pub token: [u8; 4] }               // Kind 7, total length 6
pub struct Frag {                                    // Kind 3, total length 10 or 12
    pub frag_start: u16,        // offset from the start of the UDP header
    pub identification: u32,    // shared by all fragments of one datagram
    pub frag_offset: u16,       // offset in the reassembled datagram
    pub rdos: Option<u16>,      // Some(rdos) => terminal fragment; None => non-terminal
}
```

The `Frag` wire layout (RFC 9868 Sec. 11.4, Figs. 10/11):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Kind=3       |   Length      |       Fragment Start          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Identification                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Fragment Offset        |   RDOS (terminal only)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Length is 10 for a non-terminal fragment (no RDOS) and 12 for the terminal fragment (with RDOS).

### `frag::split` types

```rust
pub struct PeerFragmentLimits {
    pub max_reassembled_size: u16, // MRDS size, default IPv4 2926
    pub max_segments: u8,          // MRDS segs, default 2
}

pub struct SplitConfig {
    pub max_fragment_surplus_len: usize, // OCS-led fragment options + fragment data
    pub peer: PeerFragmentLimits,
    pub identification: u32,
}

pub struct Fragment {
    pub frag_offset: u16,      // atomic single-fragment uses 0
    pub terminal: bool,
    pub rdos: Option<u16>,
    pub surplus_body: Vec<u8>, // OCS placeholder still zero; raw send patches OCS
}

pub struct IdentificationGenerator { /* private */ }

pub fn split_datagram(
    payload: &[u8],
    per_datagram_options_body: &[u8],
    config: SplitConfig,
) -> Result<Vec<Fragment>, SplitError>;
```

### `frag::reassembly` types

```rust
pub struct FragKey {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub identification: u32, // FRAG Identification (RFC 9868 Sec. 11.4)
}

pub enum ReassemblyOutcome {
    Incomplete,
    Complete {
        tail: Vec<u8>,
        udp_length: u16,
        fragment_options: Vec<RawOption>,
        fragment_option_failures: Vec<OptionKind>,
        fragment_ocs_nonzero: Option<bool>,
    },
    Abort(AbortReason),
}

pub enum AbortReason { Overlap, LimitExceeded, Timeout }

pub struct ReassemblyLimits {
    pub max_reassembled_size: usize, // default IPv4 MRDS 2926, including UDP header
    pub max_segments: usize,         // default 2
    pub max_pending_partials: usize, // default REASSEMBLY_MAX_PENDING_PARTIALS
    pub timeout: Duration,           // default/clamped maximum REASSEMBLY_TIMEOUT_MAX
}

// The reassembly cache (state owned per socket pair by the receiver); pure, no I/O.
pub struct ReassemblyCache { /* private */ }

impl ReassemblyCache {
    pub fn new() -> ReassemblyCache;
    pub fn with_limits(limits: ReassemblyLimits) -> ReassemblyCache;
    pub fn insert(&mut self, key: FragKey, frag: Frag, data: &[u8], now: Instant) -> ReassemblyOutcome;
    pub fn insert_with_options(
        &mut self,
        key: FragKey,
        frag: Frag,
        data: &[u8],
        fragment_options: &[RawOption],
        now: Instant,
    ) -> ReassemblyOutcome;
    pub fn discard(&mut self, key: FragKey);
    pub fn gc(&mut self, now: Instant);
    pub fn len(&self) -> usize;
    pub fn is_empty(&self) -> bool;
}
```

> The `src`/`dst` addresses in `FragKey` are `Ipv4Addr` values. The reassembly key is (src IP, dst
> IP, src port, dst port, Identification) (RFC 9868 Sec. 11.4).

### `recv::pipeline::Delivery` and `process_datagram`

```rust
pub enum Delivery {
    Payload {
        data: Vec<u8>,              // the UDP user data handed to the application
        options: Vec<RawOption>,    // successfully processed options
        option_bearing: bool,       // true when a usable UDP-options surplus layout was present
        reports: Vec<OptionReport>, // datagram status plus coalesced FragmentSet status
        ocs_reports: Vec<OcsReport>,// fixed-field OCS status for datagram/fragment set
    },
    Buffered,                    // the datagram was a fragment; nothing to deliver yet
    Dropped,                     // fragment-local failure; no user delivery
}

pub enum OptionStatus { Success, Failed, Ignored }
pub enum OptionSource { Datagram, FragmentSet }
pub enum OcsStatus { Absent, Valid, Unused, Failed, InvalidZero, Unobserved }
pub struct OptionReport {
    pub kind: OptionKind,
    pub status: OptionStatus,
    pub source: OptionSource,
}
pub struct OcsReport {
    pub status: OcsStatus,
    pub source: OptionSource,
}

// The pure receive state machine: verify UDP cksum, locate/validate surplus, validate OCS, parse,
// honor Frag. Start as the fragment option/data boundary, then buffer, drop, or deliver
// (RFC 9868 Sec. 11.4, Sec. 14).
pub fn process_datagram(
    ip_datagram: &[u8],
    cache: &mut ReassemblyCache,
    now: Instant,
) -> Result<Delivery, RecvError>;
```

### Error types

```rust
pub enum ParseError {
    InvalidLength { kind: u8, len: usize }, // Length below the Kind minimum (malformed surplus)
    Overrun { offset: usize },              // option claims to extend past the surplus area
    DuplicateFrag,                          // FRAG appeared more than once
    NonZeroPad,                             // the single odd-offset alignment pad byte was non-zero
    OcsMismatch,                            // OCS sum did not fold to the one's-complement zero
}

pub enum SplitError {
    ReassembledDatagramTooLarge { len: usize, max: usize },
    SegmentLimitExceeded { needed: usize, max: u8 },
    FragmentCapacityTooSmall { required: usize, max: usize },
    FragmentSurplusTooLarge { len: usize, max: usize },
    RdosTooLarge { rdos: usize, max: usize },
    FragmentOffsetTooLarge { offset: usize, max: usize },
    OptionsBodyTooShort { len: usize },
    IdentificationExhausted,
    Serialize(SerializeError),
}

pub enum SocketError {
    Io(std::io::Error),
    PermissionDenied, // needs CAP_NET_RAW or root
}

pub enum SendError {
    Serialize(SerializeError),
    Split(SplitError),
    Socket(SocketError),
    FragmentIdentificationRequired,
    DatagramTooLarge { len: usize, max: usize },
    InvalidConfig { reason: &'static str },
}

pub enum HeaderError {                      // IP/UDP header invalidates the whole datagram (drop)
    IpTruncated { need: usize, have: usize },
    UnsupportedVersion(u8),
    BadIhl(u8),
    BadIpLength { length: u16 },
    IpChecksumMismatch,
    UnexpectedProtocol(u8),
    UdpTruncated { have: usize },
    UdpLengthInvalid { length: u16 },
}

pub enum RecvError {
    Header(HeaderError),   // whole datagram is dropped
    Parse(ParseError),     // surplus parse failed (payload is still delivered)
    UdpLengthExceedsIpPayload { udp_len: u16, transport_payload_len: usize },
    UdpChecksumMismatch { expected: u16, actual: u16 },
    Socket(SocketError),
}
```

### `api` types and functions

```rust
pub struct DatagramAddrs { pub src: Ipv4Addr, pub dst: Ipv4Addr, pub src_port: u16, pub dst_port: u16 }
pub enum FragmentationMode { Auto, Disabled }
pub struct SendOptions { /* raw options plus automatic APC */ }
pub struct SendConfig {
    pub max_datagram_len: usize,
    pub peer: PeerFragmentLimits,
    pub fragmentation: FragmentationMode,
    pub identification: Option<u32>, // explicit low-level ID, or OS-random Peer generator seed
}
pub struct ReceivePolicy { /* required options/OCS + drop-all-option-bearing */ }
pub struct ReceivedDatagram {
    pub data: Vec<u8>,
    pub options: Vec<RawOption>,
    pub reports: Vec<OptionReport>,
    pub ocs_reports: Vec<OcsReport>,
}
pub enum ApiDelivery { Received(ReceivedDatagram), Buffered, Dropped, Filtered }
pub struct SendOutcome { pub datagrams: usize, pub bytes: usize }
pub struct Peer { /* raw sockets, cache, policy, identification generator */ }

pub fn build_datagram(addrs: DatagramAddrs, payload: &[u8], raw_options: &[RawOption]) -> Result<Vec<u8>, SendError>;
pub fn build_outgoing_datagrams(
    addrs: DatagramAddrs,
    payload: &[u8],
    options: SendOptions,
    config: SendConfig,
) -> Result<Vec<Vec<u8>>, SendError>;
pub fn decode_datagram(
    datagram: &[u8],
    cache: &mut ReassemblyCache,
    now: Instant,
    policy: &ReceivePolicy,
) -> Result<ApiDelivery, RecvError>;
```

## 4. The four design rules

### Rule 1: parse borrowed, decode owned

The parser is zero-copy: `OptionsIter<'a>` yields `OptionRef<'a>` values whose `value: &'a [u8]`
borrows directly into the received surplus buffer. No allocation happens during parsing, and the
parser is total and non-panicking on arbitrary input (RFC 9868 Sec. 10). The typed values in
`options::typed` are fixed-length `Copy` PODs with no lifetime; `TypedOption::decode` borrows the
value bytes only transiently and returns an owned value.

The borrow never crosses the public API boundary. The pipeline collects what it returns into owned
`RawOption` (a `Kind` plus a `Vec<u8>`), so `Delivery::Payload { options: Vec<RawOption>, .. }`
carries no lifetime. The caller can hold the result after the receive buffer is reused or freed.

Rationale: zero-copy parsing keeps the hot path allocation-free and makes the parser easy to
fuzz/test against random bytes, while the owned boundary keeps the public API ergonomic and free of
lifetime entanglement. It also draws a crisp line for FF1: parsing is provably pure and borrow-only,
and the only owning step is the deliberate hand-off at the API edge.

```
  received bytes (surplus area)
        |  OptionsIter<'a>  (borrows)
        v
   OptionRef<'a> { kind, value: &'a [u8] }   <- never escapes the crate internals
        |  TypedOption::decode (transient borrow) / RawOption::from (copy)
        v
   Frag/Apc/... (Copy, no lifetime)  |  RawOption { kind, value: Vec<u8> }  <- crosses the API
```

### Rule 2: a single IP version (IPv4)

`IpRepr` exposes exactly the fields the UDP-options layer needs (addresses, the transport-payload
length, and a pseudo-header seed). The surplus-area math (`locate_surplus`), the UDP pseudo-header
(`IpRepr::pseudo_header_sum`), and the FRAG keying (`FragKey` stores `Ipv4Addr`) are all written
against this one type.

IPv6 is deliberately removed from scope: the RFC 9868 mechanism is IP-version-neutral and fully
demonstrated on IPv4, while IPv6 raw-socket `IPV6_HDRINCL` semantics differ and add platform
fragility without protocol insight.

### Rule 3: pure pipeline vs privileged I/O

`recv::pipeline::process_datagram` is a pure function from bytes (plus a mutable
`ReassemblyCache`) to a `Delivery`. It performs no system calls. The privileged surface is confined
to `socket/send` and `socket/recv`, which are thin: they obtain raw-socket file descriptors, set the
options (`IP_HDRINCL`), read or write bytes, and otherwise delegate to the pure
layers. All `unsafe` FFI lives in `socket/` behind safe wrappers; the crate denies
`unsafe_op_in_unsafe_fn`.

Rationale and payoff:

- The receive correctness (the RFC 9868 processing order, the OCS gate, the disposition branches, the
  reassembly DoS limits) is fully unit-testable without `CAP_NET_RAW`, so `cargo test` stays green and
  trustworthy and the integration tests (which need root) are `#[ignore]`-gated.
- It answers FF1 directly: the line between the pure pipeline and the privileged socket modules is
  exactly the line between "RFC behaviour implementable as pure logic" and "behaviour that depends on
  what the kernel's raw-socket path lets us do."

### Rule 4: strictly single-threaded and synchronous

The crate uses no threads, no async, and no background tasks -- in the library, the binaries, the
tests, and the examples. All state is owned and mutated on one call stack. Time-based behaviour (the
FRAG reassembly timeout and garbage collection) is **caller-driven**: `ReassemblyCache::gc(&mut self,
now: Instant)` takes the current time as a parameter and the application decides when to call it, so a
cache insertion enforces expiry at the timeout boundary while idle stale entries persist until the
caller invokes `gc(now)`. There is no background sweeper thread. This keeps the receive
path deterministic and trivially testable, and it matches the staged evaluation harness (Step 0.5 /
Step 17): each spike binary (the client and the server) is itself single-threaded and synchronous, and
the shell harness (`scripts/spike.sh`) orchestrates them as two separate sequential processes -- there
is no in-process threading or async.

## 5. Data flow

### 5.1 Send walkthrough

Goal: emit a UDP datagram for which
`UDP Length < IPv4 Total Length - IPv4 IHL*4`, so the IP transport-payload tail carries the OCS and
options (RFC 9868 Sec. 7). The kernel does not fill in the UDP checksum or OCS for a raw send, so the
crate computes both.

```
 caller: addresses, ports, payload, typed options [, fragment if > single-datagram capacity]
        |
        v
 (1) options::serialize::OptionsBuilder
        - emit the OCS-led body: OCS placeholder, canonical TLVs, EOL, even zero-fill
        - reserve the OCS as body[0..2] (placeholder 0x0000); odd-start pad is added by wire/send
        |   produces: fully prepared original options body with OCS = 0
        v
 (2) choose single datagram or frag::split
        - single: keep original payload/options body
        - FRAG: consume that prepared original representation; original UDP checksum and OCS are zero
        - produce empty-UDP-data fragment bodies with FRAG and fragment data
        v
 (3) options::ocs  (per emitted datagram/fragment back-patch)
        - RFC 1071 sum from aligned OCS through area end (OCS zero) + full 16-bit surplus length
        - write the one's complement of the folded sum into the OCS field
        |   produces: surplus-area bytes with a valid OCS
        v
 (4) wire/surplus + wire/udp
        - UDP Length = 8 + user-data length (NOT including the surplus area)
        - if the surplus area starts on an odd offset, prepend one separately validated zero pad;
          its length is in the OCS length addend but its byte is before the aligned OCS word stream
        - wire/udp::compute_checksum over pseudo-header + UDP header + user data only
        |   produces: UDP header bytes + checksum
        v
 (5) socket/send::assemble_datagram  (pure, via IpRepr/UdpHeader)
        - IP Total Length = IHL*4 + UDP Length + surplus-area length
        - assemble: IP header | UDP header | user data | [pad] | OCS | options
        |   produces: a full IP datagram on the stack
        v
 (6) socket/send  (privileged: Linux, IP_HDRINCL)   <-- the only privileged step
        - write the datagram on a SOCK_RAW socket with IP_HDRINCL set
        - assert: UDP Length < IP transport-payload length when an options body is present
        |
        v
 datagram on the wire
```

For a payload too large for a single datagram, step (2) invokes `frag/split` only after step (1) has
fully prepared the original options, as RFC 9868 Sec. 11.4 requires. The fragment size S derives from
the path MTU, with MDS as a hint -- never from MRDS. Each fragment has empty UDP user data (UDP
Length 8) and carries data after all fragment options; non-terminal fragments use Length 10 and the
terminal fragment Length 12 with RDOS. The reassembled size is capped by peer MRDS (default 2926);
payload beyond it is rejected. Steps (3) through (6) then finalize and send each fragment.

### 5.2 Receive walkthrough (ASCII state machine)

`recv::pipeline::process_datagram` implements the RFC 9868 processing order: verify the UDP checksum,
locate and validate the surplus area, validate the OCS, parse the options, then buffer, drop, or
deliver (RFC 9868 Sec. 11.4, Sec. 14). A malformed surplus area discards the options but still
delivers the payload; an unknown SAFE option is ignored; an unknown UNSAFE option outside a fragment
context drops the user data with a zero-length delivery, while a fragment-local failure produces no
application delivery.

```
 socket/recv (privileged) -> raw IP datagram bytes
        |
        v
 +-------------------------------------------------------------------------------+
 | (A) wire/ip::parse + wire/udp::parse                                           |
 |     check 8 <= UDP Length <= IP payload length; sampled-log either violation   |
 +-------------------------------------------------------------------------------+
        | invalid lengths --------------------------------> [DROP datagram]
        v ok
 +-------------------------------------------------------------------------------+
 | (B) verify UDP checksum (over pseudo-header + UDP header + user data only)     |
 +-------------------------------------------------------------------------------+
        | checksum != 0 and wrong -------------------------> [DROP datagram]
        | remember whether the UDP checksum was zero (feeds the OCS gate in (D))
        v ok (passed, or zero and therefore unused)
 +-------------------------------------------------------------------------------+
 | (C) wire/surplus::locate_surplus                                              |
 +-------------------------------------------------------------------------------+
        | no surplus area OR too small for the aligned OCS (2 bytes, or 3 with the odd-start pad)
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | needs_pad and the pad byte != 0 -> ParseError::NonZeroPad
        |        -------------------------------> Delivery::Payload { data, options: [] }
        v surplus present, pad ok
 +-------------------------------------------------------------------------------+
 | (D) OCS gate (the RFC 9868 Sec. 14 matrix over OCS value x UDP-checksum value) |
 |       OCS == 0: "unused", valid ONLY if the UDP checksum was also zero         |
 |       OCS != 0: validate via options::ocs (RFC 1071 sum from aligned OCS        |
 |                 through area end + the full 16-bit surplus length folds to     |
 |                 the one's-complement zero, 0xFFFF)                             |
 +-------------------------------------------------------------------------------+
        | record OcsReport (Absent/Valid/Unused/Failed/InvalidZero; Datagram source)
        | (OCS == 0 and UDP cksum != 0) -> options ignored (legacy emulation)
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | (OCS != 0 and validation fails) -> ParseError::OcsMismatch
        |        -------------------------------> Delivery::Payload { data, options: [] }
        v (OCS != 0 and passes) OR (OCS == 0 and UDP cksum == 0)
 +-------------------------------------------------------------------------------+
 | (E) options::parse (OptionsIter): walk the TLVs after the OCS                  |
 +-------------------------------------------------------------------------------+
        | Length under the Kind minimum, option underrun, or surplus overrun -> halt
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | duplicate known SAFE with sub-minimum Length -> halt before first-wins
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | assigned but out-of-scope SAFE below its known minimum (TIME/EXP) -> halt
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | other unexpected length of a known SAFE option -> ignore that option only
        |        (Sec. 10; exception: a malformed FRAG counts as unsupported UNSAFE)
        | unknown SAFE option   -> ignore it, keep going
        | unknown UNSAFE -> terminate immediately; do not scan later bytes for FRAG
        |        no earlier trusted FRAG: zero-length delivery (Sec. 10, 12, 14)
        | sub-minimum FRAG Length -> malformed surplus, deliver payload with options discarded
        | unknown UNSAFE option after an already valid empty-payload FRAG -> fragment-local failure
        |        -------------------------------> Delivery::Dropped
        | malformed per-fragment TLV after valid empty-payload FRAG -> Delivery::Dropped
        | unsupported FRAG format with empty user data -> unsupported UNSAFE
        | correctly framed FRAG with non-empty user data -> defer to (F), regardless of Frag. Start
        | valid empty-payload FRAG -> stop option parsing at Frag. Start; bytes at or after
        |        that offset are fragment data, not more options
        v parsed options
 +-------------------------------------------------------------------------------+
 | (F) FRAG present?                                                              |
 +-------------------------------------------------------------------------------+
        | no  -> Delivery::Payload { data, options: parsed }
        | yes, valid, but UDP Length != 8 (user data non-empty) -> ignore ALL options
        |        -------------------------------> Delivery::Payload { data, options: [] } (Sec. 11.4)
        | yes (UDP Length == 8, data in surplus) -> go to (G)
        v
 +-------------------------------------------------------------------------------+
| (G) FRAG reassembly cache                                                      |
|     insert by FragKey, offset-sort, suppress exact duplicates (bytes+options), |
|     abort overlap and enforce timeout plus per-datagram/per-cache limits       |
+-------------------------------------------------------------------------------+
        | Incomplete -> Delivery::Buffered
        | Abort(_) -> Delivery::Dropped
        | valid empty-payload FRAG plus UNSAFE/malformed per-fragment option -> Delivery::Dropped
        v
 Completion path: Complete { tail, udp_length, fragment_options, fragment_option_failures,
        fragment_ocs_nonzero }
        is re-fed ONCE into process_datagram.
        A reassembled datagram with no FRAG lands at (F) -> Delivery::Payload
        { data, options }; coalesced per-fragment SAFE options are prepended only when the option is
        usable per-fragment and no fragment failed that option kind. APC is per-datagram only. The
        fragment set also contributes its coalesced `OcsReport` with `OptionSource::FragmentSet`.
        A FRAG with non-empty data hits the (F) non-empty branch (options ignored, data delivered,
        Sec. 11.4); a nested FRAG with empty data is rejected -- local anti-loop policy, never a
        second re-feed (the RFC does not define nested fragmentation)
```

Disposition summary:

| Condition                                  | Payload      | Options    | Outcome                          |
|--------------------------------------------|--------------|------------|----------------------------------|
| UDP Length out of range                    | dropped      | -          | datagram dropped (RFC Sec. 10)   |
| UDP checksum present and wrong             | dropped      | -          | datagram dropped                 |
| No surplus area, or too small for pad+OCS  | delivered    | none       | `Payload { options: [] }`        |
| Odd-offset pad byte non-zero               | delivered    | discarded  | `Payload { options: [] }`        |
| OCS == 0 but UDP checksum non-zero         | delivered    | discarded  | `Payload { options: [] }`        |
| OCS != 0 and validation fails              | delivered    | discarded  | `Payload { options: [] }`        |
| Malformed TLV (sub-minimum/under/overrun)  | delivered    | discarded  | `Payload { options: [] }`        |
| Unexpected length, known SAFE option       | delivered    | rest kept  | that option ignored (Sec. 10)    |
| Sub-minimum FRAG Length                    | delivered    | discarded  | generic malformed-surplus case   |
| Unsupported FRAG format, empty UDP data    | zero-length  | discarded  | treated as unsupported UNSAFE    |
| Correctly framed FRAG, non-empty UDP data, unusable `Frag. Start` | delivered | discarded | FRAG exception; original data |
| Valid FRAG, user data non-empty            | delivered    | discarded  | `Payload { options: [] }` (Sec. 11.4) |
| Valid FRAG, bytes after `Frag. Start`      | deferred     | not parsed  | fragment data, `Buffered`        |
| Unknown SAFE option                        | delivered    | rest kept  | option ignored                   |
| Unknown UNSAFE before any trusted FRAG     | zero-length  | discarded  | stop; later FRAG bytes not inspected       |
| Unknown UNSAFE after trusted empty FRAG    | not delivered| discarded  | `Dropped`; not inserted into reassembly    |
| Malformed per-fragment option before data  | not delivered| discarded  | `Dropped`; no zero-length frame  |
| FRAG, more fragments needed                | -            | -          | `Buffered`                       |
| FRAG, overlap / cap / timeout              | not delivered| discarded  | `Dropped` / abort state          |
| FRAG complete                              | delivered*   | parsed*    | re-fed once, then `Payload`      |

\* after the single re-feed of the reassembled datagram.

## 6. The error model and the DoS-limit knobs

### Error model

Separate enums distinguish option-area failures, datagram failures, send failures, and raw-socket
failures:

- `ParseError` says *why* the surplus area or its options were rejected: `InvalidLength { kind, len }`
  (a Length wrong for its Kind), `Overrun { offset }` (an option claims to extend past the surplus
  area), `DuplicateFrag`, `NonZeroPad` (the single odd-offset alignment pad byte was non-zero), and
  `OcsMismatch` (the OCS did not validate to one's-complement zero). Per RFC 9868 (Sec. 10, Sec. 14,
  and Verified Technical Erratum 8834), a `ParseError` over the
  surplus area does not fail the receive: the options are discarded but the UDP payload is still
  delivered. This is exactly why `ParseError` is a distinct, recoverable type and not merged into
  `RecvError`.
- `HeaderError` says *why* the IP or UDP header invalidates the whole datagram: truncated headers,
  an unsupported IP version, a bad IHL, an inconsistent IP length field, an IPv4 header-checksum
  mismatch, a non-UDP protocol, or a UDP Length below 8. Unlike a `ParseError`, a `HeaderError`
  means the datagram itself cannot be trusted and is dropped (the first row of the disposition
  table), never "payload delivered, options discarded". Produced by `IpRepr::parse` and
  `UdpHeader::parse`. The raw receive boundary sampled-logs `UDP Length < 8` before rejecting it;
  the pure pipeline sampled-logs the upper-bound violation (`UDP Length > IP transport-payload
  length`).
- `SocketError` is the raw-socket failure type: `Io(std::io::Error)` for ordinary I/O failures and
  `PermissionDenied` for missing `CAP_NET_RAW` / root.
- `SendError` covers the public send API: serialization failure, split failure, socket failure,
  datagram-size overflow, or invalid configuration.
- `RecvError` is the pipeline/socket result type: protocol/header failures plus `Socket(SocketError)`.
  `Peer::recv()` treats protocol drops, buffered fragments, and policy drops as no user datagram, and
  only returns `Err` for socket failures.

The pure parser never panics on arbitrary input: malformed bytes always become a `ParseError`, never
an out-of-bounds index. That property is what makes the parser safe to feed with anything that arrives
on the wire and is part of how the design answers FF1 (it cleanly separates protocol-logic failures
from privilege/I/O failures).

### DoS-limit knobs (`model::limits`)

The FRAG reassembler is the main untrusted-input attack surface (an attacker can send fragments that
never complete), so the limits are gathered in one place and enforced in `frag/reassembly`
(RFC 9868 Sec. 11.4 reassembly rules, Sec. 25.4 fragmentation DoS). Receive-path warn diagnostics
are sampled globally before logging so malformed unauthenticated datagrams cannot produce one warning
per packet indefinitely:

| Knob                            | Value         | Purpose                                              |
|---------------------------------|---------------|-----------------------------------------------------|
| `MRDS_DEFAULT_IPV4`             | 2926 bytes    | reassembled-size cap when no MRDS option was seen    |
| `MIN_REASSEMBLY_SEGMENTS`       | 2             | the minimum fragment count an implementation supports|
| `REASSEMBLY_TIMEOUT_MAX`        | 120 s         | upper bound on how long a partial may live           |
| `REASSEMBLY_MAX_PENDING_PARTIALS` | 64          | incomplete-datagram cap within one pair-owned cache  |
| `NOP_RUN_DOS_THRESHOLD`         | 7             | a run of NOPs beyond this is logged as a possible DoS |

Additional reassembly defenses (implemented as cache policy in `frag/reassembly`, surfaced as
`AbortReason`): per-datagram byte and segment caps and a per-cache partial cap (`LimitExceeded`), overlap
abort with exact duplicate suppression (`Overlap`), the timeout plus garbage collection, and the rule that a completed
datagram is re-fed exactly once so reassembly cannot loop. The `NOP_RUN_DOS_THRESHOLD` is enforced in
the parser path: a NOP flood is detected and logged via sampled `log` diagnostics (it does not need
root, so it is covered by the pure tests). Parsing remains linear through the IPv4-bounded datagram;
it does not stop only because a run exceeds seven, so the RFC Sec. 25.2 work-limiting recommendation
is only partially implemented. The design deliberately has no fixed non-padding-TLV count cap:
the zero-copy scan allocates nothing and a global count limit could reject valid extensible option
sets. This is the documented NFR-04 opt-out, not a claimed RFC guarantee.

## 7. Dependency rationale

The crate keeps its dependency set small and hand-rolls the pieces that are the pedagogical core of
the thesis. What is hand-rolled, and why, is as important as what is pulled in (it is the substance of
the reference implementation and feeds FF1).

- **`socket2`** (raw-socket construction and options): a thin, well-tested wrapper over
  `socket`/`setsockopt`. The protocol is the contribution, not the socket boilerplate.
- **`libc`** (`IP_HDRINCL`, FFI constants): platform constants and calls
  that `socket2` does not expose; confined to `socket/`.
- **`thiserror`** (deriving `Display`/`Error` on the error enums): removes boilerplate; it does not
  touch any protocol logic.
- **`crc32c`** (the APC CRC32C, Castagnoli): a SIMD-accelerated, vector-checked CRC32C. APC carries a
  known checksum (CRC32C in network byte order, RFC 9868 Sec. 11.3, Fig. 9), not a thesis subject; a
  hand-rolled CRC32C would be slower and riskier without teaching anything new.
- **`clap`** (the example CLIs `udpopt-send`/`udpopt-recv`): argument parsing for the examples only;
  it is not used by the library.
- **`log`** (diagnostics, including the NOP-flood DoS log): a facade only; the binary chooses the
  backend.

Hand-rolled on purpose (no crate):

- **The RFC 1071 Internet checksum** (`wire/checksum`): it is the shared primitive behind both the UDP
  checksum and the OCS, and demonstrating it correctly (odd-length padding, end-around carry, and
  validation to a folded sum of `0xFFFF`, whose complement is zero) is part of the thesis.
- **The TLV parser and serializer** (`options/parse`, `options/serialize`): the zero-copy parse, the
  extended-length form, the canonical ordering, the NOP alignment, and the EOL/zero-fill are the core
  mechanism of RFC 9868 Sec. 10.
- **The OCS** (`options/ocs`): the two-pass back-patch, the "OCS field zero during computation," the
  inclusion of the 16-bit surplus length, and the receiver's one's-complement-zero check are the
  RFC 9868 Sec. 9 contribution.

Explicitly avoided: `nom`, `pnet`, `etherparse`, `smoltcp`, `bytes`, `nix`, and `zerocopy`. Pulling in
a parser combinator or a packet library would hide exactly the mechanism the reference implementation
exists to show, and would blur the FF1 boundary between "what the RFC requires" and "what a library
already does for us."
