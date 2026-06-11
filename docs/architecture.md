# Architecture

This document describes the internal architecture of `udp-transport-options`, a userspace reference
implementation of [RFC 9868](https://www.rfc-editor.org/rfc/rfc9868.txt) (Transport Options for UDP,
October 2025) in Rust. It goes deeper than `CLAUDE.md`: it states each module's inputs and outputs,
lists the concrete public types with their planned method signatures, explains the three design rules
with their rationale, and walks the send and receive data flows step by step.

The companion thesis asks two research questions, and the architecture is shaped to answer them:

- **FF1:** which RFC 9868 requirements are fully, partially, or not implementable in userspace over
  raw sockets?
- **FF2:** how far does the surplus area survive along real network paths, and how do NAT and filter
  devices treat datagrams that carry it?

> Status note: the crate is built step by step (see `docs/plan/ROADMAP.md`). The type definitions in
> this document are taken verbatim from the committed skeleton; the method signatures are the planned
> contracts that the steps will implement. Where a signature is planned rather than already present in
> source, it is labelled "(planned)".

## 1. Overview and design goals

RFC 9868 carries transport options in the **surplus area**: the bytes between the end of the UDP
payload (delimited by the UDP Length field) and the end of the IP transport payload (IPv4 Total
Length minus the IHL, or IPv6 Payload Length minus any extension headers) (RFC 9868 Sec. 4, Sec. 7).
A normal operating-system UDP stack delivers only the UDP-length-bounded payload and never exposes
the surplus area, so this crate reaches it with raw sockets on Linux.

```
 IP datagram
 +----------------+--------------------+--------------------------------------+
 | IP header      | UDP header (8 B)   | UDP user data | surplus area         |
 +----------------+--------------------+---------------+----------------------+
                  |<------ UDP Length ---------------->|
 |<------------------------ IP payload (Total Length - IHL) ------------------>|
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
4. **IP-version genericity.** IPv4 and IPv6 share one wire layer; only the `AF_INET6` socket wiring
   is version-specific.
5. **A safe boundary around `unsafe`.** All FFI lives in `src/socket/` behind safe wrappers; the
   crate sets `#![deny(unsafe_op_in_unsafe_fn)]`.

### Scope

In scope: the TLV options framework (RFC 9868 Sec. 10); the OCS (RFC 9868 Sec. 9); the must-support
options EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES; the zero-copy parser and the serializer; FRAG
fragmentation and reassembly; the two-tier API; IPv4 and IPv6; unit and loopback integration tests;
example peer CLIs.

Out of scope: the TIME option; the reserved AUTH/UCMP/UENC options; the RFC 9869 (DPLPMTUD)
REQ/RES-for-PMTUD use case; kernel modules; bidirectional or stateful protocols.

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
  `MRDS_DEFAULT_IPV6 = 2886`, `MIN_REASSEMBLY_SEGMENTS = 2`, `REASSEMBLY_TIMEOUT_MAX = 120 s`,
  `NOP_RUN_DOS_THRESHOLD = 7`).

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

`IpRepr`, the IP-version-generic view of the header fields the UDP-options layer needs (addresses,
the transport-payload length, and a pseudo-header seed for the UDP checksum), plus IPv4 and IPv6
header parse/build. Writing the surplus math, the UDP pseudo-header, and the FRAG keying once for both
families depends on this type. Inputs (parse): the leading bytes of an IP datagram. Outputs: an
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

### `options/serialize` (pure, hand-rolled)

`OptionsBuilder`: emits options in canonical order (must-support first), pads with NOP for alignment,
terminates with EOL, and zero-fills to a 2-byte boundary. It reserves the OCS as the first content of
the surplus area for the OCS pass to back-patch. Input: the options to emit. Output: the surplus-area
byte buffer (with a zero placeholder where the OCS goes). Root-free.

### `options/ocs` (pure, hand-rolled)

OCS computation and validation (RFC 9868 Sec. 9). Computation is a two-pass back-patch: serialize the
surplus area with the OCS field zero, run the RFC 1071 sum over the whole surplus area plus the 16-bit
surplus length, then write the one's complement of the folded sum into the OCS field. Validation recomputes the sum over the same
bytes (including the stored OCS) and requires the result to be zero. Built on `wire/checksum`. Input:
the surplus-area bytes (and length). Output: the OCS value, or a pass/fail verdict. Root-free.

### `options/typed` (pure)

The `TypedOption` trait and the fixed-length `Copy` structs `Apc`, `Mds`, `Mrds`, `Req`, `Res`,
`Frag`. Each decodes from, and encodes to, its wire bytes. APC carries a CRC32C over the UDP user
data (RFC 9868 Sec. 11.3, Fig. 9). Input (decode): an option's value bytes. Output: an owned typed
value, or a `ParseError` on a wrong length. Root-free.

### `options` (mod.rs) (pure)

`RawOption`: the owned counterpart of `OptionRef` (a Kind plus owned value bytes, no lifetime). This
is the type that crosses the public API boundary, so the parser's borrow never escapes. Root-free.

### `frag/split` (pure)

Fragmentation on the send side (RFC 9868 Sec. 11.4). Splits an oversized datagram into FRAG fragments,
each carried with empty UDP user data (UDP Length 8) and the fragment data in the surplus area after
the FRAG option. Non-terminal fragments use the 10-byte FRAG form; the terminal fragment uses the
12-byte form (carrying the RDOS). The single-fragment (atomic) case is supported; sizing respects MDS
and MRDS. Input: a datagram plus size constraints. Output: an ordered list of fragment surplus areas.
Root-free.

### `frag/reassembly` (pure)

Reassembly on the receive side (RFC 9868 Sec. 11.4). `ReassemblyCache` keyed by `FragKey`, with
offset-sorted insertion, overlap detection (overlap aborts), a timeout (<= 2 minutes), garbage
collection, and per-pair plus global DoS limits. A completed datagram is returned for one re-feed
into the pipeline (a reassembled datagram must not itself carry FRAG). Input: one fragment's
`FragKey`, `Frag` fields, and data. Output: a `ReassemblyOutcome` (`Incomplete`, `Complete(bytes)`,
or `Abort(reason)`). Root-free.

### `recv/pipeline` (pure)

`process_datagram`: the pure receive state machine that implements the RFC 9868 processing order
(RFC 9868 Sec. 14). It takes a full IP datagram as bytes and returns a `Delivery`. It performs no I/O,
so it is fully unit-testable without privileges; this module holds the bulk of the receive-side
correctness. Input: the raw IP-datagram bytes plus a mutable `ReassemblyCache`. Output: a `Delivery`
(`Payload { data, options }` or `Buffered`), or a `RecvError`. Root-free.

### `socket/send` (privileged: Linux, root)

The raw send path using `IP_HDRINCL` (RFC 9868 Sec. 15; locked decision). It builds the IP header,
the UDP header (with UDP Length < IP Total Length, which is what creates the surplus area), and the
surplus area; it computes the UDP checksum and the OCS by hand; and it transmits. Input: addresses,
ports, payload, and options. Output: a sent datagram (or a `RecvError::Io` /
`RecvError::PermissionDenied`). Needs `CAP_NET_RAW`. All `unsafe` FFI is confined here behind safe
wrappers.

### `socket/recv` (privileged: Linux, root)

The raw receive path using `SOCK_RAW` `IPPROTO_UDP`. It reads full IP datagrams with the surplus area
intact, filters by destination port in userspace, and hands the bytes to `recv::pipeline`. It
mitigates raw-socket noise (own-source copies and ICMP port-unreachable when no normal UDP socket is
bound). Input: the socket. Output: raw IP-datagram bytes for the pipeline. Needs `CAP_NET_RAW`.

### `api` (pure orchestration over privileged I/O)

The two-tier public API (RFC 9868 Sec. 15 use; locked decision):

- **low-level:** set and read explicit options on individual datagrams.
- **high-level:** a peer that sends and receives payloads with typed options, applying the OCS and
  fragmentation/reassembly transparently (a send larger than MRDS auto-fragments; the receiver
  reassembles transparently).

The API logic is pure orchestration; the privileged work happens inside the socket modules it drives.

## 3. The data model

This section lists the concrete public types (verbatim from the skeleton) and the planned method
signatures the steps will fill in. Field definitions are reproduced from source; methods marked
"(planned)" are the contracts, not yet present.

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
    pub const OCS: u8 = 2;
}

pub mod limits {
    use std::time::Duration;
    pub const MRDS_DEFAULT_IPV4: u16 = 2926;
    pub const MRDS_DEFAULT_IPV6: u16 = 2886;
    pub const MIN_REASSEMBLY_SEGMENTS: u8 = 2;
    pub const REASSEMBLY_TIMEOUT_MAX: Duration = Duration::from_secs(120);
    pub const NOP_RUN_DOS_THRESHOLD: usize = 7;
}
```

### `wire::ip::IpRepr`

```rust
pub enum IpRepr {
    V4 { src: Ipv4Addr, dst: Ipv4Addr, ihl: u8, total_len: u16 },
    V6 { src: Ipv6Addr, dst: Ipv6Addr, payload_len: u16, ext_hdr_len: u16 },
}

impl IpRepr {
    // Parse the leading IP header; return the repr and the offset of the transport payload.
    // IPv4 options are skipped (never decoded) and the header checksum is verified; IPv6
    // Hop-by-Hop (only directly after the base header) and Destination Options are skipped by
    // length, Routing/Fragment/AH/ESP and other chains are rejected.
    pub fn parse(bytes: &[u8]) -> Result<(IpRepr, usize), HeaderError>;
    // Emit the header bytes (V4: 20 bytes incl. back-patched header checksum, requires ihl == 5;
    // V6: 40 bytes, requires ext_hdr_len == 0 — building options/extension headers is out of scope).
    pub fn write(&self, out: &mut [u8]);
    // Offset of the transport payload from IP datagram start (ihl * 4, or 40 + ext_hdr_len).
    pub fn header_len(&self) -> usize;
    // Length of the IP transport payload in bytes (Total Length - IHL, or Payload Length
    // - ext_hdr_len).
    pub fn transport_payload_len(&self) -> usize;
    // Fold the UDP pseudo-header (addresses, protocol 17, UDP length) into a fresh RFC 1071
    // accumulator, identically for V4 and V6; callers continue with header + data and finish().
    pub fn pseudo_header_sum(&self, udp_len: u16) -> Checksum;
    // The source / destination IpAddr, used to build a FragKey.
    pub fn src_addr(&self) -> IpAddr;
    pub fn dst_addr(&self) -> IpAddr;
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
    pub starts_at: usize, // even offset of the surplus area (after any pad), from IP datagram start
    pub needs_pad: bool,  // true when the natural start was odd (a single zero pad precedes the OCS)
    pub len: usize,       // length of the surplus area in bytes, including any pad and the OCS
}

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
    pub fn from_byte(b: u8) -> OptionKind;        // (planned)
    pub fn to_byte(self) -> u8;                   // (planned)
    pub fn is_safe(self) -> bool;                 // Kind <= 191 (planned)
    pub fn is_must_support(self) -> bool;         // Kinds 0..=7 (planned)
    pub fn is_single_byte(self) -> bool;          // Eol / Nop (planned)
}
```

### `options::parse::OptionRef` and `OptionsIter`

```rust
pub struct OptionRef<'a> {
    pub kind: OptionKind,
    pub value: &'a [u8], // value bytes, no framing; empty for EOL and NOP
}

// Borrowing iterator over the option region after the OCS; total and non-panicking; yields one
// ParseError and then halts on malformed input. (planned)
pub struct OptionsIter<'a> { /* private: remaining bytes */ }

impl<'a> OptionsIter<'a> {
    pub fn new(options_bytes: &'a [u8]) -> OptionsIter<'a>;  // (planned)
}
impl<'a> Iterator for OptionsIter<'a> {
    type Item = Result<OptionRef<'a>, ParseError>;          // (planned)
}
```

### `options::RawOption`

```rust
pub struct RawOption {
    pub kind: OptionKind,
    pub value: Vec<u8>, // owned value bytes, no framing; empty for EOL/NOP
}

impl<'a> From<OptionRef<'a>> for RawOption { /* copies value into a Vec */ } // (planned)
```

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

### `frag::reassembly` types

```rust
pub struct FragKey {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub identification: u32, // FRAG Identification (RFC 9868 Sec. 11.4)
}

pub enum ReassemblyOutcome {
    Incomplete,         // more fragments needed; nothing to deliver yet
    Complete(Vec<u8>),  // reconstructed datagram, returned for one re-feed into the pipeline
    Abort(AbortReason), // partial state discarded
}

pub enum AbortReason { Overlap, LimitExceeded, Timeout }

// The reassembly cache (state owned by the receiver); pure, no I/O. (planned)
pub struct ReassemblyCache { /* private: keyed partials, byte/segment counters, timers */ }

impl ReassemblyCache {
    pub fn new() -> ReassemblyCache;                                   // (planned)
    // Insert one fragment; offset-sort, detect overlap, enforce caps and timeout. (planned)
    pub fn insert(&mut self, key: FragKey, frag: Frag, data: &[u8]) -> ReassemblyOutcome;
    pub fn gc(&mut self, now: Instant);  // drop timed-out partials (planned)
}
```

> The `src`/`dst` addresses in `FragKey` are full `IpAddr` values, so the same key type covers IPv4
> and IPv6 without change. The reassembly key is (src IP, dst IP, src port, dst port, Identification)
> (RFC 9868 Sec. 11.4).

### `recv::pipeline::Delivery` and `process_datagram`

```rust
pub enum Delivery {
    Payload {
        data: Vec<u8>,           // the UDP user data handed to the application
        options: Vec<RawOption>, // parsed options; empty if absent or discarded
    },
    Buffered,                    // the datagram was a fragment; nothing to deliver yet
}

// The pure receive state machine: verify UDP cksum, locate/validate surplus, validate OCS, parse,
// then reassemble (FRAG) or deliver (RFC 9868 Sec. 14). (planned)
pub fn process_datagram(
    ip_datagram: &[u8],
    cache: &mut ReassemblyCache,
) -> Result<Delivery, RecvError>;                                      // (planned)
```

### `error::ParseError`, `error::HeaderError`, and `error::RecvError`

```rust
pub enum ParseError {
    InvalidLength { kind: u8, len: usize }, // Length wrong for this Kind
    Overrun { offset: usize },              // option claims to extend past the surplus area
    NonZeroPad,                             // the single odd-offset alignment pad byte was non-zero
    OcsMismatch,                            // OCS did not validate to zero over the surplus area
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
    Parse(ParseError),     // surplus parse failed (payload is still delivered)
    Io(std::io::Error),    // raw-socket I/O error
    PermissionDenied,      // needs CAP_NET_RAW or root
}
```

## 4. The three design rules

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

### Rule 2: IP-version-generic wire layer

`IpRepr { V4, V6 }` exposes exactly the fields the UDP-options layer needs (addresses, the
transport-payload length, and a pseudo-header seed). Because of this, three pieces of logic are
written once and shared by both address families:

1. **surplus-area math** (`locate_surplus`): it works from the transport-payload length and the UDP
   Length regardless of version (RFC 9868 Sec. 7).
2. **the UDP pseudo-header** for the checksum: `IpRepr::pseudo_header_sum` folds the V4 or V6
   pseudo-header into the same running RFC 1071 sum.
3. **FRAG keying**: `FragKey` stores `IpAddr`, so one key type covers both families.

Only the `AF_INET6` socket wiring (`IPV6_HDRINCL`, address structs) is version-specific, and it is
confined to `socket/`. Rationale: the protocol logic is identical across versions; duplicating it
would double the surface that must be verified against the RFC and tested. Centralizing it means
Step 16 (IPv6) reuses the pipeline unchanged and only adds socket wiring.

### Rule 3: pure pipeline vs privileged I/O

`recv::pipeline::process_datagram` is a pure function from bytes (plus a mutable
`ReassemblyCache`) to a `Delivery`. It performs no system calls. The privileged surface is confined
to `socket/send` and `socket/recv`, which are thin: they obtain raw-socket file descriptors, set the
options (`IP_HDRINCL`, `IPV6_HDRINCL`), read or write bytes, and otherwise delegate to the pure
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
single socket pair cannot pin memory -- there is no background sweeper thread. This keeps the receive
path deterministic and trivially testable, and it matches the staged evaluation harness (Step 0.5 /
Step 17): each spike binary (the client and the server) is itself single-threaded and synchronous, and
the shell harness (`scripts/spike.sh`) orchestrates them as two separate sequential processes -- there
is no in-process threading or async.

## 5. Data flow

### 5.1 Send walkthrough

Goal: emit a UDP datagram whose IP Total Length is larger than its UDP Length, so the trailing bytes
form a surplus area carrying the OCS and the options (RFC 9868 Sec. 7). The kernel does not fill in
the UDP checksum or the OCS for a raw send, so the crate computes both. With `IP_HDRINCL`, the crate
builds the IP header itself, which is what lets UDP Length be smaller than IP Total Length.

```
 caller: addresses, ports, payload, typed options [, fragment if > MRDS]
        |
        v
 (1) options::serialize::OptionsBuilder
        - emit options must-support-first, NOP-align, EOL-terminate, zero-fill to 2-byte boundary
        - reserve the OCS as the first two bytes of the surplus area (placeholder 0x0000)
        |   produces: surplus-area bytes with OCS = 0
        v
 (2) options::ocs  (back-patch)
        - RFC 1071 sum over the whole surplus area (OCS field zero) + the 16-bit surplus length
        - write the one's complement of the folded sum into the OCS field
        |   produces: surplus-area bytes with a valid OCS
        v
 (3) wire/surplus + wire/udp
        - UDP Length = 8 + user-data length (NOT including the surplus area)
        - if the surplus area starts on an odd offset, prepend one zero pad byte (covered by OCS,
          not by the UDP checksum)
        - wire/udp::compute_checksum over pseudo-header + UDP header + user data only
        |   produces: UDP header bytes + checksum
        v
 (4) wire/ip  (build, via IpRepr)
        - IP Total Length (v4) / Payload Length (v6) = headers + UDP Length + surplus-area length
        - assemble: IP header | UDP header | user data | [pad] | OCS | options
        |   produces: a full IP datagram on the stack
        v
 (5) socket/send  (privileged: Linux, IP_HDRINCL)   <-- the only privileged step
        - write the datagram on a SOCK_RAW socket with IP_HDRINCL set
        - assert on the wire: IP Total Length > UDP Length (the surplus area is present)
        |
        v
 datagram on the wire
```

For a payload larger than the peer's MRDS, step (1) is preceded by `frag/split`, which produces one
FRAG fragment per output datagram: each fragment has empty UDP user data (UDP Length 8) and carries
its data in the surplus area after the FRAG option; non-terminal fragments use the 10-byte FRAG form
and the terminal fragment the 12-byte form with the RDOS (RFC 9868 Sec. 11.4). Steps (2) through (5)
then run per fragment.

### 5.2 Receive walkthrough (ASCII state machine)

`recv::pipeline::process_datagram` implements the RFC 9868 processing order: verify the UDP checksum,
locate and validate the surplus area, validate the OCS, parse the options, then reassemble (FRAG) or
deliver (RFC 9868 Sec. 14). A malformed surplus area discards the options but still delivers the
payload; an unknown SAFE option is ignored; an unknown UNSAFE option causes the reassembled data to
be dropped (RFC 9868 Sec. 10).

```
 socket/recv (privileged) -> raw IP datagram bytes
        |
        v
 +-------------------------------------------------------------------------------+
 | (A) wire/ip::parse + wire/udp::parse                                           |
 |     check 8 <= UDP Length <= IP payload length                                 |
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
        | no surplus area OR surplus < 2 bytes (no room for OCS)
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | needs_pad and the pad byte != 0 -> ParseError::NonZeroPad
        |        -------------------------------> Delivery::Payload { data, options: [] }
        v surplus present, pad ok
 +-------------------------------------------------------------------------------+
 | (D) OCS gate (the RFC 9868 Sec. 14 matrix over OCS value x UDP-checksum value) |
 |       OCS == 0: "unused", valid ONLY if the UDP checksum was also zero         |
 |       OCS != 0: validate via options::ocs (RFC 1071 sum over the whole surplus |
 |                 area incl. the stored OCS + the 16-bit surplus length == 0)    |
 +-------------------------------------------------------------------------------+
        | (OCS == 0 and UDP cksum != 0) -> options ignored (legacy emulation)
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | (OCS != 0 and validation fails) -> ParseError::OcsMismatch
        |        -------------------------------> Delivery::Payload { data, options: [] }
        v (OCS != 0 and passes) OR (OCS == 0 and UDP cksum == 0)
 +-------------------------------------------------------------------------------+
 | (E) options::parse (OptionsIter): walk the TLVs after the OCS                  |
 +-------------------------------------------------------------------------------+
        | any InvalidLength / Overrun -> halt
        |        -------------------------------> Delivery::Payload { data, options: [] }
        | unknown SAFE option   -> ignore it, keep going
        | unknown UNSAFE option -> drop the user data (Sec. 12; with FRAG via G, without FRAG directly)
        v parsed options
 +-------------------------------------------------------------------------------+
 | (F) FRAG present?                                                              |
 +-------------------------------------------------------------------------------+
        | no  -> Delivery::Payload { data, options: parsed }
        | yes (UDP Length == 8, data in surplus) -> go to (G)
        v
 +-------------------------------------------------------------------------------+
 | (G) frag/reassembly: insert into ReassemblyCache keyed by FragKey             |
 |     offset-sort; detect overlap; enforce per-pair + global caps and timeout   |
 +-------------------------------------------------------------------------------+
        | Incomplete                 -> Delivery::Buffered
        | Abort(Overlap|LimitExceeded|Timeout) -> drop partial -> Delivery::Buffered
        | unknown-UNSAFE seen in (E) -> drop the reassembled datagram -> Delivery::Buffered
        | Complete(bytes)            -> re-feed ONCE into process_datagram
        |                               (reassembled datagram MUST NOT carry FRAG)
        v
 second pass over the reassembled datagram lands at (F) with no FRAG ->
        Delivery::Payload { data, options }
```

Disposition summary:

| Condition                                  | Payload      | Options    | Outcome                          |
|--------------------------------------------|--------------|------------|----------------------------------|
| UDP Length out of range                    | dropped      | -          | datagram dropped (RFC Sec. 14)   |
| UDP checksum present and wrong             | dropped      | -          | datagram dropped                 |
| No surplus area, or surplus < 2 bytes      | delivered    | none       | `Payload { options: [] }`        |
| Odd-offset pad byte non-zero               | delivered    | discarded  | `Payload { options: [] }`        |
| OCS == 0 but UDP checksum non-zero         | delivered    | discarded  | `Payload { options: [] }`        |
| OCS != 0 and validation fails              | delivered    | discarded  | `Payload { options: [] }`        |
| Malformed TLV (length/overrun)             | delivered    | discarded  | `Payload { options: [] }`        |
| Unknown SAFE option                        | delivered    | rest kept  | option ignored                   |
| Unknown UNSAFE option (no FRAG)            | dropped      | discarded  | user data silently dropped (Sec. 12) |
| Unknown UNSAFE option (with FRAG)          | -            | -          | reassembled datagram dropped     |
| FRAG, more fragments needed                | -            | -          | `Buffered`                       |
| FRAG, overlap / cap / timeout              | -            | -          | partial discarded, `Buffered`    |
| FRAG complete                              | delivered*   | parsed*    | re-fed once, then `Payload`      |

\* after the single re-feed of the reassembled datagram.

## 6. The error model and the DoS-limit knobs

### Error model

Three enums separate "the options were bad" from "the datagram was bad" from "the receive operation
failed":

- `ParseError` says *why* the surplus area or its options were rejected: `InvalidLength { kind, len }`
  (a Length wrong for its Kind), `Overrun { offset }` (an option claims to extend past the surplus
  area), `NonZeroPad` (the single odd-offset alignment pad byte was non-zero), and `OcsMismatch` (the
  OCS did not validate to zero). Per RFC 9868 (Sec. 14), a `ParseError` over the surplus area does not
  fail the receive: the options are discarded but the UDP payload is still delivered. This is exactly
  why `ParseError` is a distinct, recoverable type and not merged into `RecvError`.
- `HeaderError` says *why* the IP or UDP header invalidates the whole datagram: truncated headers,
  an unsupported IP version, a bad IHL, an inconsistent IP length field, an IPv4 header-checksum
  mismatch, a non-UDP protocol, or a UDP Length below 8. Unlike a `ParseError`, a `HeaderError`
  means the datagram itself cannot be trusted and is dropped (the first row of the disposition
  table), never "payload delivered, options discarded". Produced by `IpRepr::parse` and
  `UdpHeader::parse`; how a drop is reported (and logged) is the Step-10 pipeline's decision.
- `RecvError` is the pipeline/socket result type: `Parse(ParseError)` (carried for diagnostics),
  `Io(std::io::Error)` (a raw-socket failure), and `PermissionDenied` (the operation needs
  `CAP_NET_RAW` or root). `RecvError` implements `From<ParseError>` and `From<std::io::Error>`.

The pure parser never panics on arbitrary input: malformed bytes always become a `ParseError`, never
an out-of-bounds index. That property is what makes the parser safe to feed with anything that arrives
on the wire and is part of how the design answers FF1 (it cleanly separates protocol-logic failures
from privilege/I/O failures).

### DoS-limit knobs (`model::limits`)

The FRAG reassembler is the main untrusted-input attack surface (an attacker can send fragments that
never complete), so the limits are gathered in one place and enforced in `frag/reassembly`
(RFC 9868 Sec. 11.4 reassembly rules, Sec. 25.4 fragmentation DoS):

| Knob                            | Value         | Purpose                                              |
|---------------------------------|---------------|-----------------------------------------------------|
| `MRDS_DEFAULT_IPV4`             | 2926 bytes    | reassembled-size cap when no MRDS option was seen    |
| `MRDS_DEFAULT_IPV6`             | 2886 bytes    | reassembled-size cap (IPv6) when no MRDS was seen    |
| `MIN_REASSEMBLY_SEGMENTS`       | 2             | the minimum fragment count an implementation supports|
| `REASSEMBLY_TIMEOUT_MAX`        | 120 s         | upper bound on how long a partial may live           |
| `NOP_RUN_DOS_THRESHOLD`         | 7             | a run of NOPs beyond this is logged as a possible DoS |

Additional reassembly defenses (implemented as cache policy in `frag/reassembly`, surfaced as
`AbortReason`): per-pair byte and segment caps and a global partial cap (`LimitExceeded`), overlap
abort (`Overlap`), the timeout plus garbage collection (`Timeout`), and the rule that a completed
datagram is re-fed exactly once so reassembly cannot loop. The `NOP_RUN_DOS_THRESHOLD` is enforced in
the parser path: a NOP flood is logged via `log` (it does not need root, so it is covered by the pure
tests).

## 7. Dependency rationale

The crate keeps its dependency set small and hand-rolls the pieces that are the pedagogical core of
the thesis. What is hand-rolled, and why, is as important as what is pulled in (it is the substance of
the reference implementation and feeds FF1).

- **`socket2`** (raw-socket construction and options): a thin, well-tested wrapper over
  `socket`/`setsockopt`. The protocol is the contribution, not the socket boilerplate.
- **`libc`** (`IP_HDRINCL`/`IPV6_HDRINCL`, `AF_INET6`, FFI constants): platform constants and calls
  that `socket2` does not expose; confined to `socket/`.
- **`thiserror`** (deriving `Display`/`Error` on the two enums): removes boilerplate; it does not
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
  checksum and the OCS, and demonstrating it correctly (odd-length padding, end-around carry, the
  `sum + complement == 0` property) is part of the thesis.
- **The TLV parser and serializer** (`options/parse`, `options/serialize`): the zero-copy parse, the
  extended-length form, the canonical ordering, the NOP alignment, and the EOL/zero-fill are the core
  mechanism of RFC 9868 Sec. 10.
- **The OCS** (`options/ocs`): the two-pass back-patch, the "OCS field zero during computation," the
  inclusion of the 16-bit surplus length, and the receiver's "sum must be zero" check are the
  RFC 9868 Sec. 9 contribution.

Explicitly avoided: `nom`, `pnet`, `etherparse`, `smoltcp`, `bytes`, `nix`, and `zerocopy`. Pulling in
a parser combinator or a packet library would hide exactly the mechanism the reference implementation
exists to show, and would blur the FF1 boundary between "what the RFC requires" and "what a library
already does for us."
