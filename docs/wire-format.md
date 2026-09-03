# Wire Format

This document specifies the on-the-wire byte layout of RFC 9868 UDP Options as implemented by this
crate. It is the authoritative reference for the encode and decode paths; every offset, `Kind`
number, and length below is verified against RFC 9868 (October 2025) and mirrors the constants
declared in `src/model.rs` and the types in `src/options/` and `src/wire/`.

Conventions:

- All multi-byte integers are big-endian (network byte order) on the wire, as required by RFC 9868
  Sec. 8. The Rust structs store them in host byte order; conversion happens at the codec
  boundary.
- "Offset" is counted from the first byte of the surplus area unless stated otherwise.
- Byte diagrams are drawn most-significant byte first, one cell per byte.

## 1. The Surplus Area

UDP Options live in the surplus area, the region of the IP transport payload that extends past the
UDP datagram (RFC 9868 Sec. 7). It is computed from the IP payload length and the UDP Length field:

```
surplus_area = ip_transport_payload_length - udp_length
```

where `ip_transport_payload_length` is the IP total length minus the IP header (IHL x 4), and
`udp_length` is the UDP `Length` field. The surplus area begins at the byte immediately
following the UDP user data (as delimited by `udp_length`) and runs to the end of the IP payload
(RFC 9868 Sec. 7):

```
+------------+------------+---------------------+-----------------------+
| IP Header  | UDP Header | UDP user data       | Surplus area          |
+------------+------------+---------------------+-----------------------+
             |<---------- UDP Length ---------->|
             |<-------------- IP transport payload length --------------->|
```

The surplus area is present only when `surplus_area > 0`; when `udp_length` equals the IP transport
payload length there is no surplus area and therefore no options (RFC 9868 Sec. 7). This computation
is the job of `wire::surplus`, whose `SurplusLayout { starts_at, needs_pad, len }` records the
surplus-area start offset (the pad byte, when required, is the area's first byte), whether a pad
byte is required, and the total surplus length; the 2-byte-aligned OCS field sits at
`starts_at + needs_pad`.

The inputs come from `wire::ip::IpRepr`: the transport payload length is `total_len` minus the IP
header length in bytes (IHL x 4). The UDP boundary is
`wire::udp::UdpHeader::length`.

UDP Options are not reliable: middleboxes may strip or drop the surplus area, and a sender cannot
know in advance whether the receiver supports options at all (RFC 9868 Sec. 18, Sec. 19, Sec. 25.6).
The design therefore degrades to legacy behavior by default: SAFE options that do not arrive are
simply absent and the UDP user data is still delivered. The one exception is a receiver explicitly
configured to require a given option, which silently drops datagrams missing it (RFC 9868 Sec. 14,
Sec. 15). Options are interpreted only after the surplus area passes the OCS gate of Section 3
(RFC 9868 Sec. 8, Sec. 9).

## 2. OCS Placement and Alignment

The Options Checksum (OCS) is positional, not a TLV option: it occupies a fixed two-byte slot after
any required pre-OCS alignment pad and carries no `Kind` or `Length` octet (`model::length::OCS` =
2). The OCS MUST be aligned to the first 2-byte boundary of the area relative to the start of the IP
datagram (RFC 9868 Sec. 8). The surplus area is interpreted as UDP options only when there is enough
space for the optional pad byte and OCS, all pre-OCS pad bytes are zero, and the OCS gate of
Section 3 passes; otherwise the entire surplus area is ignored as though no options were present
(RFC 9868 Sec. 8, Sec. 9).

When the surplus area would otherwise begin at an odd offset relative to the start of the IP
datagram, a single pad byte is inserted before the OCS so that the OCS itself starts on an even
boundary. This
pad byte MUST be zero and is validated separately (RFC 9868 Sec. 8). The RFC 1071 word stream starts
at the aligned OCS rather than one byte earlier; the pad is nevertheless included in the full surplus
length addend used by the OCS (Section 3). `SurplusLayout` records this case in `needs_pad`.

```
Even natural start:                 Odd natural start:
+--------+--------+                 +--------+--------+--------+
| OCS hi | OCS lo |                 |  0x00  | OCS hi | OCS lo |
+--------+--------+                 +--------+--------+--------+
 offset 0..2                         pad     OCS at offset 1..3
```

After the (optional) pad byte and the two OCS bytes, the remaining surplus area carries the TLV
options described in Section 4.

## 3. The Option Checksum (OCS)

OCS is the standard Internet checksum: the 16-bit one's-complement sum (RFC 1071) computed from the
aligned OCS field through the end of the surplus area, with the OCS field itself treated as zero.
The full surplus length -- including any separately validated pre-OCS pad -- is added as a 16-bit
one's-complement value; the result is stored as the one's-complement of that sum (RFC 9868 Sec. 8,
Sec. 9). The length addend binds the checksum to the complete surplus extent without shifting the
absolute two-byte word grouping established by OCS alignment.

```
ocs_body = surplus_area[pre_ocs_pad_length..]
sum = ones_complement_sum_16(ocs_body, with OCS field taken as zero)
sum = ones_complement_add_16(sum, surplus_len as u16)
OCS = !sum
```

This is the contract of `options::ocs`, which is built on the RFC 1071 primitive in `wire::checksum`
(the same primitive backs the UDP checksum, so it is hand-rolled rather than pulled from a crate).
Computation is a two-pass back-patch over the surplus area: the OCS field is reserved as zero, the
rest is serialized, then the field is patched in. A computed value of `0x0000` is transmitted as its
one's-complement equivalent `0xFFFF`, exactly as for the UDP checksum, so a used OCS is never zero.
Validation re-runs the one's-complement sum over the OCS-aligned body (including the stored OCS)
and the full 16-bit surplus length; on a valid datagram the result is the one's-complement zero (a
folded sum of `0xFFFF`; equivalently, its complement is `0`).

The OCS is optional in exactly one case: when the UDP checksum is zero, the OCS MAY be unused, which
is indicated by a zero OCS value, and a zero OCS is then assumed correct without running any sum.
The OCS MUST be non-zero whenever the UDP checksum is non-zero, and implementations MUST default to
using a non-zero OCS (RFC 9868 Sec. 9). A zero OCS paired with a non-zero UDP checksum is handled by
the RFC 9868 Sec. 14 receive disposition (legacy emulation: deliver the payload, ignore all
options); see the disposition table in `docs/requirements.md` (FR-36).

If the OCS is in use and does not validate, the entire surplus area MUST be ignored and the datagram
processed as though no options were present (RFC 9868 Sec. 9). The pad byte remains part of the
surplus area and the length addend, but is not prepended to the OCS-aligned checksum byte stream.

The receive API exposes this fixed-field option separately from TLV `OptionReport`s as
`OcsReport { status: OcsStatus, source }`. `OcsStatus` distinguishes `Absent`, `Valid`, `Unused`,
`Failed`, and `InvalidZero`; fragment sets receive their own coalesced report, which degrades to
`Unobserved` when fragments entered the shared reassembly cache through its public insertion
methods (no OCS observation; never satisfies a required-OCS policy). This avoids inventing a Kind
byte for OCS while satisfying the Sec. 15 status requirement.

## 4. TLV Option Framing

Each option after the OCS uses TLV (type, length, value) syntax (RFC 9868 Sec. 8, Sec. 10):

```
+--------+--------+----------------------+
|  Kind  | Length |   Value (variable)   |
+--------+--------+----------------------+
   1 byte   1 byte    Length - 2 bytes
```

- `Kind` (1 byte): the option type (`options::kind::OptionKind`).
- `Length` (1 byte): the total number of bytes in the option, including the `Kind` and `Length`
  octets themselves (RFC 9868 Sec. 10). The smallest valid TLV `Length` is therefore 2.
- `Value`: `Length - 2` bytes of option data.

The parser in `options::parse` yields borrowed `OptionRef { kind, value }` views over the surplus
bytes (value excludes framing); the owned counterpart is `options::RawOption { kind, value }`. The
serializer in `options::serialize` emits the OCS-led body: a bare two-byte zero OCS placeholder,
canonical TLV options (FRAG first when present, then other must-support options, then other SAFE
options), NOP only when needed to align a following TLV, EOL, and zero-fill to an even body length.
The must-support-before-other-SAFE part is the RFC 9868 Sec. 10 transmitter MUST; the exact
FRAG-first order inside the must-support group and the even-length zero-fill are this builder's
canonical form. For known fixed-size options, the builder validates the raw value length before
emitting the TLV so it does not create malformed APC/FRAG/MDS/MRDS/REQ/RES options. It also rejects
duplicate FRAG options, patches the FRAG Start field to the final fragment-data offset, and accepts
raw `Other` options only for the unassigned SAFE range `10..=126`; assigned or reserved out-of-scope
SAFE Kinds such as TIME, AUTH, EXP, and 128..=191 are not generated by this builder.
The optional pre-OCS pad byte for an odd surplus start is emitted by the wire/send layer, not by the
serializer.
The API uses this serializer only when at least one option is requested; an empty option set emits no
surplus area and therefore no bare OCS/EOL body.

### 4.1 Extended Length

A `Length` octet equal to 255 (`model::kind::EXTENDED_LENGTH_MARKER`) is a sentinel that selects the
Extended Length encoding: the two octets that follow are a 16-bit Extended Length giving the total
option length, and the literal value 255 is not the length (RFC 9868 Sec. 10).
Because the length is total option length, the default form can carry at most 252 value bytes
(`252 + Kind + Length = 254`). For this canonical serializer, a value of 253 bytes is the first case
that cannot fit the default form and encodes an Extended Length of 257
(`253 + Kind + marker + Extended Length`). A receiver can still encounter structurally bounded
extended totals 255 or 256; the parser accepts them even though the corresponding values could have
used a shorter default encoding.

The transmitter MUST use the default form for a total option length of at most 254 and the extended
form above 254. This crate also rejects bounded received extended encodings with total length
`4..=254`. That receive disposition is an explicit local strictness policy; RFC 9868 specifies the
wire form but does not separately prescribe the receiver outcome for this non-canonical, otherwise
bounded encoding. Extended lengths below the four-byte extended header are inherently malformed.

```
+--------+--------+--------+--------+----------------------+
|  Kind  |  255   |   Extended Length (16 bits)  |  Value  |
+--------+--------+--------+--------+----------------------+
```

### 4.2 Single-Byte Options

EOL (`Kind` 0, `model::kind::EOL`) and NOP (`Kind` 1, `model::kind::NOP`) are the two exceptions:
each is exactly one byte, a `Kind` octet with no `Length` and no `Value` (RFC 9868 Sec. 8, Sec. 10).
EOL terminates option processing in the surplus area; any bytes following an EOL are ignored. NOP is
padding and may appear multiple times. Both decode with an empty `value` in `OptionRef`/`RawOption`.

## 5. Kind Codepoints and Ranges

The `Kind` octet is partitioned into two ranges (RFC 9868 Sec. 10), with the boundary at
`model::kind::UNSAFE_MIN` (192):

- SAFE, `Kind` 0..=191: an option a receiver may safely skip when it does not recognize it. Skipping
  it does not change the meaning of the UDP user data.
- UNSAFE, `Kind` 192..=255: an option that MUST NOT be silently skipped. An unrecognized UNSAFE
  option forces the receiver to terminate option processing, drop all options, and drop the
  (reassembled) UDP user data. On the ordinary or post-reassembly path, a zero-length datagram is
  still delivered to the user (RFC 9868 Sec. 10, Sec. 12, Sec. 14). If a valid empty-payload FRAG was
  already established before the failure, the fragment/reassembly set is discarded with no user
  frame. Processing stops at the first unsupported UNSAFE; later bytes are never scanned for FRAG.

Within the SAFE range, `Kind` 0..=7 are the must-support options every conforming implementation is
required to support (RFC 9868 Sec. 10):

| Kind | Name | Variant            | model::kind | Section    |
|------|------|--------------------|-------------|------------|
| 0    | EOL  | `OptionKind::Eol`  | `EOL`       | Sec. 10    |
| 1    | NOP  | `OptionKind::Nop`  | `NOP`       | Sec. 10    |
| 2    | APC  | `OptionKind::Apc`  | `APC`       | Sec. 11.3  |
| 3    | FRAG | `OptionKind::Frag` | `FRAG`      | Sec. 11.4  |
| 4    | MDS  | `OptionKind::Mds`  | `MDS`       | Sec. 11.5  |
| 5    | MRDS | `OptionKind::Mrds` | `MRDS`      | Sec. 11.6  |
| 6    | REQ  | `OptionKind::Req`  | `REQ`       | Sec. 11.7  |
| 7    | RES  | `OptionKind::Res`  | `RES`       | Sec. 11.7  |

Any other codepoint, assigned or not, is carried verbatim as `OptionKind::Other(u8)`. A well-formed
but unrecognized option is preserved as a `RawOption` so it can be inspected; the Step 5 raw builder
re-emits only unassigned SAFE `Other` Kinds `10..=126`. SAFE `Other` options may be skipped, UNSAFE
`Other` options force the user-data drop described above (RFC 9868 Sec. 10).

An option that claims bytes beyond the surplus option area is not ignored locally. Per Sec. 10 and
[RFC Editor Erratum 8834](https://www.rfc-editor.org/errata/eid8834), the whole options area is
malformed and all TLV options/TLV reports are discarded; the ordinary UDP payload remains
deliverable. The separately modeled OCS gate can still report the checksum disposition that was
established before TLV parsing.

## 6. Additional Payload Checksum (APC)

`Kind` 2 (`model::kind::APC` -> `OptionKind::Apc`), `Length` 6 (`model::length::APC`). APC carries a
CRC32c computed over the UDP user data (the bytes covered by the UDP Length field, excluding the UDP
header), letting a receiver detect corruption of the user data independently of the UDP header
checksum (RFC 9868 Sec. 11.3). The typed value is `options::typed::Apc { crc32c }`.
RFC 9868 reports APC as useful only per-datagram because UDP fragments have no UDP user data; a
fragment-local APC is therefore treated like an unusable SAFE per-fragment option and is not
coalesced into `FragmentSet` status.

```
+--------+--------+--------+--------+--------+--------+
|  Kind  | Length |             crc32c (32)           |
|   2    |   6    |                                   |
+--------+--------+--------+--------+--------+--------+
   off 0    off 1   off 2 .............. off 5
```

## 7. Fragmentation (FRAG)

`Kind` 3 (`model::kind::FRAG` -> `OptionKind::Frag`). FRAG permits a single UDP datagram with options
to be split across multiple IP packets at the UDP Options layer (RFC 9868 Sec. 11.4). A non-terminal
fragment uses `Length` 10 (`model::length::FRAG_NON_TERMINAL`); the terminal fragment uses `Length`
12 (`model::length::FRAG_TERMINAL`), the extra two bytes holding the RDOS (Reassembled Datagram
Option Start) pointer. The option contains a 16-bit Frag. Start, a 32-bit Identification, and a
16-bit Frag. Offset; the terminal fragment additionally carries the 16-bit RDOS (RFC 9868 Sec.
11.4). The field semantics (all offsets in bytes):

- `Frag. Start`: where this fragment's data begins, measured from the beginning of this fragment's
  UDP header (the data follows the remainder of the fragment's UDP options and runs to the end of
  the IP datagram).
- `Frag. Offset`: where this fragment's data belongs within the original (pre-fragmentation) UDP
  datagram, measured from the start of the original datagram's UDP header.
- `RDOS` (terminal only): a pointer, measured from the start of the original UDP datagram's header,
  to the end of the reassembled data and thus the start of the per-datagram surplus area (the
  options that apply to the reassembled datagram) within the original datagram. It is an offset,
  not a size.

Non-terminal FRAG (`Length` 10):

```
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
|  Kind  | Length |   Frag. Start    |        Identification             |  Frag. Offset |
|   3    |   10   |   frag_start     |          identification           |  frag_offset  |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
   off 0    off 1   off 2 .. off 3    off 4 ............ off 7            off 8 .. off 9
```

Terminal FRAG (`Length` 12) appends the 16-bit RDOS trailer:

```
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
|  Kind  | Length |   Frag. Start    |        Identification             |  Frag. Offset |     RDOS      |
|   3    |   12   |   frag_start     |          identification           |  frag_offset  |     rdos      |
+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+--------+
```

Fields map to `options::typed::Frag { frag_start, identification, frag_offset, rdos }`, where `rdos`
is `Option<u16>`: `None` on a non-terminal fragment, `Some(_)` on the terminal fragment. All
fragments of one datagram share the same 32-bit `identification`; on the receive side a reassembler
groups them by `frag::reassembly::FragKey { src, dst, src_port, dst_port, identification }` (the UDP
4-tuple plus the FRAG Identification). The send side (`frag::split`) carries each fragment with empty
UDP user data (UDP Length 8) and places the fragment data in the surplus area after all of the
fragment's options (the data follows the remainder of the UDP options, as located by `Frag. Start`,
and runs to the end of the IP datagram). The receive pipeline uses the same boundary: for a valid
empty-payload FRAG, bytes at or after `Frag. Start` are fragment data and are not interpreted as
additional UDP options. The receive-side reassembler stores those bytes by `FragKey`, coalesces
validated per-fragment MDS/MRDS/REQ/RES values, suppresses exact duplicate fragments only when both
the fragment data and per-fragment options match, aborts conflicting overlap or fragment-local
UNSAFE/malformed failures, and re-feeds the reconstructed datagram once when terminal coverage is
gap-free.

A sender first fully prepares the original datagram's options, with the original OCS represented as
zero for the fragmenting path, and only then passes that representation to `frag::split`. The
original UDP checksum SHOULD be zero because it is never sent; when each fragment uses non-zero OCS,
the original OCS SHOULD likewise be zero. Each emitted fragment then receives its own per-fragment
options, UDP checksum, and OCS before transmission (RFC 9868 Sec. 11.4).

On receive, a correctly framed FRAG combined with non-empty UDP user data is never used as a
reassembly boundary: all options are ignored and the original user data is delivered. Empty-payload
fragments are reassembled only after a trusted FRAG. Cache resource limits are intended to be per
socket pair: low-level callers must not share one `ReassemblyCache` across pairs because its
pending-partial cap applies to the entire cache. `Peer` owns one cache per instance, but the raw
receiver filters ports only, so distinct address pairs that share those ports share the budget
(FR-34 partial). The default timeout is clamped to 120 seconds and expires when
`elapsed >= timeout`; reclamation remains caller-driven through insertion/`gc`.

## 8. Maximum Datagram Size (MDS)

`Kind` 4 (`model::kind::MDS` -> `OptionKind::Mds`), `Length` 4 (`model::length::MDS`). MDS advertises
the IP-layer MTU minus the fixed IP and UDP headers, as a single 16-bit size (RFC 9868 Sec. 11.5).
The typed value is `options::typed::Mds { max_datagram_size }`.

```
+--------+--------+--------+--------+
|  Kind  | Length | max_datagram_sz |
|   4    |   4    |      (16)       |
+--------+--------+--------+--------+
   off 0    off 1   off 2 .. off 3
```

## 9. Maximum Reassembled Datagram Size (MRDS)

`Kind` 5 (`model::kind::MRDS` -> `OptionKind::Mrds`), `Length` 5 (`model::length::MRDS`). MRDS
advertises the largest reassembled datagram the sender can accept after UDP Options-layer
reassembly: a 16-bit size followed by a one-byte maximum-segment count (RFC 9868 Sec. 11.6).

```
+--------+--------+--------+--------+--------+
|  Kind  | Length | max_reassembled | segs   |
|   5    |   5    |   _size (16)    |  (8)   |
+--------+--------+--------+--------+--------+
   off 0    off 1   off 2 .. off 3    off 4
```

Fields map to `options::typed::Mrds { max_reassembled_size, max_segments }`. The advertised size
counts the whole reassembled datagram including the UDP header and any per-datagram options
(RFC 9868 Sec. 11.6). When no MRDS option has been received, a sender MUST assume an MRDS size of
2926 bytes over IPv4 (`model::limits::MRDS_DEFAULT_IPV4`) with 2 segments; a receiver MUST support
at least these values (`model::limits::MIN_REASSEMBLY_SEGMENTS` = 2) (the RFC additionally defines
2886 for IPv6, out of scope here) (RFC 9868 Sec. 11.6).

## 10. Echo Request and Echo Response (REQ / RES)

REQ is `Kind` 6 (`model::kind::REQ` -> `OptionKind::Req`) and RES is `Kind` 7 (`model::kind::RES` ->
`OptionKind::Res`); both have `Length` 6 (`model::length::REQ`, `model::length::RES`). They form a
lightweight echo handshake: the sender emits a REQ carrying an opaque 4-byte token, and the peer
echoes the same token back in a RES (RFC 9868 Sec. 11.7). The typed values are
`options::typed::Req { token }` and `options::typed::Res { token }`, each a `[u8; 4]`.

The implementation is a pass-through library and never generates RES automatically. A caller that
constructs a RES MUST use a token it previously received in REQ; direct `Res`/`--res` construction
does not make the library a provenance authority. Using the most recently received REQ token is the
RFC's upper-layer SHOULD (RFC 9868 Sec. 11.7).

```
REQ (Kind 6) / RES (Kind 7):
+--------+--------+--------+--------+--------+--------+
|  Kind  | Length |             token (32)            |
|  6/7   |   6    |                                   |
+--------+--------+--------+--------+--------+--------+
   off 0    off 1   off 2 .............. off 5
```

## 11. Surplus Area Arithmetic Summary

Putting the pieces together, the surplus area is laid out as:

```
[ optional 1-byte zero pad ] [ OCS (2 bytes) ] [ TLV options ... ] [ optional EOL ]
```

- `surplus_area = ip_transport_payload_length - udp_length` (RFC 9868 Sec. 7); options are present
  only when this is greater than zero.
- The pad byte is present iff the surplus area's natural start offset relative to the IP datagram is
  odd; it MUST be zero and is validated separately (RFC 9868 Sec. 8).
- The OCS checksum byte stream begins at the aligned OCS field, not at an earlier pad. It is computed
  through the end of the area with the OCS field taken as zero, plus the full `surplus_len` (including
  the pad) as a 16-bit one's-complement addend, stored as the one's-complement
  of the sum (a computed `0x0000` is sent as `0xFFFF`); a zero OCS is legal only when the UDP
  checksum is also zero (RFC 9868 Sec. 9).
- Each TLV option's `Length` counts its own `Kind` and `Length` octets; a `Length` of 255 selects
  the 16-bit Extended Length, and EOL ends processing so any trailing bytes are ignored (RFC 9868
  Sec. 10).
