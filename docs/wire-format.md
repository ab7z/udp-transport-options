# Wire Format

This document specifies the on-the-wire byte layout of RFC 9868 UDP Options as implemented by this
crate. It is the authoritative reference for the encode and decode paths; every offset, `Kind`
number, and length below is verified against RFC 9868 (October 2025) and mirrors the constants
declared in `src/model.rs` and the types in `src/options/` and `src/wire/`.

Conventions:

- All multi-byte integers are big-endian (network byte order) on the wire, as required by RFC 9868
  Sec. 8. The skeleton structs store them in host byte order; conversion happens at the codec
  boundary.
- "Offset" is counted from the first byte of the surplus area unless stated otherwise.
- Byte diagrams are drawn most-significant byte first, one cell per byte.

## 1. The Surplus Area

UDP Options live in the surplus area, the region of the IP transport payload that extends past the
UDP datagram (RFC 9868 Sec. 7). It is computed from the IP payload length and the UDP Length field:

```
surplus_area = ip_transport_payload_length - udp_length
```

where `ip_transport_payload_length` is the IP total length minus the IP header and any extension
headers, and `udp_length` is the UDP `Length` field. The surplus area begins at the byte immediately
following the UDP user data (as delimited by `udp_length`) and runs to the end of the IP payload
(RFC 9868 Sec. 7):

```
+------------+------------+---------------------+-----------------------+
| IP Header  | UDP Header | UDP user data       | Surplus area          |
+------------+------------+---------------------+-----------------------+
|<-------- UDP Length -------------------------->|
|<-------- IP transport payload length ------------------------------->|
```

The surplus area is present only when `surplus_area > 0`; when `udp_length` equals the IP transport
payload length there is no surplus area and therefore no options (RFC 9868 Sec. 7). This computation
is the job of `wire::surplus`, whose `SurplusLayout { starts_at, needs_pad, len }` records the
(post-pad, 2-byte-aligned) OCS start offset, whether a pad byte is required, and the total surplus
length.

The IP-version-generic inputs come from `wire::ip::IpRepr`: for IPv4 the transport payload length is
`total_len` minus the IHL, and for IPv6 it is `payload_len` minus `ext_hdr_len`. The UDP boundary is
`wire::udp::UdpHeader::length`.

UDP Options are not reliable: middleboxes may strip or drop the surplus area, so an endpoint MUST NOT
depend on options arriving and MUST still operate correctly when the surplus area is removed in
transit (RFC 9868 Sec. 9). Options are interpreted only after the surplus area passes the OCS check
(RFC 9868 Sec. 8, Sec. 9).

## 2. OCS Placement and Alignment

The Options Checksum (OCS) is positional, not a TLV option: it occupies a fixed two-byte slot after
any required pre-OCS alignment pad and carries no `Kind` or `Length` octet (`model::length::OCS` =
2). The OCS MUST be aligned to the first 2-byte boundary of the area relative to the start of the IP
datagram (RFC 9868 Sec. 8). The surplus area is interpreted as UDP options only when there is enough
space for the optional pad byte and OCS, all pre-OCS pad bytes are zero, and the OCS validates;
otherwise the entire surplus area is ignored as though no options were present (RFC 9868 Sec. 8).

When the surplus area would otherwise begin at an odd offset relative to the start of the IP
datagram, a single pad byte is inserted before the OCS so that the OCS itself starts on an even
boundary. This
pad byte MUST be zero and is included in the OCS computation (RFC 9868 Sec. 8). `SurplusLayout`
records this case in its `needs_pad` field.

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

OCS is the standard Internet checksum: the 16-bit one's-complement sum (RFC 1071) computed over the
entire surplus area with the OCS field itself treated as zero, to which the length of the surplus
area is added as a 16-bit one's-complement addend; the result is stored as the one's-complement of
that sum, exactly as for the UDP checksum (RFC 9868 Sec. 9). The surplus-length addend plays the
role of a pseudo-header, binding the OCS to the surplus area's length (RFC 9868 Sec. 8).

```
sum = ones_complement_sum_16(surplus_area, with OCS field taken as zero)
sum = ones_complement_add_16(sum, surplus_len as u16)
OCS = !sum
```

This is the contract of `options::ocs`, which is built on the RFC 1071 primitive in `wire::checksum`
(the same primitive backs the UDP checksum, so it is hand-rolled rather than pulled from a crate).
Computation is a two-pass back-patch over the surplus area: the OCS field is reserved as zero, the
rest is serialized, then the field is patched in. Validation re-runs the one's-complement sum over
the whole surplus area; on a valid datagram the result is zero.

If the computed OCS does not validate, the entire surplus area MUST be ignored and the datagram
processed as though no options were present (RFC 9868 Sec. 8). The pad byte (Section 2), when
present, is part of the surplus area and so is covered by this sum.

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
serializer in `options::serialize` emits options in canonical order (must-support first), pads with
NOP for alignment, terminates with EOL, and reserves the OCS as the first option for back-patching.

### 4.1 Extended Length

A `Length` octet equal to 255 (`model::kind::EXTENDED_LENGTH_MARKER`) is a sentinel that selects the
Extended Length encoding: the two octets that follow are a 16-bit Extended Length giving the total
option length, and the literal value 255 is not the length (RFC 9868 Sec. 10).

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
  option forces the receiver to drop the surplus area or drop the datagram.

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
but unrecognized option is preserved as a `RawOption` so it can be inspected or re-emitted; SAFE
`Other` options may be skipped, UNSAFE `Other` options force a drop (RFC 9868 Sec. 10).

## 6. Application Payload Checksum (APC)

`Kind` 2 (`model::kind::APC` -> `OptionKind::Apc`), `Length` 6 (`model::length::APC`). APC carries a
CRC32c computed over the UDP user data (the bytes covered by the UDP Length field, excluding the UDP
header), letting a receiver detect corruption of the user data independently of the UDP header
checksum (RFC 9868 Sec. 11.3). The typed value is `options::typed::Apc { crc32c }`.

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
Options Size) trailer. The option contains a 16-bit Frag. Start, a 32-bit Identification, and a
16-bit Frag. Offset; the terminal fragment additionally carries the 16-bit RDOS (RFC 9868 Sec.
11.4).

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
5-tuple plus the FRAG Identification). The send side (`frag::split`) carries each fragment with empty
UDP user data (UDP Length 8) and places the data in the surplus area after the FRAG option.

## 8. Maximum Datagram Size (MDS)

`Kind` 4 (`model::kind::MDS` -> `OptionKind::Mds`), `Length` 4 (`model::length::MDS`). MDS advertises
the largest datagram the sender can receive without IP fragmentation, as a single 16-bit size
(RFC 9868 Sec. 11.5). The typed value is `options::typed::Mds { max_datagram_size }`.

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

Fields map to `options::typed::Mrds { max_reassembled_size, max_segments }`. When no MRDS option is
received, the default reassembly limits are 2926 bytes over IPv4 (`model::limits::MRDS_DEFAULT_IPV4`)
and 2886 bytes over IPv6 (`model::limits::MRDS_DEFAULT_IPV6`). A conforming implementation must be
able to reassemble at least two fragments (`model::limits::MIN_REASSEMBLY_SEGMENTS` = 2).

## 10. Echo Request and Echo Response (REQ / RES)

REQ is `Kind` 6 (`model::kind::REQ` -> `OptionKind::Req`) and RES is `Kind` 7 (`model::kind::RES` ->
`OptionKind::Res`); both have `Length` 6 (`model::length::REQ`, `model::length::RES`). They form a
lightweight echo handshake: the sender emits a REQ carrying an opaque 4-byte token, and the peer
echoes the same token back in a RES (RFC 9868 Sec. 11.7). The typed values are
`options::typed::Req { token }` and `options::typed::Res { token }`, each a `[u8; 4]`.

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
  odd; it MUST be zero and is covered by the OCS (RFC 9868 Sec. 8).
- The OCS is computed over the whole surplus area (pad byte included) with the OCS field taken as
  zero, plus `surplus_len` added as a 16-bit one's-complement addend, stored as the one's-complement
  of the sum (RFC 9868 Sec. 9).
- Each TLV option's `Length` counts its own `Kind` and `Length` octets; a `Length` of 255 selects
  the 16-bit Extended Length, and EOL ends processing so any trailing bytes are ignored (RFC 9868
  Sec. 10).
