# Requirements

This document records the requirements for the RFC 9868 (Transport Options for UDP, October 2025) reference
implementation in this repository. It exists to make the project's claims about RFC conformance auditable and to
ground the two research questions of the accompanying master's thesis:

- **FF1**: which RFC 9868 requirements are fully, partially, or not implementable in userspace over raw sockets.
- **FF2**: how far the surplus area survives along real network paths, and how NAT and filter devices treat
  datagrams that carry it.

Each functional requirement carries an RFC source section, a normative level (MUST/SHOULD/MAY), a scope flag, the
ROADMAP step that implements it (see `docs/plan/ROADMAP.md`), and a status. The status vocabulary tracks both
implementation progress and the FF1 userspace feasibility lens:

- **Planned**: in scope, fully implementable in userspace, scheduled in a ROADMAP step.
- **Implemented**: the covered in-scope requirement is complete in the steps listed in the row.
- **Partially implemented**: a concrete subset is present, but the full stated behavior or evidence
  is not; the row names what remains instead of implying that a roadmap status completes it.
- **Partial-in-userspace**: implementable, but with a caveat imposed by the userspace / raw-socket constraint
  (documented in the Notes and in the "Userspace / raw-socket limitations" section).
- **Delegated**: the wire behavior is implemented, while an RFC obligation that belongs to the upper layer is an
  explicit caller precondition rather than library-managed state.
- **Not selected**: an optional RFC MAY/conditional SHOULD is deliberately not implemented; the rationale is recorded
  in the row rather than leaving an unowned "Planned" item.
- **Not-feasible-in-userspace**: cannot be met faithfully from userspace with raw sockets; explained in the same
  section. (No in-scope requirement currently carries this status; it is reserved for the FF1 discussion.)

Out-of-scope items (TIME, AUTH/UCMP/UENC, RFC 9869 DPLPMTUD use cases, kernel modules, stateful protocols, IPv6) are
kept in the conformance matrix and marked explicitly so the boundary of the contribution is visible. IPv6 was removed
from scope: the RFC 9868 mechanism is IP-version-neutral and fully demonstrated on IPv4; IPv6 raw-socket
`IPV6_HDRINCL` semantics differ and added platform fragility without protocol insight.

IDs (FR-NN, NFR-NN) are stable; do not renumber. Steps are the ROADMAP.md numbers 0..17 (16 removed with IPv6). Arrows are written `->`;
comparisons `<=` / `>=`.

## Reference: wire facts used below

The surplus area is the IP-payload tail after the UDP-Length-bounded user data, up to the end of the IP transport
payload (RFC 9868 Sec. 7). It can begin at any byte offset (Sec. 7); its first non-padding field, the 2-byte OCS, is aligned
to the first 2-byte boundary of the area relative to the start of the IP datagram, an odd natural start being
preceded by one zero pad byte (Sec. 8). The OCS algorithm is defined in Sec. 9. Options are TLV with a 1-byte Kind, a 1-byte Length (total, including Kind and Length), and a value;
`Length == 255` selects the 2-byte Extended Length form; EOL (Kind 0) and NOP (Kind 1) are single bytes with no
Length (Sec. 10). Must-support Kinds are 0..7; SAFE is 0..191, UNSAFE is 192..255 (Sec. 10).

```
                 IP transport payload
      <------------------------------------------------->
+--------+---------+----------------------+------------------+
| IP Hdr | UDP Hdr |     UDP user data    |   surplus area   |
+--------+---------+----------------------+------------------+
          <------------------------------>
                     UDP Length
```

The surplus area itself (RFC 9868 Sec. 8, 9, 10):

```
+--------+--------+--------+--------+------~~------+
| [pad]  |      OCS        |  Kind  | Len | value | ...   -> EOL + zero-fill
+--------+--------+--------+--------+------~~------+
 0 or 1    2 bytes          one or more TLV options
 byte
```

## 1. Functional requirements

| ID | Requirement | RFC source | Priority | Scope | Step | Status | Notes |
|----|-------------|-----------|----------|-------|------|--------|-------|
| FR-01 | Compute the RFC 1071 one's-complement Internet checksum, including the odd-length (final-byte) and all-zero cases, such that data plus its stored complement folds to negative zero (`0xFFFF`). | Sec. 9; RFC 1071 | MUST | in | 1 | Implemented | Hand-rolled in `wire::checksum`; pedagogical core. Basis for UDP checksum and OCS. |
| FR-02 | Represent the IPv4 header in `IpRepr` exposing addresses, transport-payload length, and the pseudo-header seed. | Sec. 7 | MUST | in | 2 | Implemented | `wire::ip::IpRepr`. IPv4 bound `UDP_Length <= Total_Length - IHL*4`. |
| FR-03 | Parse and build the 8-byte `UdpHeader`; compute the UDP checksum over pseudo-header + UDP header + user data only (not the surplus area). | Sec. 7, 9; RFC 768 | MUST | in | 2 | Implemented | `wire::udp::UdpHeader`. Kernel does not checksum raw datagrams, so this is done by hand. |
| FR-04 | Locate the surplus area: the bytes from UDP Length to the end of the IP transport payload (Sec. 7), with the OCS aligned to the first 2-byte boundary of the area relative to the IP datagram start (Sec. 8). | Sec. 7, 8 | MUST | in | 2 | Implemented | `wire::surplus::locate_surplus` -> `SurplusLayout { starts_at, needs_pad, len }`. Area existence/location is Sec. 7; the OCS 2-byte alignment is Sec. 8. |
| FR-05 | Honor the odd-pad rule: a surplus area whose natural start is odd is preceded by exactly one byte that MUST be zero; on transmit emit a zero pad, on receipt reject a non-zero pad. | Sec. 8 | MUST | in | 2,6 | Implemented | `SurplusLayout::needs_pad`; non-zero pad -> `ParseError::NonZeroPad` -> discard all options, deliver payload. The pad is validated separately; it is not part of the OCS-aligned checksum byte stream. |
| FR-06 | Classify any Kind byte into `OptionKind` (Eol/Nop/Apc/Frag/Mds/Mrds/Req/Res/Other) with correct SAFE/UNSAFE and must-support predicates. | Sec. 10 | MUST | in | 3 | Implemented | `options::kind::OptionKind`; `is_must_support` true for 0..7; UNSAFE for `kind >= model::kind::UNSAFE_MIN` (192). Exhaustive tests cover all 256 Kind byte values. |
| FR-07 | Parse the TLV stream zero-copy via `OptionsIter`/`OptionRef`, in surplus order, without panicking on any input. | Sec. 10, 14 | MUST | in | 4 | Implemented | `options::parse::OptionsIter`. Borrowed view; property tests and `options_tlv` fuzz target exhaust arbitrary bytes. |
| FR-08 | Treat EOL (Kind 0) and NOP (Kind 1) as single-byte options with no Length field. | Sec. 10, 11.1, 11.2 | MUST | in | 4 | Implemented | Parser yields EOL and NOP with empty `OptionRef.value`; EOL then terminates iteration and trailing bytes are not processed. |
| FR-09 | Decode and encode the Extended Length form when `Length == 255` (16-bit network-order Extended Length); transmitters use the default form for total lengths `<= 254` and the extended form above it. | Sec. 10 | MUST | in | 4,5 | Implemented | The serializer emits the default form for `value_len <= 252` and Extended Length for `value_len >= 253`. The parser also rejects bounded extended encodings with total length `4..=254`; that receiver disposition is a deliberate local strictness policy, not an additional literal RFC receiver MUST. |
| FR-10 | On TLV framing violations -- missing header bytes, default Length `< 2`, inherently unusable extended Length `< 4`, or a total length pointing past the end of the surplus area -- treat the surplus area as malformed and silently discard all options. | Sec. 10, 14; Erratum 8834 | MUST | in | 4 | Implemented | Parser returns exactly one `ParseError::InvalidLength` / `ParseError::Overrun` and then halts; Step 10 applies the payload-delivery disposition. The additional rejection of bounded extended encodings `4..=254` is the local strictness policy recorded in FR-09. |
| FR-11 | Silently ignore unknown or malformed SAFE options (Kind in 0..191), matching legacy behavior, except where Sec. 10 makes the length fatal to all options. | Sec. 10, 19 | MUST | in | 4,10 | Implemented | Unknown SAFE is ignored. A known SAFE Kind below its RFC minimum length discards all options, including out-of-scope assigned SAFE Kinds with known minima (TIME Len 10, EXP min Len 4); a merely over-minimum/unrecognized length is ignored option-locally. TLV framing violations discard all options (FR-10); FRAG is the exception (FR-27). |
| FR-12 | Do not treat merely unexpected Lengths of known options as fatal where the RFC forbids it (to allow future option revisions). | Sec. 10 | MUST | in | 4,7,10 | Implemented | Pipeline distinguishes "below the Kind minimum" (fatal to all options) from "unrecognized but at/above the minimum" (option-local). |
| FR-13 | Interpret options strictly in the order they occur in the surplus area (and, for fragments, in the fragment option area). | Sec. 10, 14 | MUST | in | 4,10 | Implemented | Iterator preserves order; pipeline applies first-instance rule (FR-15) in that order. For valid empty-payload FRAG datagrams, `Frag. Start` ends the fragment option area; following bytes are fragment data, not more options. |
| FR-14 | Serialize options with `OptionsBuilder`: must-support options first, NOP only for alignment, terminate with EOL, zero-fill to a 2-byte boundary, smallest format. | Sec. 8, 10, 11.1 | MUST | in | 5 | Implemented | `options::serialize`. Emits the OCS-led body with `body[0..2]` reserved for OCS, FRAG-first canonical SAFE ordering, inter-TLV NOP alignment only, EOL, and even zero-fill; known fixed-size options must use their RFC value lengths before emission, duplicate FRAG is rejected, and FRAG Start is patched from the final body length. Raw `Other` serialization is limited to unassigned SAFE `10..=126`; out-of-scope assigned/reserved SAFE Kinds are not generated. Must-support-before-other-SAFE is the Sec. 10 MUST; FRAG-first within must-support and even zero-fill are the builder canonicalization. The optional odd-start pad is wire/send-layer work. |
| FR-15 | Enforce the once-per-datagram rule: for options other than FRAG, NOP, EXP, UEXP, interpret only the first instance and ignore later ones. | Sec. 10 | MUST | in | 10 | Implemented | Pipeline tracks seen Kinds; in scope this affects APC/MDS/MRDS/REQ/RES. Later duplicates are ignored only after their Length is checked against the Kind minimum. Duplicate FRAG is malformed per FR-29. |
| FR-16 | Limit consecutive NOPs: do not emit more than seven; on receipt, log persistently excessive NOP runs as a possible DoS. | Sec. 11.2, 25 | SHOULD | in | 5,10 | Implemented | Step 5 emits at most one inter-option NOP at a time and never uses NOP as tail fill. Step 10 logs receive-side NOP runs above `NOP_RUN_DOS_THRESHOLD`; receive-path warn diagnostics are globally sampled to avoid log flooding. |
| FR-17 | Require the last non-NOP option to be EOL when options do not fill the area, and set all bytes after EOL to zero on transmit. | Sec. 11.1 | MUST | in | 5 | Implemented | Builder always closes with EOL + zero-fill; prevents side-channel use of the tail. |
| FR-18 | Optionally check that post-EOL bytes are zero on receipt; if checked and non-zero, discard the options but still deliver the payload. | Sec. 11.1 | MAY | in | 10 | Not selected | The receiver stops at EOL and does not inspect the tail. Transmit always zero-fills. No configuration switch is claimed because this optional receive check was consciously not selected. |
| FR-19 | Compute the OCS as a 16-bit Internet checksum over the OCS-aligned bytes from the OCS field through the end of the surplus area (OCS field taken as zero), plus the full surplus length including any pre-OCS pad as a 16-bit value; validation folds to negative zero (`0xFFFF`). | Sec. 8, 9 | MUST | in | 6 | Implemented | `options::ocs`; two-pass back-patch (reserve OCS, then patch); a computed `0x0000` is sent as `0xFFFF`. The separately zero-validated odd-start pad precedes this checksum byte stream but remains part of the length addend. |
| FR-20 | Validate the OCS on receipt: if `OCS != 0` and the sum does not verify, ignore all options and silently discard the surplus area (still deliver the payload). | Sec. 9, 14 | MUST | in | 6,10 | Implemented | `ParseError::OcsMismatch` maps to payload delivery with no options. |
| FR-21 | Default to a non-zero OCS whenever the UDP checksum is non-zero; permit a zero OCS only when the UDP checksum is also zero. | Sec. 9 | MUST | in | 6,10 | Implemented | Send path defaults OCS on. The `OCS == 0` with non-zero UDP checksum case is handled by the Step 10 receive disposition. |
| FR-22 | Implement APC (Kind 2, Len 6): a CRC32C over the UDP user data only; encode/decode and verify it. | Sec. 11.3 | MUST | in | 7,13 | Implemented | `options::typed::Apc { crc32c }` encodes/decodes Len 6 and computes CRC32C with the `crc32c` crate, validated against `123456789 -> 0xe3069283`; the receive pipeline reports datagram-level APC success/failure through `OptionReport`. |
| FR-23 | On an incorrect or unrecognized-length APC, default to delivering the payload with an APC-failure indication, ignoring the option (do not drop), unless explicitly configured otherwise. | Sec. 11.3, 14, 19 | MUST/SHOULD | in | 7,10,13 | Implemented | Incorrect or unrecognized-length APC is ignored as an option, the payload is still delivered, and datagram-level `OptionStatus::Failed` is exposed through the API. Required-option policy can override delivery by filtering datagrams without a successful APC. APC is per-datagram only; fragment-local APC is treated like an unusable SAFE per-fragment option and is not surfaced as `FragmentSet` status. |
| FR-24 | Implement MDS (Kind 4, Len 4) and MRDS (Kind 5, Len 5): 16-bit size, and for MRDS an 8-bit segment count; encode/decode and report to the user. | Sec. 11.5, 11.6 | MUST | in | 7,13 | Implemented | `typed::Mds` and `typed::Mrds` encode/decode the fixed wire values and are surfaced as successful `RawOption`s plus `OptionReport`s. MDS remains a hint and is not used as a hard send rejection condition. |
| FR-25 | Implement REQ (Kind 6, Len 6) and RES (Kind 7, Len 6): a 4-byte opaque token; encode/decode and deliver to the user; never auto-respond. A transmitted RES token MUST previously have been received by that transmitter in REQ. | Sec. 11.7 | MUST | in | 7,13 | Delegated | `typed::Req` and `typed::Res` implement the wire format and are passed through. No automatic REQ/RES layer is built. Because callers can construct `Res` directly, they MUST enforce token provenance; the library and CLI do not attest that an arbitrary RES token came from an earlier REQ. |
| FR-26 | Implement the FRAG option (Kind 3): non-terminal Len 10 (Frag Start, Identification, Frag Offset) and terminal Len 12 (adds RDOS). | Sec. 11.4 | MUST | in | 7,10,11,12 | Implemented | `typed::Frag { frag_start, identification, frag_offset, rdos }` encodes/decodes both value layouts; `rdos: Some(..)` marks terminal. Step 10 uses `Frag. Start` to stop option parsing before fragment data. Step 11 emits non-terminal and terminal FRAG bodies for send-side fragmentation; Step 12 reassembles them on receive. |
| FR-27 | Treat an unsupported FRAG format as an unsupported UNSAFE option (not as an ignorable SAFE option), after applying the generic Sec. 10 below-minimum Length rule. | Sec. 10, 11.4 | MUST | in | 10,12 | Implemented | A FRAG Length below 10 is malformed surplus, so all options are discarded and the UDP user data is delivered. For empty UDP user data, an otherwise unsupported FRAG format follows the UNSAFE disposition. If a correctly framed FRAG is present with non-empty UDP user data, FR-28 is controlling: ignore all options and deliver the original data; `Frag. Start` is not trusted as a reassembly boundary in that branch. |
| FR-28 | Require empty UDP user data (UDP Length 8) whenever a valid FRAG is present; if user data is non-empty, ignore all options and deliver the received user data. | Sec. 11.4 | MUST | in | 10,11 | Implemented | Send path always emits FRAG with empty user data; receive path applies the non-empty-data exception only to valid FRAG, not malformed FRAG. |
| FR-29 | If FRAG occurs more than once in a datagram, treat the options area as malformed and do not process it. | Sec. 10 | MUST | in | 10 | Implemented | Pipeline reports `ParseError::DuplicateFrag` for duplicate FRAG outside a valid empty-fragment context. Inside a valid empty-payload fragment option area, duplicate FRAG drops the fragment without user delivery. Bytes at or after `Frag. Start` are fragment data and are not parsed as duplicate options. |
| FR-30 | Fully prepare the original option-bearing datagram, zero its original UDP checksum (SHOULD) and, when every fragment uses non-zero OCS, its original OCS (SHOULD), then split it into non-terminal/terminal FRAG fragments or the atomic single-fragment case, sized to respect MDS/MRDS. | Sec. 11.4 | MUST/SHOULD | in | 11 | Implemented | `OptionsBuilder` prepares the original OCS-led body before `frag::split::split_datagram` consumes it; the original checksums are represented as zero placeholders and each emitted fragment receives its own finalized UDP checksum and OCS in the send layer. Fragment bodies use empty UDP data, S-12/S-14 accounting, terminal RDOS, and UDP-header-relative offsets. |
| FR-31 | Reassemble fragments (receive) keyed by `FragKey` (src IP, dst IP, src port, dst port, Identification); offset-sort; deliver only the complete datagram. | Sec. 11.4 | MUST | in | 12 | Implemented | `ReassemblyCache::insert(key, frag, data, now)` stores offset-sorted tail segments and returns `Complete { tail, udp_length, fragment_options, fragment_option_failures, fragment_ocs_nonzero }` only after gap-free terminal coverage; the pipeline's richer insertion path coalesces validated per-fragment SAFE options and OCS state. Individual fragments return `Delivery::Buffered`, not user data. |
| FR-32 | Abort reassembly on any fragment overlap, discarding all fragments of that datagram, with no ICMP error. | Sec. 11.4 | MUST | in | 12 | Implemented | `ReassemblyOutcome::Abort(AbortReason::Overlap)` discards the partial; byte-identical fragments with identical per-fragment options are treated as no-op packet duplicates, while differing duplicate ranges, differing per-fragment options, and partial overlaps abort. |
| FR-33 | Use a default reassembly timeout of at most 2 minutes, generating no ICMP error and no zero-length frame to the user on expiry. | Sec. 11.4 | SHOULD/MUST | in | 12 | Implemented | `model::limits::REASSEMBLY_TIMEOUT_MAX = 120s`; configured values are clamped to that default maximum and expiry occurs at `elapsed >= timeout`. `insert()` runs GC first and callers may also call `gc(now)`; without either call, stale storage is not reclaimed in the background. Expiry creates no user delivery or ICMP. |
| FR-34 | Limit reassembly resources per socket pair rather than sharing the resource budget across pairs; abort on exceedance. | Sec. 11.4, 25.4 | SHOULD | in | 12 | Implemented | `Peer` owns one `ReassemblyCache` per socket pair. Low-level callers MUST preserve that ownership rule and not share a cache across pairs because `max_pending_partials` applies to the whole cache. Per-datagram size/segment caps and the per-cache pending cap return `LimitExceeded` without evicting unrelated keys. |
| FR-35 | Support a local MRDS size of at least 2926 (IPv4) bytes and at least 2 segments; assume these as defaults when no MRDS option was received. | Sec. 11.4, 11.6 | MUST | in | 11,12 | Implemented | `model::limits::{MRDS_DEFAULT_IPV4, MIN_REASSEMBLY_SEGMENTS=2}` and `PeerFragmentLimits::default_ipv4()` cover the send-side default; `ReassemblyLimits::default()` applies the same receive-side defaults. |
| FR-36 | Apply the RFC 9868 Sec. 14 receive disposition exactly (UDP checksum -> OCS x checksum matrix -> option processing -> deliver/discard), implemented as a pure function. | Sec. 9, 14 | MUST | in | 10 | Implemented | `recv::pipeline::process_datagram` -> `Delivery::{Payload{data,options}, Buffered, Dropped}`. Owns the `OCS == 0` with non-zero UDP checksum case (legacy emulation). See the disposition table below. |
| FR-37 | Make per-packet options and their success/fail status available to the user, except FRAG, NOP, EOL (handled internally). | Sec. 14, 15 | MUST | in | 10,12,13,18 | Implemented | `RawOption`/`OptionReport` surface TLV options. OCS, which has no Kind byte, is exposed separately as `OcsReport { status: OcsStatus, source }` for datagrams and fragment sets; statuses distinguish absent, valid, unused, failed, invalid-zero, and (for fragment sets fed through the public cache-insertion methods) unobserved OCS. Fragment-set reports are coalesced/failure-dominant; FRAG/NOP/EOL remain internal. |
| FR-38 | Deliver the UDP user data by default for all SAFE options regardless of whether options are supported, present, or succeed (legacy equivalence), unless explicitly overridden. | Sec. 6, 14, 19 | MUST | in | 10,13 | Implemented | Step 10's default path delivers data for SAFE option success/failure; Step 13 adds receive-policy overrides for required options and drop-all-option-bearing sockets. |
| FR-39 | Terminate option processing at the first unsupported UNSAFE Kind. Outside an already established valid empty-FRAG context, discard the options and deliver zero-length user data; a fragment-local failure after a trusted FRAG discards the fragment/reassembly set without a user frame. | Sec. 10, 12, 14 | MUST | in | 10,12,18 | Implemented | Bytes after the first unsupported UNSAFE are not scanned for a later FRAG and cannot select a cache key. Only a FRAG fully recognized before the failure establishes fragment-local `Delivery::Dropped`; ordinary and post-reassembly UNSAFE follow the legacy-compatible zero-length disposition. |
| FR-40 | Build and transmit option-bearing datagrams via a raw `IP_HDRINCL` socket so that `UDP Length < IPv4 Total Length - IPv4 IHL*4` on the wire (the surplus area exists). | Sec. 7; locked decision | MUST | in | 8 | Partial-in-userspace | `socket::send`. Total Length set explicitly; IP checksum and possibly Identification are filled by the kernel (see limitations). Empty option sets emit a plain UDP datagram with no surplus area. Linux + CAP_NET_RAW only. |
| FR-41 | Receive full IP datagrams with the surplus area intact via a raw `SOCK_RAW`/`IPPROTO_UDP` socket; filter by destination port in userspace; avoid spurious ICMP. | Sec. 7; locked decision | MUST | in | 8 | Partial-in-userspace | `socket::recv`. Bind a dummy `SOCK_DGRAM` to absorb ICMP port-unreachable; drop own-source copies. Linux + CAP_NET_RAW only; no macOS recv path. Step 9 was merged into Step 8 so send/receive are validated as one root-gated socket round trip. |
| FR-42 | Provide a low-level project API to set and read explicit per-datagram options. | Sec. 15 subset; project API | project MUST | in | 13 | Implemented | `api::build_datagram()` builds explicit `RawOption` datagrams via the serializer and raw assembler; an empty explicit option list emits a plain UDP datagram. `api::decode_datagram()` returns payload, successful options, and status reports. Low-level send guards compare canonical wire Kind bytes, so `OptionKind::Other(3)` cannot bypass FRAG's empty-user-data rule. This bounded project API is not claimed as the complete Sec. 15 surface: it has no separate per-fragment placement list, caller-selected minimum datagram length, or omitted/per-source receive policy. |
| FR-43 | Provide a high-level project API that applies the OCS and FRAG fragmentation/reassembly transparently (a send too large for a single datagram auto-fragments, capped by the peer's MRDS; recv reassembles). | Sec. 15 subset; project design | project SHOULD | in | 13 | Implemented | `api::build_outgoing_datagrams()` and `api::Peer` compose serializer, raw sockets, FRAG split/reassembly, and receive policy. Fragmentation is triggered by configured single-datagram capacity, never MRDS; over-MRDS sends fail with `SendError::Split`. Empty `SendOptions` do not add an empty OCS/EOL body, preserving the default IPv4 MRDS payload capacity. Raw FRAG aliases are rejected, raw APC aliases cannot be combined with automatic APC, and duplicate high-level APC/MDS/MRDS/REQ/RES Kinds are rejected. This project abstraction does not complete the broader descriptive Sec. 15 send form. |
| FR-44 | Offer per-socket-pair receive policy for named per-datagram and per-fragment options that are required or omitted, including drop + log for missing/failed requirements, plus a setting to discard all option-bearing datagrams that defaults to normal processing. | Sec. 15 | MUST | in | 13,18 | Partially implemented | `ReceivePolicy` can require successful APC/MDS/MRDS/REQ/RES or an acceptable OCS without distinguishing `Datagram` from `FragmentSet`, and implements default-off `drop_all_option_bearing`; policy drops are sampled-logged. Tails too short for the aligned OCS are delivered without options unless OCS is required. Named omission and independently scoped datagram/fragment-set policies remain unimplemented. |
| FR-45 | Do not expose user control over option order or per-packet fragment boundaries; do allow enabling/disabling options (incl. fragmentation) per packet. | Sec. 15 (API guidance, non-normative); Sec. 25 (rationale) | guidance | in | 13 | Implemented | `SendOptions` selects options/APC and `SendConfig::fragmentation` enables/disables FRAG; option ordering and fragment boundaries remain controlled by `OptionsBuilder` and `split_datagram`. |
| FR-46 | Provide example peer CLIs `udpopt-send` and `udpopt-recv` with working `--help` and a documented loopback run that sends options and prints them decoded. | Sec. 15 (API illustration); ROADMAP | SHOULD | in | 14 | Implemented | `src/bin/udpopt-send.rs`, `src/bin/udpopt-recv.rs` (`clap`). Privileged (CAP_NET_RAW). |
| FR-48 | Never emit an ICMP error from UDP-options processing (reassembly expiry, overlap abort, length-invalid drops). | Sec. 10, 11.4 | MUST | in | 8,10,12 | Partially implemented | Userspace raw path emits no ICMP by construction; Step 10 is pure and emits no network side effects. Step 12 covers reassembly expiry/overlap. |
| FR-49 | Validate UDP Length bounds: at least 8 and no larger than the IP transport payload; silently drop (and log) datagrams outside this range. | Sec. 10 | MUST | in | 2,10,18 | Implemented | `process_datagram` sampled-logs upper-bound failures; the raw receive demultiplexer sampled-logs the `< 8` parse failure before discarding it, so both end-to-end paths satisfy the logging requirement. |
| FR-50 | When an option's claimed length overruns the surplus option area, treat the area as malformed and silently discard all options rather than ignoring only that option. | Sec. 10; Erratum 8834 (Verified, Technical) | MUST | in | 4,10,18 | Implemented | Erratum 8834 replaces the obsolete Sec. 14 sentence with a reference to Sec. 10. Parser overrun is terminal for the option area; normal UDP payload remains deliverable, while fragment-local parse failure discards the fragment set. |

### Receive disposition (FR-36, RFC 9868 Sec. 14)

| UDP checksum | OCS | Disposition |
|--------------|-----|-------------|
| fails | any | Silently drop the entire datagram (RFC 1122). Nothing delivered. |
| passes or zero | `OCS != 0` and OCS passes | Deliver the user data after parsing and processing all options (regardless of per-option support/success). |
| passes or zero | `OCS == 0` and UDP checksum `== 0` | Deliver the user data after parsing and processing all options (OCS treated as "correct"). |
| passes or zero | `OCS != 0` and OCS fails | Deliver the user data but ignore all other options (legacy emulation). |
| passes or zero | `OCS == 0` and UDP checksum `!= 0` | Deliver the user data but ignore all other options (legacy emulation; FR-36's flag case). |

### RFC Editor errata incorporated

- [Erratum 8834](https://www.rfc-editor.org/errata/eid8834) is **Verified / Technical**. It removes
  the obsolete Sec. 14 advice to ignore only an option that overruns the packet and points to the
  Sec. 10 malformed-area rule instead. FR-10, FR-50, and the matrix below use that corrected rule.
- [Erratum 8708](https://www.rfc-editor.org/errata/eid8708) is **Held for Document Update /
  Editorial**. Figure 11 is the terminal FRAG form; this repository consistently uses Length 12 for
  terminal and Length 10 for non-terminal FRAG.

## 2. Non-functional requirements

| ID | Requirement | RFC source / rationale | Priority | Step | Status | Notes |
|----|-------------|------------------------|----------|------|--------|-------|
| NFR-01 | Memory safety: confine all `unsafe` to `src/socket/` behind safe wrappers; the crate sets `#![deny(unsafe_op_in_unsafe_fn)]`. | Sec. 25.3 (buffer-overflow risk from IP/UDP length mismatch); Rust | MUST | 0,8 | Implemented | Parser/pipeline/options/frag are fully safe Rust; only raw `libc`/`socket2` calls are `unsafe`. |
| NFR-02 | No-panic parsing: the TLV parser and the receive pipeline are total functions that never panic on arbitrary input. | Sec. 25.3 | MUST | 4,10 | Implemented | Verified with property tests and fuzz targets; malformed input yields typed errors/dispositions, never an abort. |
| NFR-03 | Zero-copy parse: parsing borrows the surplus bytes (`OptionRef<'a>`/`OptionsIter<'a>`); owned values (`RawOption`, typed options) are produced only at decode time, and the borrow never crosses the public API. | "parse borrowed, decode owned" design rule | MUST | 4,7,13 | Implemented | Parser output borrows with `OptionRef<'a>`, while API results expose only owned `ReceivedDatagram`, `RawOption`, and `OptionReport` values. |
| NFR-04 | DoS resistance, option count: bound the number of non-padding TLVs processed per datagram and drop/log beyond it. | Sec. 25.3 | conditional SHOULD | 10 | Not selected | This implementation does not impose a TLV-count cap. The zero-copy parser is bounded by the IPv4 datagram length, allocates nothing while scanning, and already terminates on malformed framing/UNSAFE plus sampled-logs excessive NOPs. A fixed global cap could reject valid extensible option sets; an adaptive policy remains a possible deployment-layer hardening, not a claimed endpoint invariant. |
| NFR-05 | DoS resistance, NOP runs: detect runs of more than seven NOPs and limit the work they cause; log occurrences. | Sec. 11.2, 25.2 | SHOULD | 10 | Partially implemented | Runs above `NOP_RUN_DOS_THRESHOLD` are detected and sampled-logged. Parsing remains linear through the bounded datagram and is not stopped solely because the run exceeded seven; therefore the work-limiting half is not claimed. |
| NFR-06 | DoS resistance, reassembly: per-pair (non-shared) and per-cache caps, a default timeout `<= 2 min`, garbage collection of stale partials, and overlap-abort. | Sec. 11.4, 25.4 | SHOULD | 12 | Implemented | Implements FR-32..FR-34; `Peer` owns one cache per pair and low-level callers have the same ownership precondition. GC is caller-driven and expiry is enforced on insertion; there is no background thread. |
| NFR-07 | Platform/privilege: raw-socket paths run only on Linux and require `CAP_NET_RAW` (or root); the library and binaries still compile on any platform. | Locked decision; Linux capabilities | MUST | 8,15 | Partial-in-userspace | `SocketError::PermissionDenied` covers missing capability; pure modules and API datagram builders need no privilege. |
| NFR-08 | Rate-limited logging: all diagnostic logging (DoS indicators, dropped datagrams, required-option failures) is rate limited and may be coalesced to a count. | Sec. 10, 25.1 | SHOULD | 10,12,13 | Implemented | Pipeline diagnostics and Step 13 receive-policy drops use sampled `log` warnings so diagnostics do not become a resource sink. |
| NFR-09 | Reproducible tests: a root-free functional lane (`cargo test`) and a root-gated, `#[ignore]`-d integration lane (on Linux `sudo cargo test -- --ignored`; from macOS `scripts/vm-ubuntu-server.sh ignored` against a configurable SSH Linux host) that is skipped, not failed, without privilege. | ROADMAP verification | MUST | 10,15,17 | Implemented | Pure pipeline is fully unit-testable; loopback/netns tests are gated so a green run stays trustworthy; on any Linux box the lanes run natively without the cross-compile setup. |
| NFR-10 | Performance/overhead observability: make the surplus-area overhead measurable on the wire and provide a reproducible evaluation runbook for FF2. | FF2; ROADMAP Step 17 | SHOULD | 10.5,17 | Partially implemented | The independent wire lane validates endpoint wire images. Step 17 provides controlled local namespace/veth, routed, Linux NAT, and negative filter paths. It does not provide tunnel scripts, intentionally surplus-modifying middleboxes, or measurements over real external paths; those are required before FF2 can be called answered. |
| NFR-11 | Code style and hygiene: `rustfmt` at `max_width = 120`, clean `clippy -D warnings`, and hand-rolled checksum/TLV/OCS (no `nom`, `pnet`, `etherparse`, `smoltcp`, `bytes`, `nix`, `zerocopy`). | ROADMAP conventions | MUST | all | Implemented | The hand-rolled primitives are the pedagogical core of the thesis. |
| NFR-12 | Determinism / no hidden state: the receive pipeline is a pure function over byte buffers; all mutable state (reassembly cache) is explicit and isolated from I/O. | "pure pipeline vs privileged I/O" rule | MUST | 10,12 | Implemented | `process_datagram` takes bytes, an explicit `ReassemblyCache`, and a caller-provided `Instant`; no socket, thread, async task, or hidden wall-clock access is used. |

## 3. RFC 9868 conformance matrix (endpoint-relevant normative items)

"Covered" is relative to the in-scope deliverable. Out-of-scope rows are marked `out` and map to the explicit
scope exclusions.

| RFC area | Normative item | Level | Covered | Step | Notes |
|----------|----------------|-------|---------|------|-------|
| Sec. 10 | UDP Length in `[8, IP transport payload]`; else drop + log | MUST | yes | 2,10 | FR-49. |
| Sec. 7 | Surplus area exists/located as the IP-payload tail after UDP Length | MUST | yes | 2 | FR-04 (location); alignment is Sec. 8. |
| Sec. 8 | Options use the entire surplus area; OCS aligned to the first 2-byte boundary; any preceding pad is separately zero-validated | MUST | yes | 2,6 | FR-04, FR-05, FR-19. The OCS word stream begins at the aligned OCS; full surplus length still includes the pad. |
| Sec. 8 | Pre-OCS alignment pad byte MUST be zero; else ignore all + discard surplus | MUST | yes | 2,6 | FR-05. |
| Sec. 9 | OCS = Internet checksum from aligned OCS through surplus end + 16-bit full surplus length | MUST | yes | 6 | FR-19; the pre-OCS zero pad is not prepended to the checksum word stream. |
| Sec. 9 | OCS non-zero when UDP checksum non-zero | MUST | yes | 6 | FR-21. |
| Sec. 9 | Default to using a non-zero OCS | MUST | yes | 6 | FR-21 (send default). |
| Sec. 9 | OCS validation failure -> ignore all options, discard surplus | MUST | yes | 6,10 | FR-20. |
| Sec. 9 / 14 | UDP-checksum-valid data delivered by default even if OCS fails | MUST | yes | 10 | FR-38, disposition table. |
| Sec. 10 | TLV framing; `Length` total incl. Kind+Length; `255` -> extended | MUST | yes | 4,5 | FR-07, FR-09. |
| Sec. 10 | NOP/EOL never use a Length form | MUST | yes | 4 | FR-08. |
| Sec. 10 | TLV framing length below the format minimum -> error -> discard all options | MUST | yes | 4 | FR-10. |
| Sec. 10 | Underrun/overrun lengths -> malformed surplus -> discard all | MUST | yes | 4,10,18 | FR-10/FR-50; Erratum 8834 removes the obsolete Sec. 14 ignore-only wording. |
| Sec. 10 | Known option Length below its Kind minimum -> error -> discard all options | MUST | yes | 10 | FR-11/FR-12; includes duplicate known options and out-of-scope assigned SAFE options with known minima (TIME/EXP). |
| Sec. 10 | Options >254 use extended format; options <=254 use default format; smallest format SHOULD | MUST/SHOULD | yes (send); local strict receive | 4,5 | FR-09, FR-14. Rejecting a bounded extended encoding `4..=254` on receive is an explicit local strictness policy. |
| Sec. 10 / 14 | Process options in surplus order | MUST | yes | 4,10 | FR-13. |
| Sec. 10 | Support all must-support options (EOL, NOP, APC, FRAG, MDS, MRDS, REQ, RES), recognize and generate | MUST | yes | 3,5,7,11,12 | FR-06, FR-14, FR-22..FR-26, FR-30, FR-31. |
| Sec. 10 | Silently ignore unknown SAFE and known SAFE lengths that are unrecognized but not below-minimum | MUST | yes | 4,10 | FR-11/FR-12. |
| Sec. 10 | Malformed FRAG -> treated as unsupported UNSAFE | MUST | yes | 10,12 | FR-27. |
| Sec. 10 | Non-FRAG/NOP/EXP/UEXP options at most once; first wins | SHOULD/MUST | yes | 10 | FR-15. |
| Sec. 10 | NOP MAY repeat (alignment) | MAY | yes | 5 | FR-16 limits runs to 7. |
| Sec. 10 | FRAG more than once -> options area malformed | MUST | yes | 10 | FR-29. |
| Sec. 10 | UNSAFE present -> user data empty and payload inside FRAG | MUST | yes (by construction) | 10,11 | No UNSAFE option is generated; on receive, unsupported UNSAFE outside a valid FRAG context drops data (FR-39). |
| Sec. 10 | Unsupported UNSAFE -> terminate processing immediately, drop all options | MUST | yes | 10,12,18 | FR-39; no later bytes are scanned for FRAG. Only an already trusted FRAG establishes fragment-local no-delivery handling. |
| Sec. 10 | Must-support options (except NOP/EOL) placed before other SAFE options; receiver MAY drop if not | MUST/MAY | yes | 5 (send), 10 (recv MAY) | FR-14 emits must-support-first; receiver-side reordering tolerance is the MAY. |
| Sec. 11.1 | Last non-NOP option is EOL when area not filled; post-EOL bytes zero on transmit | MUST | yes | 5 | FR-17. |
| Sec. 11.1 | Post-EOL non-zero (if checked) -> discard options, deliver data | MUST (conditional) / MAY check | not selected | 10 | FR-18; transmit zero-fill is implemented, optional receive-tail checking is not. |
| Sec. 11.2 | <= 7 consecutive NOPs; log excessive runs and limit resources | SHOULD | partial | 5,10 | FR-16, NFR-05; detection/logging exists, run-triggered early termination does not. |
| Sec. 11.3 | APC = CRC32C over user data; failure -> deliver with indication | MUST/SHOULD | yes | 7 | FR-22, FR-23. |
| Sec. 11.3 | Unrecognized APC length treated like a failed APC | MUST | yes | 7,10 | FR-12, FR-23. |
| Sec. 11.4 | FRAG non-terminal Len 10 / terminal Len 12 (RDOS) | MUST | yes | 7,11 | FR-26. |
| Sec. 11.4 | FRAG present -> user data empty | MUST | yes | 10,11 | FR-28. |
| Sec. 11.4 | Reassemble >= 2 fragments fitting a 1500-byte MTU | MUST | yes | 11,12 | FR-35. |
| Sec. 11.4 | Identification unique over reassembly timeout; IPv6-style generation | MUST/SHOULD | yes | 11 | Send-side ID generation; key includes Identification (FR-31). |
| Sec. 11.4 | Fragments MUST NOT overlap; overlap -> abort + discard, no ICMP | MUST | yes | 12 | FR-32, FR-48. |
| Sec. 11.4 | Duplicate fragments MAY be dropped instead of treated as overlap | MAY | yes | 12 | FR-32 notes. |
| Sec. 11.4 | Reassembly timeout default `<= 2 min`; no ICMP on expiry | SHOULD/MUST | yes | 12 | FR-33. |
| Sec. 11.4 | Reassembly space limited; not shared across pairs | SHOULD | yes | 12 | FR-34, NFR-06. |
| Sec. 11.4 | Individual fragments MUST NOT be forwarded to the user | MUST | yes | 12 | FR-31. |
| Sec. 11.4 | Reassembly failure -> no zero-length frame to the user | SHOULD | yes | 10,12 | FR-33; Step 10 uses `Delivery::Dropped` for fragment-local failures that must not reach the user. |
| Sec. 11.5 | MDS encode/decode; MDS MUST NOT limit transmission | MUST | yes | 7 | FR-24. |
| Sec. 11.6 | MRDS size >= 2926, segs >= 2; defaults when absent | MUST | yes (IPv4; IPv6 out of scope) | 7,11,12 | FR-35. |
| Sec. 11.7 | REQ/RES wire handling; never auto-respond; RES token came from a received REQ | MUST | delegated | 7,13 | FR-25; pass-through is implemented and token provenance is an explicit upper-layer caller precondition. |
| Sec. 11.7 | Auto REQ/RES layer (if any) disabled by default | MUST | yes (vacuous) | 13 | No such layer is built; RFC 9869 use case is out of scope. |
| Sec. 11.8 | TIME option | MUST (when implemented) | out | - | Out of scope. |
| Sec. 11.9 | AUTH option (RESERVED) | reserved | out | - | Out of scope; reserved Kind 9 not generated, unknown SAFE on receive (FR-11). |
| Sec. 11.10 | EXP option (16-bit ExID; minimum option length 4) | MUST (when implemented) | out | - | Not generated; on receive carried as `Other`/ignored. |
| Sec. 12 | UNSAFE options (UCMP/UENC/UEXP) | reserved | out | - | Out of scope; any UNSAFE Kind on receive triggers FR-39. |
| Sec. 12 | UNSAFE only inside fragments; unsupported UNSAFE -> drop data | MUST | yes (drop side) | 10 | FR-39 covers the receiver obligation. |
| Sec. 13 | New-option design rules | MUST | n/a | - | No new options are defined by this implementation. |
| Sec. 14 | Receive disposition order (checksum -> OCS -> options -> deliver) | MUST | yes | 10 | FR-36 + disposition table. |
| Sec. 14 | All must-support options processed if present | MUST | yes | 10 | FR-06, FR-36. |
| Sec. 14 | Non-must-support options MAY be ignored | MAY | yes | 10 | Configurable. |
| Sec. 14 | Default-deliver data for all SAFE options regardless of success | MUST | yes | 10 | FR-38. |
| Sec. 14 | FRAG/NOP/EOL not passed to the user; other option status available | MUST | yes | 10,13,18 | FR-37 includes separate OCS status. |
| Sec. 14 + Erratum 8834 | Option overrun follows Sec. 10 malformed-area handling | MUST | yes | 4,10,18 | FR-50. |
| Sec. 15 | Receive API: per-packet/per-fragment required-or-omitted options | MUST | partial | 13,18 | Required TLV options and OCS are covered; omitted/per-fragment policy remains coalesced rather than a complete per-fragment control surface. |
| Sec. 15 | Required option absent -> silently drop + log | MUST | partial | 13 | FR-44; implemented source-agnostically for a successful datagram-level or coalesced FragmentSet option, but the application cannot require it independently at one source level. |
| Sec. 15 | "Drop all option-bearing datagrams" setting; default = process | MUST | yes | 13 | FR-44; the pre-buffer filter still observes UDP checksum validation first. |
| Sec. 15 | Options + status (except FRAG/NOP/EOL) available to the user | MUST | yes | 10,13,18 | FR-37; OCS uses `OcsReport`, TLVs use `OptionReport`, and fragment-set status is coalesced as Sec. 15 permits. |
| Sec. 15 | Send API selects options/fragment scope and supports minimum-length EOL zero-fill | descriptive API form | partial | 5,13 | Option selection and canonical EOL/zero-fill are implemented; separate per-fragment option lists and caller-selected minimum datagram length are not exposed. This bullet has no BCP-14 keyword. |
| Sec. 15 / 25 | No user control over option order or per-packet fragment boundaries | guidance ("not intended") | yes | 13 | FR-45 (Sec. 15 API guidance, no BCP-14 MUST; enforced as project canonicalization). |
| Sec. 16 / 19 | Options MUST NOT be altered in transit; SAFE options ignored on failure; data still delivered | MUST | yes (endpoint side) | 10 | Endpoint never alters options in flight; FR-38. In-transit integrity itself is an FF2 measurement, not enforceable by an endpoint. |
| Sec. 25.2/.3/.4 | DoS limits on options, NOP runs, reassembly; rate-limited logging | SHOULD | partial / documented opt-out | 10,12 | NFR-04 is a reasoned opt-out; NFR-05 is partial; NFR-06/NFR-08 are implemented. |
| Sec. 25 | Return options in a reference order (anti-covert-channel) | SHOULD | partial | 10,13 | Send order is canonical (FR-14); receive-side reordering of reported options is optional and not the default. |
| Sec. 23 | Multicast/broadcast considerations | special | out | - | Unicast only; not exercised. |
| Sec. 26 | SAFE names avoid "U"; UNSAFE names start "U" | MUST | n/a | - | No new Kinds registered. |

## 4. Userspace / raw-socket limitations (input to FF1)

This section records where the userspace + raw-socket constraint changes, weakens, or blocks an RFC requirement.
These are the concrete answers FF1 collects.

**L1 - IP header field fill under `IP_HDRINCL` (FR-40).** With `IP_HDRINCL` the application supplies the IPv4
header, but the Linux kernel still fills the IPv4 header checksum and may overwrite the Identification field (and
will set Total Length if it is left zero). The implementation therefore sets Total Length explicitly and asserts
`UDP Length < Total Length - IHL*4` on the wire (ROADMAP Step 8). Consequence: the FRAG Identification carried in the
surplus area is fully under our control (it lives in the UDP option area, not the IP header), but we cannot
guarantee a specific IPv4 ID; this does not affect conformance because FRAG keying uses the option Identification,
not the IP ID. Status of FR-40: Partial-in-userspace (works, with kernel-owned IP fields).

**L2 - No UDP checksum offload; checksum done by hand (FR-03, FR-19).** A raw socket does not compute the UDP
checksum, and there is no path to NIC checksum offload for these datagrams. The crate computes both the UDP
checksum and the OCS itself (FR-01, FR-03, FR-19). This is a correctness requirement here, not a limitation per se,
but it means the implementation cannot lean on hardware and that performance (NFR-10) reflects pure-software
checksumming. On loopback and some NICs, offload can also rewrite or defer checksums; the evaluation disables
offload (`ethtool -K`) so captures show the real bytes.

**L3 - Surplus stripping and option dropping by middleboxes (FF2; Sec. 18, 25.6).** Endpoints cannot prevent a
NAT, relay, or filter from resetting IP Length to UDP Length (truncating the surplus area) or dropping
option-bearing datagrams; [Zu20] reports paths where this happens. The OCS protects only against accidental reuse
of the area and lets datagrams traverse middleboxes that wrongly checksum the whole IP payload (Sec. 9); it does
not stop deliberate stripping. The implementation's response is to fall back to legacy behavior (SAFE options
absent -> payload still delivered; UNSAFE-bearing payload -> lost, since it lived in the stripped FRAG area). This
is squarely the FF2 measurement target. Step 17 currently stages controlled namespace/veth, routed, Linux NAT,
and negative filter paths; tunnel behavior is documented only as an encapsulation control, and real external paths
remain future empirical work. No endpoint code can make a stripping path conformant.

**L4 - Privilege requirement, `CAP_NET_RAW` / root (FR-40, FR-41, FR-46; NFR-07).** Both raw sockets require
`CAP_NET_RAW`. This is not an RFC requirement but it constrains who can run an RFC 9868 endpoint in userspace: an
unprivileged process cannot open the surplus area at all. The design quarantines this to `src/socket/` and the CLIs
so the entire parser/serializer/OCS/FRAG/pipeline is testable unprivileged (NFR-09); `SocketError::PermissionDenied`
is the explicit socket failure mode.

**L5 - Raw-recv noise: duplicates and ICMP (FR-41, FR-48).** A `SOCK_RAW`/`IPPROTO_UDP` socket receives a copy of
every UDP datagram (including our own sends and datagrams for other ports) and, because no normal socket is bound
to the target port, the kernel would emit ICMP port-unreachable. The implementation filters by destination port
and own-source in userspace and binds a dummy `SOCK_DGRAM` to absorb the ICMP, satisfying the RFC's
no-ICMP-from-options-processing posture (FR-48). The residual risk is that this is a heuristic at the edge of the
kernel's behavior, not a kernel-enforced demux; that caveat is what makes FR-41 Partial-in-userspace.

**L7 - macOS receive is impossible.** macOS raw sockets cannot receive UDP at all, which is why the project is
Linux-only at runtime. This bounds the portability of any userspace RFC 9868 endpoint and is recorded as a hard
FF1 finding (Not-feasible on macOS), independent of the Linux Partial-in-userspace statuses above.

**L8 - Per-fragment status is deliberately coalesced (Sec. 15).** The RFC permits per-fragment option status to
default to "not computed / not passed up" unless requested and permits coalescing. The implementation reports
failure-dominant FragmentSet status for MDS/MRDS/REQ/RES plus the fragment-set OCS, but does not expose a record for
every constituent fragment. This is an allowed low-overhead API choice, while the separate required/omitted
per-fragment control surface remains partial.

Net FF1 reading: the core transport-options state machine (surplus location, OCS, TLV parse/serialize, must-support
wire formats, FRAG split/reassembly, Sec. 14 disposition) is implementable in userspace and implemented in the pure
modules. RES provenance is deliberately delegated to the upper layer, and the broader Sec. 15 API remains partial
where this document says so.
The raw-socket boundary degrades, but does not block, the I/O requirements (FR-40, FR-41: Partial-in-
userspace, per L1, L4, L5), and the only outright infeasibility is platform reach (macOS receive, L7) and the
network-path survival of the surplus area (L3), the latter being precisely the empirical question FF2 measures
rather than a code defect.
