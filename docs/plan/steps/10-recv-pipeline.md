# Step 10: Receive pipeline (pure)

Status: implemented

## Goal

Implement the pure, root-free receive state machine that encodes the RFC 9868 processing order.

## Requirements

- `process_datagram(ip_datagram: &[u8], cache: &mut ReassemblyCache) -> Result<Delivery, RecvError>`
  (the signature of `architecture.md`: the pipeline takes the full IP-datagram bytes).
- Validate the UDP Length bounds first: `8 <= UDP Length <= IP transport payload`; outside that
  range, silently drop the datagram and log (RFC 9868 Sec. 10; FR-49).
- Order: verify the UDP checksum, locate/validate the surplus area, validate the OCS, parse the
  options, then either buffer a FRAG datagram for Step 12 or deliver.
- Dispositions: a malformed surplus area discards the options but still delivers the payload; a known
  option below its RFC minimum length discards all options; a merely over-minimum known SAFE length
  ignores only that option; a sub-minimum FRAG length follows the generic malformed-surplus
  disposition; a malformed FRAG at or above the minimum length counts as unsupported UNSAFE; unknown
  SAFE options are ignored; unknown UNSAFE options outside a fragment context cause the user data to
  be dropped with a zero-length delivery. A valid empty-payload FRAG with a fragment-local UNSAFE or
  malformed per-fragment option produces `Delivery::Dropped`, not a successful `Buffered` result.
- For a valid empty-payload FRAG, `Frag. Start` is the boundary between fragment options and fragment
  data; bytes at or after that offset are not parsed as more options.
- Valid FRAG with non-empty UDP user data: ignore all options, deliver the received user data
  (Sec. 11.4). Malformed FRAG is not eligible for this exception.
- Receive-side must-support ordering check; violations are logged, not dropped.
- The {UDP checksum 0 / nonzero} x {OCS 0 / valid / invalid} disposition matrix.
- Apply the >7-consecutive-NOP DoS log (via sampled `log` diagnostics).
- No I/O; fully unit-testable without privilege.

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): the receive order as a pure function of the datagram bytes -- UDP
Length bounds, UDP checksum, surplus location/pad, OCS, TLV parse, option dispositions, then
FRAG/deliver -- and the full Sec. 14 disposition matrix, including Erratum 8834 (an overrunning
option is a malformed surplus area: discard all options, deliver the payload), the
known-SAFE-length split (sub-minimum fatal to all options, over-minimum ignored locally), unknown SAFE
ignored, unsupported UNSAFE zero-length delivery, malformed-FRAG-as-UNSAFE, valid FRAG deferral, and the
{UDP checksum 0/nonzero} x {OCS 0/valid/invalid} matrix.

Theorems (after implementation): the Lean `Receive` model captures the UDP-checksum/OCS disposition
matrix; the Rust table tests and the `process_datagram` fuzz target cover the byte-level pipeline.
Options are never delivered unless every prior gate passed.

## Plan

1. `process_datagram(ip_datagram, &mut cache)`: check the UDP Length bounds (drop + log outside
   `[8, transport payload]`), verify the UDP checksum, `locate_surplus`, validate the OCS, and apply
   the cksum/OCS disposition matrix.
2. Parse and classify options: sub-minimum known lengths, underrun, and overrun -> discard all options
   but deliver the payload; the sub-minimum check runs before duplicate first-wins and includes
   assigned out-of-scope SAFE Kinds with known minima (TIME/EXP); an over-minimum known SAFE length
   -> ignore that option only; sub-minimum FRAG -> discard all options and deliver the payload;
   malformed FRAG or invalid `Frag. Start` -> unsupported UNSAFE; unknown SAFE -> ignore; unknown
   UNSAFE before a valid FRAG context -> zero-length delivery; unknown UNSAFE after a valid
   empty-payload FRAG or malformed per-fragment options before `Frag. Start` -> `Delivery::Dropped`.
3. Apply the receive-side must-support ordering check and the >7-NOP DoS log through sampled warnings.
4. On a clean FRAG with empty user data, return `Delivery::Buffered`. Step 10 introduces the
   `ReassemblyCache` type so the signature is stable; Step 12 fills it with insert/GC/limit logic,
   including persisted fragment-failure state, and the single re-process path. On FRAG with non-empty
   user data, ignore all options and deliver the user data.
5. Table-driven unit tests, property tests, and a fuzz target over crafted and arbitrary byte buffers,
   requiring no privilege.

## Tasks

- [x] Implement the pipeline function and `Delivery` handling.
- [x] Encode every non-reassembly disposition branch.
- [x] Table-driven unit tests over crafted byte buffers (no root).
- [x] Property test and fuzz target assert totality over arbitrary input.

## Definition of Done

- Table-driven tests cover valid delivery, UDP-Length bounds and logging, bad OCS, malformed TLV,
  sub-minimum versus over-minimum known SAFE lengths, sub-minimum FRAG, duplicate non-FRAG
  first-wins behavior, duplicate sub-minimum known options, assigned SAFE sub-minimum lengths,
  duplicate FRAG, valid and malformed FRAG, fragment data after `Frag. Start`, unknown SAFE,
  fragment-local UNSAFE, unknown UNSAFE outside a fragment context (including later
  malformed TLV), the full cksum/OCS matrix, must-support ordering logs, and the sampled NOP-flood
  log, all without root.
- `process_datagram` is fuzzed for no-panic behavior and a strengthened disposition oracle;
  `ReassemblyCache` is a Step-10 stub only.
