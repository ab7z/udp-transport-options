# Step 10: Receive pipeline (pure)

Status: pending

## Goal

Implement the pure, root-free receive state machine that encodes the RFC 9868 processing order.

## Requirements

- `process_datagram(ip_datagram: &[u8], cache: &mut ReassemblyCache) -> Result<Delivery, RecvError>`
  (the signature of `architecture.md`: the pipeline takes the full IP-datagram bytes).
- Validate the UDP Length bounds first: `8 <= UDP Length <= IP transport payload`; outside that
  range, silently drop the datagram and log (RFC 9868 Sec. 10; FR-49).
- Order: verify the UDP checksum, locate/validate the surplus area, validate the OCS, parse the
  options, then either reassemble (FRAG, Step 12) or deliver.
- Dispositions: a malformed surplus area discards the options but still delivers the payload; an
  unexpected length of a known SAFE option ignores only that option (a malformed FRAG counts as
  unsupported UNSAFE); unknown SAFE options are ignored; unknown UNSAFE options cause the
  (reassembled) user data to be dropped with a zero-length delivery to the user (Sec. 12, 14).
- FRAG with non-empty UDP user data: ignore all options, deliver the received user data (Sec. 11.4).
- Receive-side must-support ordering check.
- The {UDP checksum 0 / nonzero} x {OCS 0 / valid / invalid} disposition matrix.
- Apply the >7-consecutive-NOP DoS log (via `log`).
- No I/O; fully unit-testable without privilege.

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): the receive order as a pure function of the datagram bytes -- UDP
Length bounds, UDP checksum, surplus location/pad, OCS, TLV parse, option dispositions, then
FRAG/deliver -- and the full Sec. 14 disposition matrix, including Erratum 8834 (an overrunning
option is a malformed surplus area: discard all options, deliver the payload), the
known-SAFE-unexpected-length rule, unknown SAFE ignored, unknown UNSAFE dropping the (reassembled)
data with zero-length delivery, the FRAG-with-non-empty-data precedence, and the
{UDP checksum 0/nonzero} x {OCS 0/valid/invalid} matrix.

Theorems (after implementation): `process_datagram` is total over byte buffers; each matrix row is
an equation on the function; options are never delivered unless every prior gate passed. The
table-driven Rust tests come first; the Lean theorems track the same matrix.

## Plan

1. `process_datagram(ip_datagram, &mut cache)`: check the UDP Length bounds (drop + log outside
   `[8, transport payload]`), verify the UDP checksum, `locate_surplus`, validate the OCS, and apply
   the cksum/OCS disposition matrix.
2. Parse and classify options: sub-minimum/underrun/overrun lengths -> discard all options but
   deliver the payload; an unexpected length of a known SAFE option -> ignore that option only
   (malformed FRAG -> unsupported UNSAFE); unknown SAFE -> ignore; unknown UNSAFE -> drop the
   (reassembled) user data and deliver a zero-length datagram -- unless FRAG with non-empty user
   data applies, whose Sec. 11.4 rule (ignore all options, deliver the data) takes precedence.
3. Apply the receive-side must-support ordering check and the >7-NOP DoS log (via `log`).
4. On FRAG with empty user data, feed the reassembly cache (Step 12) and re-process once on
   completion; on FRAG with non-empty user data, ignore all options and deliver the user data.
5. Table-driven unit tests over crafted byte buffers, requiring no privilege.

## Tasks

- [ ] Implement the pipeline function and `Delivery` handling.
- [ ] Encode every disposition branch.
- [ ] Table-driven unit tests over crafted byte buffers (no root).

## Definition of Done

- Table-driven tests cover valid delivery, UDP-Length bounds, bad OCS, malformed TLV, the
  known-SAFE-unexpected-length case, FRAG with non-empty user data, unknown SAFE, unknown UNSAFE
  (zero-length delivery), the full cksum/OCS matrix, and the NOP-flood log, all without root.
