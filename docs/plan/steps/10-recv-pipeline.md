# Step 10: Receive pipeline (pure)

Status: pending

## Goal

Implement the pure, root-free receive state machine that encodes the RFC 9868 processing order.

## Requirements

- `process_datagram(ip, transport_payload, &mut cache) -> Result<Delivery, RecvError>`.
- Order: verify the UDP checksum, locate/validate the surplus area, validate the OCS, parse the
  options, then either reassemble (FRAG, Step 12) or deliver.
- Dispositions: a malformed surplus area discards the options but still delivers the payload; unknown
  SAFE options are ignored; unknown UNSAFE options cause the (reassembled) data to be dropped.
- Receive-side must-support ordering check.
- The {UDP checksum 0 / nonzero} x {OCS 0 / valid / invalid} disposition matrix.
- Apply the >7-consecutive-NOP DoS log (via `log`).
- No I/O; fully unit-testable without privilege.

## Plan

To be detailed when the step starts.

## Tasks

- [ ] Implement the pipeline function and `Delivery` handling.
- [ ] Encode every disposition branch.
- [ ] Table-driven unit tests over crafted byte buffers (no root).

## Definition of Done

- Table-driven tests cover valid delivery, bad OCS, malformed TLV, unknown SAFE, unknown UNSAFE, the
  full cksum/OCS matrix, and the NOP-flood log, all without root.
