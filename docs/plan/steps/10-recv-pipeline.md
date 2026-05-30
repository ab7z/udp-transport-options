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

1. `process_datagram(ip, transport_payload, &mut cache)`: verify the UDP checksum, `locate_surplus`,
   validate the OCS, and apply the cksum/OCS disposition matrix.
2. Parse and classify options: malformed -> discard options but deliver the payload; unknown SAFE ->
   ignore; unknown UNSAFE -> drop the (reassembled) data.
3. Apply the receive-side must-support ordering check and the >7-NOP DoS log (via `log`).
4. On FRAG, feed the reassembly cache (Step 12) and re-process once on completion.
5. Table-driven unit tests over crafted byte buffers, requiring no privilege.

## Tasks

- [ ] Implement the pipeline function and `Delivery` handling.
- [ ] Encode every disposition branch.
- [ ] Table-driven unit tests over crafted byte buffers (no root).

## Definition of Done

- Table-driven tests cover valid delivery, bad OCS, malformed TLV, unknown SAFE, unknown UNSAFE, the
  full cksum/OCS matrix, and the NOP-flood log, all without root.
