# Step 12: FRAG reassembly (recv)

Status: pending

## Goal

Reassemble FRAG fragments with overlap protection, timeouts, and DoS limits.

## Requirements

- A `ReassemblyCache` keyed by `FragKey` (the UDP 5-tuple plus Identification).
- Offset-sorted insertion; overlapping fragments abort and discard the partial (no ICMP).
- A reassembly timeout (<= 2 minutes) and garbage collection of expired partials.
- Per-socket-pair byte and segment limits, plus a global cap on pending partials; one pair hitting a
  limit must not affect another.
- On completion, return the reassembled datagram for one re-pass through the pipeline; a reassembled
  datagram must not itself carry FRAG (reject to prevent loops).

## Plan

1. `ReassemblyCache` keyed by `FragKey`, with a per-key partial holding offset-sorted segments, the
   terminal flag, the RDOS, a byte total, and a receive timestamp.
2. Insert with overlap detection (overlap -> `Abort(Overlap)`); enforce per-pair byte and segment
   caps plus a global pending-partial cap.
3. Timeout and garbage-collect partials (<= 2 minutes); on completion reconstruct the datagram
   (`Complete(bytes)`) and reject a nested FRAG on the re-pass.
4. Tests: in-order and out-of-order success; overlap abort; each cap firing; GC; pair isolation; no
   re-process loop.

## Tasks

- [ ] Cache structure, insertion, overlap detection.
- [ ] Timeout + GC.
- [ ] Per-pair and global limits.
- [ ] Completion + re-pass with nested-FRAG rejection.
- [ ] Tests for each behavior.

## Definition of Done

- In-order and out-of-order reassembly succeed; overlaps abort; limits fire; expired partials are
  collected; two pairs are isolated; a completed datagram re-enters the pipeline exactly once with no
  loop.
