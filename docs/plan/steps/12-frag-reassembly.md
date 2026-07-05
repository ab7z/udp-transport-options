# Step 12: FRAG reassembly (recv)

Status: implemented

## Goal

Reassemble FRAG fragments with overlap protection, timeouts, and DoS limits.

## Requirements

- A `ReassemblyCache` keyed by `FragKey` (the UDP 5-tuple plus Identification).
- Offset-sorted insertion; overlapping fragments abort and discard the partial (no ICMP).
- A reassembly timeout (<= 2 minutes) and garbage collection of expired partials.
- Per-socket-pair byte and segment limits, plus a global cap on pending partials; one pair hitting a
  limit must not affect another.
- On completion, return the reassembled datagram for one re-pass through the pipeline. A FRAG
  reappearing there with non-empty user data follows the RFC rule: ignore all options, deliver the
  data (Sec. 11.4). Only a nested FRAG with empty user data is rejected, as local anti-loop policy
  (the RFC does not define nested fragmentation); there is never a second re-feed.

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): the cache as a pure state machine over insert/gc transitions with a
passed-in `now`; the key is (source IP, source port, destination IP, destination port) plus
Identification; overlap aborts; completion exactly on gap-free coverage with a terminal fragment;
the timeout is a parameter whose default is at most 2 minutes (an RFC SHOULD, modeled as the
default, not a hard invariant); the per-pair and global caps.

Theorems (after implementation): Step 11 fragments inserted in any order complete to the original
bytes; any overlap aborts; gc removes exactly the expired partials; the caps fire; two pairs are
isolated. Wall-clock time itself is not modeled, only the relation between `now` and stored
timestamps.

## Plan

1. `ReassemblyCache` keyed by `FragKey`, with a per-key partial holding offset-sorted segments, the
   terminal flag, the RDOS, a byte total, and a receive timestamp.
2. Insert with overlap detection (overlap -> `Abort(Overlap)`; exact duplicate fragments are ignored
   as packet duplicates only when bytes and per-fragment options match); enforce per-datagram byte and
   segment caps plus a global pending-partial cap for retained incomplete state.
3. Timeout and garbage-collect partials (<= 2 minutes); on completion reconstruct the datagram
   (`Complete { tail, udp_length, fragment_options }`) and re-pass once. Coalesced per-fragment
   MDS/MRDS minima and latest REQ/RES tokens are prepended to the delivered options; FRAG with
   non-empty data -> options ignored, data delivered (Sec. 11.4); nested FRAG with empty data ->
   rejected (local policy).
4. Tests: in-order and out-of-order success; overlap abort; each cap firing; GC; pair isolation; no
   re-process loop.

## Tasks

- [x] Cache structure, insertion, overlap detection.
- [x] Timeout + GC.
- [x] Per-datagram and global limits.
- [x] Completion + single re-pass (RFC rule for non-empty data; empty-data nested FRAG rejected).
- [x] Tests for each behavior.

## Definition of Done

- In-order and out-of-order reassembly succeed; overlaps abort; limits fire; expired partials are
  collected; two pairs are isolated; a completed datagram re-enters the pipeline exactly once with no
  loop.
