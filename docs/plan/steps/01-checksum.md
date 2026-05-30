# Step 1: RFC 1071 checksum primitive

Status: pending

## Goal

Implement the one's-complement Internet checksum (RFC 1071) that backs both the UDP checksum and the
RFC 9868 Option Checksum (OCS).

## Requirements

- A function computing the 16-bit one's-complement sum over a byte slice, with correct end-around
  carry folding and odd-length handling (final byte treated as the high byte of a 16-bit word).
- An incremental accumulator so callers can sum several regions (for example a pseudo-header plus a
  payload) without copying them into one buffer.
- The "complement" result, such that summing the data together with the stored complement yields zero.
- Pure, allocation-free, no `unsafe`. Located in `src/wire/checksum.rs`.

## Plan

To be detailed when the step starts (build on `model`; expose a small `Checksum` accumulator and a
one-shot helper).

## Tasks

- [ ] Implement the folding accumulator and the one-shot helper.
- [ ] Unit tests against the RFC 1071 worked example.
- [ ] Hand-computed vectors including an odd-length input and an all-zero input.
- [ ] Property: `sum(data) + complement == 0` (mod one's-complement).

## Definition of Done

- Unit tests pass against the RFC worked example and at least three hand vectors (odd-length and
  all-zero included); the complement property holds.
