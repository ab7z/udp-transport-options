# Step 1: RFC 1071 checksum primitive

Status: done

> Historical terminology note (2026-07-13): in one's-complement arithmetic, data plus its stored
> checksum validates to the all-ones representation (`0xFFFF`), whose complement is zero. Any older
> shorthand in this step saying that the raw sum "yields zero" should be read in that precise sense;
> the Outcome and Lean theorem already use the folded `0xFFFF` criterion.

## Goal

Implement the one's-complement Internet checksum (RFC 1071) that backs both the UDP checksum and the
OCS.

## Requirements

- A function computing the 16-bit one's-complement sum over a byte slice, with correct end-around
  carry folding and odd-length handling (final byte treated as the high byte of a 16-bit word).
- An incremental accumulator so callers can sum several regions (for example a pseudo-header plus a
  payload) without copying them into one buffer.
- The "complement" result, such that summing the data together with the stored complement yields zero.
- Pure, allocation-free, no `unsafe`. Located in `src/wire/checksum.rs`.

## Lean verification

Retrofit done: `formal/lean-rfc9868/Rfc9868/Checksum.lean` (all theorems proven, gated by
`scripts/lean-gate.sh`). The workflow for all later steps: extend the Lean spec in
`formal/lean-rfc9868/` first, then implement, then prove (`lake build` green, no `sorry`); see
`LEAN_RFC9868_VALIDATION.md`.

Spec: the 16-bit one's-complement sum with end-around carry; a trailing odd byte is the high byte
of a final word.

Theorems: `finish` is the complement of the folded sum; data plus the stored complement folds to
`0xffff` (also with the `0x0000 -> 0xFFFF` normalization); incremental accumulation equals the
one-shot sum — word-level unconditionally, byte-level for word-aligned region splits, which is
the documented `add_slice` contract itself (RFC 1071 Section 2(A)); a trailing odd byte is the
high byte of a final word.

## Plan

1. Define a `Checksum` accumulator over a running `u32`: `add_slice(&[u8])` folds 16-bit big-endian
   words and treats a trailing odd byte as the high byte of a final word; `add_u16(u16)` adds scalar
   fields (the surplus length, pseudo-header parts).
2. `fold()` performs end-around carry folding; `finish() -> u16` returns the one's complement;
   `sum() -> u16` returns the non-complemented folded sum (OCS verification expects 0).
3. Provide a one-shot `internet_checksum(&[u8]) -> u16` helper for tests and simple callers.
4. Keep the module allocation-free and free of `unsafe`.

## Tasks

- [x] Implement the folding accumulator and the one-shot helper.
- [x] Unit tests against the RFC 1071 worked example.
- [x] Hand-computed vectors including an odd-length input and an all-zero input.
- [x] Property: `sum(data) + complement == 0` (mod one's-complement).

## Definition of Done

- Unit tests pass against the RFC worked example and at least three hand vectors (odd-length and
  all-zero included); the complement property holds.

## Outcome

- `Checksum` accumulator (`add_slice`, `add_u16`, `sum`, `finish`) plus the one-shot
  `internet_checksum` in `src/wire/checksum.rs`; pure, allocation-free, no `unsafe`.
- One deviation from the plan sketch: instead of a separate deferred `fold()`, `add_u16` folds the
  end-around carry eagerly, keeping the running sum below 2^17 so the `u32` accumulator cannot
  overflow for any input length; `sum()` performs the final fold.
- Six unit tests: the RFC 1071 Section 3 worked example (sum `0xddf2`, checksum `0x220d`),
  odd-length (trailing byte = high byte), all-zero, end-around-carry vectors, the
  data-plus-stored-complement property (folds to `0xffff`), and incremental == one-shot.
- Verified on the host and cross-compiled on `achim` (`scripts/vm-ubuntu-server.sh verify`).
