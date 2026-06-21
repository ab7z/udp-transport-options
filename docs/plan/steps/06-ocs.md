# Step 6: OCS compute + validate

Status: done

## Goal

Compute and validate the Option Checksum (RFC 9868 Section 9) over the surplus area.

## Requirements

- Compute the OCS as a two-pass back-patch: serialize the options with the OCS field zeroed, then set
  the OCS so the one's-complement sum over the whole surplus area (including the 16-bit surplus
  length) is the one's-complement zero. The OCS is the first content in the surplus area.
- Transmit a computed `0x0000` as its one's-complement equivalent `0xFFFF` (as for the UDP checksum),
  so a used OCS is never zero ("OCS MUST be non-zero when the UDP checksum is non-zero", Sec. 9).
- Validate by recomputing the sum and checking it folds to the one's-complement zero (a folded sum of
  `0xFFFF`; equivalently, its complement is `0`).
- Enforce the odd-start pad byte is zero on both write and read.
- Handle the zero-OCS rules: OCS == 0 with UDP checksum == 0 is "unused, assumed correct" (no sum is
  run); "OCS == 0 while the UDP checksum is nonzero" means the options are ignored (Sec. 9, 14).

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): OCS = the one's-complement sum over the whole surplus area (the OCS
field as zero) plus the 16-bit surplus length, stored complemented; validation accepts iff the
folded sum is `0xFFFF`; OCS == 0 with UDP checksum == 0 is "unused, assumed correct"; OCS == 0 with
a non-zero UDP checksum means the options are ignored; the odd-start pad byte is zero. Caveat: the
"computed `0x0000` is sent as `0xFFFF`" rule is not literally quotable from RFC 9868 -- it follows
from the Internet-checksum convention plus the non-zero-OCS requirement (Sec. 9); pin the exact
citation in the spec rather than axiomatizing it silently.

Theorems (after implementation): compute -> validate succeeds for every serialized surplus; the
forced `0x0000 -> 0xFFFF` value still validates; validation is equivalent to the sum specification
(so any byte change that alters the sum fails); a non-zero pad is rejected.

## Plan

1. `compute_ocs`: over the serialized surplus (OCS field zeroed) plus the 16-bit surplus length, run
   the Step 1 accumulator and write `!sum` into the reserved OCS field (two-pass back-patch); a
   `0x0000` result is written as `0xFFFF`.
2. `validate_ocs`: recompute and accept iff the result is the one's-complement zero (folded sum
   `0xFFFF`; equivalently `!sum == 0`); skip the sum entirely for the unused case (OCS == 0 with
   UDP checksum == 0, assumed correct).
3. Enforce the odd-start pad byte is zero on both write and read (`ParseError::NonZeroPad`).
4. Encode the disposition: OCS == 0 with a non-zero UDP checksum means the options are ignored.
5. Expose the OCS validation disposition that Step 10 will use as the gate before `OptionsIter`
   runs; the receive pipeline itself remains deferred to Step 10.
6. Tests: a serialized surplus validates (one's-complement zero); any byte flip fails; the forced
   `0x0000 -> 0xFFFF` case; seed the cksum/OCS matrix.

## Tasks

- [x] OCS compute (back-patch) and validate.
- [x] Odd-pad zero enforcement.
- [x] Expose the validation disposition for the Step 10 parse gate.
- [x] Tests: validates (one's-complement zero); any byte flip fails; forced `0x0000 -> 0xFFFF`; the
      OCS==0/UDP-cksum disposition.

## Definition of Done

- A serialized surplus area validates (one's-complement zero); flipping any surplus byte fails
  validation; a forced `0x0000` computation is emitted as `0xFFFF` and still validates; the
  "OCS == 0 with nonzero UDP checksum" case is flagged distinctly; a non-zero odd pad is rejected.
