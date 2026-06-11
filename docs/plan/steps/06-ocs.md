# Step 6: OCS compute + validate

Status: pending

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

## Plan

1. `compute_ocs`: over the serialized surplus (OCS field zeroed) plus the 16-bit surplus length, run
   the Step 1 accumulator and write `!sum` into the reserved OCS field (two-pass back-patch); a
   `0x0000` result is written as `0xFFFF`.
2. `validate_ocs`: recompute and accept iff the result is the one's-complement zero (folded sum
   `0xFFFF`; equivalently `!sum == 0`); skip the sum entirely for the unused case (OCS == 0 with
   UDP checksum == 0, assumed correct).
3. Enforce the odd-start pad byte is zero on both write and read (`ParseError::NonZeroPad`).
4. Encode the disposition: OCS == 0 with a non-zero UDP checksum means the options are ignored.
5. Wire validation in as the gate before `OptionsIter` runs.
6. Tests: a serialized surplus validates (one's-complement zero); any byte flip fails; the forced
   `0x0000 -> 0xFFFF` case; seed the cksum/OCS matrix.

## Tasks

- [ ] OCS compute (back-patch) and validate.
- [ ] Odd-pad zero enforcement.
- [ ] Wire the validation into the parse gate.
- [ ] Tests: validates (one's-complement zero); any byte flip fails; forced `0x0000 -> 0xFFFF`; the
      OCS==0/UDP-cksum disposition.

## Definition of Done

- A serialized surplus area validates (one's-complement zero); flipping any surplus byte fails
  validation; a forced `0x0000` computation is emitted as `0xFFFF` and still validates; the
  "OCS == 0 with nonzero UDP checksum" case is flagged distinctly; a non-zero odd pad is rejected.
