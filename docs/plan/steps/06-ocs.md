# Step 6: OCS compute + validate

Status: pending

## Goal

Compute and validate the Option Checksum (RFC 9868 Section 9) over the surplus area.

## Requirements

- Compute the OCS as a two-pass back-patch: serialize the options with the OCS field zeroed, then set
  the OCS so the one's-complement sum over the whole surplus area (including the 16-bit surplus
  length) is zero. The OCS is the first content in the surplus area.
- Validate by recomputing the sum and checking it is zero.
- Enforce the odd-start pad byte is zero on both write and read.
- Handle the UDP-checksum-zero interaction: distinguish "OCS == 0 while the UDP checksum is nonzero"
  (options must be ignored) from a validated OCS.

## Plan

1. `compute_ocs`: over the serialized surplus (OCS field zeroed) plus the 16-bit surplus length, run
   the Step 1 accumulator and write `!sum` into the reserved OCS field (two-pass back-patch).
2. `validate_ocs`: recompute and accept iff the folded sum is 0.
3. Enforce the odd-start pad byte is zero on both write and read (`ParseError::NonZeroPad`).
4. Encode the disposition: OCS == 0 with a non-zero UDP checksum means the options are ignored.
5. Wire validation in as the gate before `OptionsIter` runs.
6. Tests: a serialized surplus validates to 0; any byte flip fails; seed the cksum/OCS matrix.

## Tasks

- [ ] OCS compute (back-patch) and validate.
- [ ] Odd-pad zero enforcement.
- [ ] Wire the validation into the parse gate.
- [ ] Tests: validates to zero; any byte flip fails; the OCS==0/UDP-cksum disposition.

## Definition of Done

- A serialized surplus area validates (sum zero); flipping any surplus byte fails validation; the
  "OCS == 0 with nonzero UDP checksum" case is flagged distinctly; a non-zero odd pad is rejected.
