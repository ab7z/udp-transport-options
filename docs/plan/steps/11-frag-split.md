# Step 11: FRAG fragmentation (send)

Status: pending

## Goal

Split an oversized datagram into FRAG fragments.

## Requirements

- Each fragment carries empty UDP user data (UDP Length == 8); the data lives in the surplus area
  after the FRAG option.
- Non-terminal fragments use the 10-byte FRAG form; the terminal fragment uses the 12-byte form with
  the Reassembled-Datagram-Option-Start (RDOS).
- Correct `Frag.Start`, `Identification` (unique per 5-tuple), and `Frag.Offset` across fragments.
- The single-fragment (atomic) case is supported.
- Sizing respects MDS (per-link) and the MRDS reassembly cap (2926 IPv4 / 2886 IPv6).

## Plan

1. From a payload plus per-datagram options, size fragments against MDS, the MRDS cap, and the
   surplus budget.
2. Emit fragments, each with empty UDP data (Length 8): a FRAG option (non-terminal 10-byte /
   terminal 12-byte with RDOS), correct Frag.Start and Frag.Offset, a shared 32-bit Identification,
   and an OCS.
3. Handle the atomic single-fragment (terminal-only) case.
4. Tests: fragmenting N bytes reassembles to N; sizing respects the MRDS cap.

## Tasks

- [ ] Fragment-splitting logic and per-fragment surplus assembly.
- [ ] Identification generation.
- [ ] Atomic single-fragment case.
- [ ] Tests: fragmenting N bytes reassembles to N; sizing respects MRDS.

## Definition of Done

- Fragmenting an N-byte payload produces fragments whose offsets and terminal RDOS reassemble to N;
  the atomic case is valid; the MRDS cap is respected.
