# Step 11: FRAG fragmentation (send)

Status: pending

## Goal

Split an oversized datagram into FRAG fragments.

## Requirements

- Each fragment carries empty UDP user data (UDP Length == 8); the fragment data lives in the
  surplus area after all of the fragment's options (located by Frag.Start, running to the end of the
  IP datagram).
- Non-terminal fragments use the 10-byte FRAG form; the terminal fragment uses the 12-byte form with
  the Reassembled-Datagram-Option-Start (RDOS).
- Correct `Frag.Start`, `Identification` (unique per 5-tuple), and `Frag.Offset` across fragments.
- The single-fragment (atomic) case is supported.
- The fragment size S derives from the path MTU, with MDS as a hint (Sec. 11.5) -- never from MRDS;
  chunks are <= S-12 (non-terminal) / S-14 (terminal). The reassembled size (UDP header + data +
  per-datagram options) must not exceed the peer's MRDS; assume 2926 (IPv4) and
  2 segments when no MRDS was received (Sec. 11.6); a payload over that cap is rejected with an
  error, not fragmented.

## Plan

1. From a payload plus per-datagram options, size fragments against S (path MTU, MDS hint) and the
   surplus budget; reject payloads whose reassembled size exceeds the MRDS cap.
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
