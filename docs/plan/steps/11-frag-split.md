# Step 11: FRAG fragmentation (send)

Status: done

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

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): every fragment carries empty UDP user data (UDP Length == 8);
non-terminal fragments use the 10-byte FRAG form, the terminal one the 12-byte form with RDOS;
chunks are <= S-12 / S-14; offsets are contiguous and the reassembled size respects the MRDS cap
(reject, never fragment past it); the atomic single-fragment case.

Theorems (after implementation): split -> concatenate is the identity on the payload (N bytes in,
N bytes reassembled); the sizing bound holds; the offset/RDOS arithmetic is correct.

## Plan

1. From a payload plus per-datagram options, size fragments against S (path MTU, MDS hint) and the
   surplus budget; reject payloads whose reassembled size exceeds the MRDS cap.
2. Emit fragments, each with empty UDP data (Length 8): a FRAG option (non-terminal 10-byte /
   terminal 12-byte with RDOS), correct Frag.Start and Frag.Offset, a shared 32-bit Identification,
   and an OCS.
3. Handle the atomic single-fragment (terminal-only) case.
4. Tests: fragmenting N bytes reassembles to N; sizing respects the MRDS cap.

## Implementation notes

- `frag::split::split_datagram` is pure and socket-free. It emits one OCS-led surplus body per
  fragment; callers pass that body to the raw send assembler with empty UDP user data.
- Fragment bodies are minimal: OCS plus exactly one FRAG TLV before fragment data. That keeps the
  measured budgets at S-12 for non-terminal fragments and S-14 for terminal fragments.
- `Frag.Offset` is measured from the original UDP header. Multi-fragment splits therefore emit the
  first payload byte at offset 8, while the RFC standalone/atomic FRAG variant emits offset 0.
- `PeerFragmentLimits::default_ipv4()` captures the no-MRDS default (2926 bytes, 2 segments).

## Tasks

- [x] Fragment-splitting logic and per-fragment surplus assembly.
- [x] Identification generation.
- [x] Atomic single-fragment case.
- [x] Tests: fragmenting N bytes reassembles to N; sizing respects MRDS.

## Definition of Done

- Fragmenting an N-byte payload produces fragments whose offsets and terminal RDOS reassemble to N;
  the atomic case is valid; the MRDS cap is respected.

Verification: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test`, and
`scripts/lean-gate.sh` passed during implementation. The mandatory full `scripts/pre-pr.sh` gate is
run before PR publication.
