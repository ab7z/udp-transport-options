# Step 3: OptionKind model + classification

Status: done

## Completion note

Implemented on branch `step-03-option-kind` after the preparatory Lean/CI/roadmap work. The Rust
implementation now contains the byte mapping, classification predicates, framing/fixed-length
helpers, exhaustive tests over all 256 Kind byte values, and Step-3 Lean Kind-table theorems.

## Goal

Map between the raw Kind byte and `OptionKind`, and classify options as SAFE/UNSAFE and as
must-support. This is the small classification layer that every later parser, serializer, typed
option, and receive-pipeline decision builds on.

## Requirements

- `OptionKind` <-> `u8` conversion using the constants in `model::kind`.
- Unknown Kind bytes must round-trip exactly through `OptionKind::Other(u8)`, including boundary
  values such as 8, 191, 192, and 255.
- `is_safe()` (Kind 0..=191), `is_unsafe()` (192..=255), and `is_must_support()` (0..=7) operate on
  the raw Kind byte after mapping through `OptionKind`.
- Framing classification is only about the Kind byte: EOL and NOP are single-byte options; every
  other Kind is length-delimited. `model::kind::EXTENDED_LENGTH_MARKER == 255` is a Length-field
  marker, not a special Kind.
- Fixed-length metadata must distinguish fixed total lengths from alternatives: APC 6, MDS 4, MRDS
  5, REQ 6, RES 6, and FRAG 10 or 12. Unknown Kinds have no fixed expected length.
- The helpers should stay allocation-free, panic-free, and usable by `const`/table-style tests where
  practical.

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`). This step also
bootstraps the Lean track: a `formal/lean-rfc9868/` Lake project with a repo-pinned
`lean-toolchain`, a no-`sorry` policy, and the retrofit specs of Steps 1-2.

Spec (before implementation): the Kind constants; SAFE `0..=191` / UNSAFE `192..=255`;
must-support `0..=7`; EOL and NOP as the only single-byte Kinds; all other Kinds as
length-delimited; the fixed lengths (APC 6, FRAG 10/12, MDS 4, MRDS 5, REQ 6, RES 6); `255` as the
Length-field extended-length marker, separate from Kind classification.

Theorems (after implementation, exhaustive over all 256 byte values): `to_byte(from_byte(b)) == b`;
`is_safe b` iff `b < 192`; `is_unsafe` iff not `is_safe`; `is_must_support b` iff `b <= 7`; EOL and
NOP are exactly the single-byte Kinds; the fixed-length metadata agrees with the spec table,
including both valid FRAG lengths.

## Plan

1. Add the conversion helpers backed by `model::kind`, mapping unknown bytes to `Other(u8)`.
2. Add raw-byte based SAFE/UNSAFE and must-support predicates; keep boundary behavior explicit for
   7/8 and 191/192.
3. Add a minimal framing helper for `SingleByte` vs `LengthDelimited`; leave extended-length parsing
   to Step 4 because it is driven by the Length field.
4. Add fixed-length metadata helpers that can represent "no fixed length" and the two FRAG lengths.
5. Add exhaustive tests over all 256 Kind byte values plus named boundary tests for readability.

## Tasks

- [x] `from_byte` / `to_byte` with exact `Other(u8)` preservation.
- [x] SAFE/UNSAFE and must-support predicates over the raw Kind byte.
- [x] Single-byte vs length-delimited framing helper; document that extended length is a Length-field
  concern for Step 4.
- [x] Fixed-length metadata helpers for APC/MDS/MRDS/REQ/RES and both FRAG lengths.
- [x] Exhaustive 0..=255 table tests and named boundary tests.
- [x] Lean spec/theorems for the Kind table and boundary predicates.

## Definition of Done

- Exhaustive Rust tests confirm the Kind mapping, exact `Other(u8)` preservation, the SAFE/UNSAFE
  boundary, `is_must_support` for 0..7, and the framing/fixed-length metadata.
- `scripts/lean-gate.sh` passes with the Step-3 Kind table theorems.
