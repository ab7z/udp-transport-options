# Step 3: OptionKind model + classification

Status: pending

## Goal

Map between the raw Kind byte and `OptionKind`, and classify options as SAFE/UNSAFE and as
must-support, with the framing rules for each Kind.

## Requirements

- `OptionKind` <-> `u8` conversion using the constants in `model::kind`.
- `is_safe()` (Kind 0..=191) and `is_unsafe()` (192..=255); `is_must_support()` (0..=7).
- Framing classification per Kind: single-byte (EOL, NOP) vs TLV vs the extended (255) length form.
- The fixed length expected for each fixed-size Kind (from `model::length`).

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`). This step also
bootstraps the Lean track: a `formal/lean-rfc9868/` Lake project with a repo-pinned
`lean-toolchain`, a no-`sorry` policy, and the retrofit specs of Steps 1-2.

Spec (before implementation): the Kind constants; SAFE `0..=191` / UNSAFE `192..=255`;
must-support `0..=7`; EOL and NOP as the only single-byte kinds; the fixed lengths (APC 6,
FRAG 10/12, MDS 4, MRDS 5, REQ 6, RES 6); `255` as the extended-length marker.

Theorems (after implementation, exhaustive over all 256 byte values): `to_u8 (from_u8 b) = b`;
`is_safe b` iff `b < 192`; `is_unsafe` iff not `is_safe`; `is_must_support b` iff `b <= 7`; the
framing classification and `fixed_len` agree with the spec table.

## Plan

1. `OptionKind::from_u8` / `to_u8` backed by `model::kind`, mapping unknown bytes to `Other(u8)`.
2. `is_safe` / `is_unsafe` via `UNSAFE_MIN`; `is_must_support` for kinds 0..=7.
3. A `framing()` classifier (single-byte vs TLV vs extended-capable) and `fixed_len()` from
   `model::length`.
4. Exhaustive tests over all 256 Kind byte values.

## Tasks

- [ ] `from_u8` / `to_u8`.
- [ ] SAFE/UNSAFE and must-support predicates.
- [ ] Framing/expected-length helpers.
- [ ] Exhaustive table tests.

## Definition of Done

- Exhaustive tests confirm the Kind mapping, the SAFE/UNSAFE boundary, `is_must_support` for 0..7,
  and the framing/length classification.
