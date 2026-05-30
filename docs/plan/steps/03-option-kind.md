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
