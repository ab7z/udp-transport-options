# Step 7: Typed must-support options

Status: pending

## Goal

Implement `TypedOption` decode/encode for the fixed-size must-support options.

## Requirements

- `Apc` (CRC32C over the UDP user data, via the `crc32c` crate), `Mds`, `Mrds`, `Req`, `Res`.
- `decode(&[u8]) -> Result<Self, ParseError>` validates the exact value length; `encode` appends the
  full Kind + Length + Value framing.
- `Frag` encode/decode is shared with Steps 11/12 (the value layout lives here).

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): the exact fixed lengths (APC 6, MDS 4, MRDS 5, REQ 6, RES 6; FRAG 10
non-terminal / 12 terminal with RDOS) and the big-endian value layouts.

Theorems (after implementation): `decode` accepts exactly the spec lengths and rejects all others;
encode -> decode round-trips; the FRAG length determines the terminal flag. APC's CRC32C stays a
trusted primitive validated by external test vectors, not a Lean model.

## Plan

1. Implement `TypedOption` for `Apc`, `Mds`, `Mrds`, `Req`, `Res`, and the `Frag` value codec.
2. `decode` checks the exact value length and reads big-endian fields; `encode` writes the full
   Kind + Length + Value framing.
3. `Apc` computes CRC32C over the UDP user data via the `crc32c` crate.
4. Tests: encode -> parse -> decode round-trips; APC against a known vector; a wrong value length
   yields `ParseError`.

## Tasks

- [ ] Implement `TypedOption` for `Apc`, `Mds`, `Mrds`, `Req`, `Res` (and `Frag` value layout).
- [ ] APC CRC32C with a cross-check vector.
- [ ] Tests: encode->parse->decode round-trips; wrong length -> `ParseError`.

## Definition of Done

- Each typed option round-trips encode->parse->decode; APC matches the `crc32c` crate and a known
  vector; an incorrect value length yields `ParseError`.
