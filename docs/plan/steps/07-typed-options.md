# Step 7: Typed must-support options

Status: pending

## Goal

Implement `TypedOption` decode/encode for the fixed-size must-support options.

## Requirements

- `Apc` (CRC32C over the UDP user data, via the `crc32c` crate), `Mds`, `Mrds`, `Req`, `Res`.
- `decode(&[u8]) -> Result<Self, ParseError>` validates the exact value length; `encode` appends the
  full Kind + Length + Value framing.
- `Frag` encode/decode is shared with Steps 11/12 (the value layout lives here).

## Plan

To be detailed when the step starts.

## Tasks

- [ ] Implement `TypedOption` for `Apc`, `Mds`, `Mrds`, `Req`, `Res` (and `Frag` value layout).
- [ ] APC CRC32C with a cross-check vector.
- [ ] Tests: encode->parse->decode round-trips; wrong length -> `ParseError`.

## Definition of Done

- Each typed option round-trips encode->parse->decode; APC matches the `crc32c` crate and a known
  vector; an incorrect value length yields `ParseError`.
