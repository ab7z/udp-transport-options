# Step 5: Option serializer

Status: pending

## Goal

Serialize a set of options into a surplus area with correct ordering, alignment, and termination.

## Requirements

- `OptionsBuilder` accepting typed options and emitting their wire bytes.
- Must-support options emitted before other SAFE options (canonical order).
- NOP used for inter-option alignment; EOL terminates; the remainder is zero-filled to a 2-byte
  boundary so the total surplus length is even.
- The extended length form emitted when a value is large enough to need it.
- The OCS is reserved as the first option here and back-patched in Step 6.

## Plan

1. `OptionsBuilder` accumulates owned `RawOption`s from typed options.
2. `finish()` emits must-support options first (canonical order, excluding EOL/NOP), then other SAFE
   options; inserts NOP padding only where alignment requires; appends EOL; zero-fills to an even
   length.
3. Reserve the leading OCS slot (Kind + Length + two zero bytes) as the first content and record its
   offset for the Step 6 back-patch.
4. Emit the extended length form when a value is large enough to need it.
5. Tests: serialize -> parse round-trip; canonical ordering; even total length; a golden-byte layout.

## Tasks

- [ ] Builder API and ordering.
- [ ] NOP alignment, EOL, zero-fill to even length.
- [ ] Extended-length emission.
- [ ] Tests: serialize->parse round-trip; golden-byte layout.

## Definition of Done

- A mixed option set round-trips serialize->parse; the output begins with the must-support options in
  canonical order, has even length, and matches a hand-laid-out golden buffer.
