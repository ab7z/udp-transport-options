# Step 5: Option serializer

Status: implemented

## Goal

Serialize a set of options into a surplus area with correct ordering, alignment, and termination.

## Requirements

- `OptionsBuilder` accepting owned `RawOption`s and emitting their wire bytes. Typed option codecs
  are added in Step 7.
- Must-support options emitted before other SAFE options (canonical order).
- NOP used only for inter-option 2-byte alignment before real TLVs; EOL terminates; the remainder is
  zero-filled to a 2-byte boundary so the OCS-led body length is even (a builder canonicalization --
  the RFC only requires EOL plus zero-fill to the end of the chosen area, RFC 9868 Sec. 11.1).
- The extended length form emitted when `value_len >= 253`, because default TLV length is the total
  option length and its largest encodable value is 252 bytes.
- The leading two-byte OCS field is reserved here and back-patched in Step 6. The OCS is positional,
  not a TLV: a bare two-byte slot with no Kind and no Length octet (RFC 9868 Sec. 8). The optional
  pre-OCS pad byte for odd surplus starts is handled by the wire/send layer, not by this builder.

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): the canonical OCS-led body encoding -- FRAG first when present, then
the other must-support TLVs, then unassigned SAFE `Other` options; NOP only for inter-option TLV
alignment; EOL then zero-fill to an even body length; the smallest length form (`value_len <= 252`
default, extended above); the leading two-byte OCS slot is positional, not a TLV; FRAG Start is
patched from the final body length.

Theorems (after implementation): the serializer model's output is well-formed under the Step 4
grammar for representative boundary cases; the evenness invariant holds for every modeled input;
canonical reordering is exercised on non-canonical input; small round-trip and extended-boundary
cases are kernel-checked without `native_decide`.

## Plan

1. `OptionsBuilder` accumulates owned `RawOption`s; Step 7 adds typed option encoding later.
2. `finish()` validates the input (`EOL`/`NOP` are builder-owned, UNSAFE and assigned/reserved
   out-of-scope SAFE Kinds are rejected, lengths are checked, known fixed-size option values must
   have RFC-valid lengths, and FRAG may appear at most once), emits FRAG first when present, then
   other must-support TLVs, then unassigned SAFE `Other` options.
3. Insert NOP padding only before a real TLV that would otherwise start at an odd body offset; append
   EOL; zero-fill to an even OCS-led body length; patch FRAG Start to the final fragment-data offset.
4. Reserve the leading OCS slot (a bare two-byte field, zeroed; no Kind/Length framing) as `body[0..2]`
   for the Step 6 back-patch.
5. Emit default TLVs for `value_len <= 252`; emit Extended Length for `value_len >= 253`; return
   `SerializeError` rather than panicking when a value/body is too large, a fixed-size value has the
   wrong length, FRAG is duplicated, or FRAG Start cannot be represented.
6. Tests: serialize -> parse round-trip; canonical ordering; even body length; golden-byte layout;
   property tests, fuzz target, and Lean serializer model.

## Tasks

- [x] Builder API and ordering.
- [x] NOP alignment, EOL, zero-fill to even length.
- [x] Extended-length emission.
- [x] Tests: serialize->parse round-trip; golden-byte layout; property/fuzz/Lean coverage.

## Definition of Done

- A mixed option set round-trips serialize->parse; the output begins with `body[0..2] == 0`, orders
  FRAG and must-support SAFE options canonically, has even body length, matches a hand-laid-out
  golden buffer, is covered by a property test and an `options_serialize` fuzz target, and the Lean
  gate proves the Step 5 serializer model's ordering, boundary, and evenness cases.
