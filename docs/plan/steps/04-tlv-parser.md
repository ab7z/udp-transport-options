# Step 4: Zero-copy TLV parser

Status: done

## Goal

Parse the options in a surplus area as a zero-copy, total, panic-free iterator of borrowed
`OptionRef` values.

## Requirements

- `OptionsIter<'a>` yielding `Result<OptionRef<'a>, ParseError>` over the bytes after the OCS field
  (and after any odd-start pad).
- EOL terminates iteration; NOP is a one-byte option; the extended length form (`Length == 255`) is
  handled.
- Strict bounds and length validation: a truncated header, an option that overruns the surplus, or a
  malformed extended length yields exactly one `Err` and then stops.
- No option-specific APC/FRAG/MDS/MRDS/REQ/RES length validation in this step; fixed-length typed
  decoding remains Step 7, and receive disposition remains Step 10.
- Count consecutive NOPs so the pipeline can apply the >7-NOP DoS policy (Step 10).
- No panic on any input; no allocation.

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): the TLV grammar over the bytes after the OCS -- EOL terminates, NOP
is one byte, every other Kind carries Length (with `255` selecting the extended 2-byte form); the
minimum-length and bounds rules of RFC 9868 Sec. 10, with an option running past the surplus area
being malformed per Erratum 8834 (all options discarded, payload still delivered -- the pipeline
disposition, Step 10).

Theorems (after implementation): the Lean parser model reduces every input to a stopped trace (the
Lean analogue of "never panics"); representative default TLVs are yielded in stream order; any
`parseOne` framing error yields exactly one error and ends the loop; EOL terminates the stream; NOP
advances the NOP run; strict Extended Length rejects values below 255 and advances valid extended
TLVs by the 16-bit total length. Serializer round-trip proof belongs to Step 5, where the serializer
is introduced.

## Plan

1. `OptionsIter::new(bytes_after_ocs)` tracking `pos`, a `done` flag, and a consecutive-NOP counter.
2. Each `next()`: read Kind; EOL sets `done` and stops; NOP consumes one byte and increments the NOP
   run; otherwise read Length (and the extended form when `Length == 255`), check `len >= 2` and
   `pos + len <= end`, slice the value, and reset the NOP run.
3. On any framing or bounds violation, yield exactly one `Err(ParseError::...)` and set `done`.
4. Expose the maximum NOP run so the pipeline can apply the DoS policy (Step 10).
5. Tests: valid mixed options; truncated header; overrunning length; bad extended length; a loop over
   many random inputs asserting no panic.

## Tasks

- [x] Implement the iterator with framing + bounds validation.
- [x] Extended-length handling.
- [x] NOP-run counting surfaced to the caller.
- [x] Tests: valid mixed options; truncated; overrun; bad extended length; random inputs do not panic.

## Definition of Done

- The iterator yields the correct `OptionRef`s for hand-built surplus areas; each malformed case
  produces exactly one `Err` then halts; a loop over many random inputs never panics.
