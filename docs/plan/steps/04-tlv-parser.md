# Step 4: Zero-copy TLV parser

Status: pending

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
- Count consecutive NOPs so the pipeline can apply the >7-NOP DoS policy (Step 10).
- No panic on any input; no allocation.

## Plan

To be detailed when the step starts.

## Tasks

- [ ] Implement the iterator with framing + bounds validation.
- [ ] Extended-length handling.
- [ ] NOP-run counting surfaced to the caller.
- [ ] Tests: valid mixed options; truncated; overrun; bad extended length; random inputs do not panic.

## Definition of Done

- The iterator yields the correct `OptionRef`s for hand-built surplus areas; each malformed case
  produces exactly one `Err` then halts; a loop over many random inputs never panics.
