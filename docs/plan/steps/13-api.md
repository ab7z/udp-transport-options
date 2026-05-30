# Step 13: Two-tier API + error types

Status: pending

## Goal

Expose the library through a low-level and a high-level API, with finalized error types.

## Requirements

- Low-level API: set and read explicit options on individual datagrams.
- High-level peer: send and receive payloads with typed options, applying the OCS and
  fragmentation/reassembly transparently.
- Finalized `thiserror` error types across parse / receive / socket layers.
- Documented public API (`cargo doc` builds cleanly).

## Plan

To be detailed when the step starts (composes Steps 5-12).

## Tasks

- [ ] Low-level API surface.
- [ ] High-level peer (transparent OCS + FRAG).
- [ ] Error-type consolidation.
- [ ] Doctests / API docs.

## Definition of Done

- `cargo doc` builds; a high-level send of a payload larger than MRDS auto-fragments and a high-level
  receive reassembles it transparently.
