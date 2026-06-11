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

1. Low-level API: build a datagram from explicit `RawOption`s and parse a received datagram into
   payload plus options.
2. High-level peer: wrap the sockets, the pipeline, and the cache; `send(payload, options)` applies
   the OCS and auto-fragments when the payload exceeds the single-datagram capacity (fragment size S
   from the path MTU, MDS as a hint); a send whose reassembled size exceeds the peer's MRDS fails
   with an error; `recv()` reassembles transparently and returns the payload and typed options.
3. Consolidate the `thiserror` error types and document the public surface.
4. Doctests plus a larger-than-one-datagram (within-MRDS) auto-fragment / reassemble round-trip and
   an over-MRDS send that fails with an error.

## Tasks

- [ ] Low-level API surface.
- [ ] High-level peer (transparent OCS + FRAG).
- [ ] Error-type consolidation.
- [ ] Doctests / API docs.

## Definition of Done

- `cargo doc` builds; a high-level send of a payload larger than a single datagram's capacity (but
  within the peer's MRDS) auto-fragments and a high-level receive reassembles it transparently; a
  send whose reassembled size exceeds the peer's MRDS fails with an error.
