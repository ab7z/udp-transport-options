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
   the OCS and fragments when needed; `recv()` reassembles transparently and returns the payload and
   typed options.
3. Consolidate the `thiserror` error types and document the public surface.
4. Doctests plus a larger-than-MRDS auto-fragment / reassemble round-trip.

## Tasks

- [ ] Low-level API surface.
- [ ] High-level peer (transparent OCS + FRAG).
- [ ] Error-type consolidation.
- [ ] Doctests / API docs.

## Definition of Done

- `cargo doc` builds; a high-level send of a payload larger than MRDS auto-fragments and a high-level
  receive reassembles it transparently.
