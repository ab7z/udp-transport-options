# Step 13: Two-tier API + error types

Status: done

## Goal

Expose the library through a low-level and a high-level API, with finalized error types.

## Requirements

- Low-level API: set and read explicit options on individual datagrams.
- High-level peer: send and receive payloads with typed options, applying the OCS and
  fragmentation/reassembly transparently.
- Finalized `thiserror` error types across parse / receive / socket layers.
- Documented public API (`cargo doc` builds cleanly).

## Lean verification

Spec first, then implement, then prove (see `LEAN_RFC9868_VALIDATION.md`).

Spec (before implementation): the high-level send/receive as compositions of the already-specified
pieces -- send = serialize + OCS (+ split when the payload needs it), receive = pipeline
(+ reassembly). The socket layer is excluded; only the pure composition is in scope.

Theorems (after implementation): an end-to-end round trip -- for well-formed inputs within the MRDS
cap, a high-level send followed by a high-level receive returns the original payload and options.
Most obligations are inherited from Steps 4-6 and 10-12; this step proves the composition, not new
wire rules.

Implemented in `formal/lean-rfc9868/Rfc9868/Api.lean`: the API send path selects a single datagram
when the original tail fits, selects FRAG when it does not, uses the same MRDS gate as the Step 11
split model, and preserves the original reassembled tail/RDOS shape.

## Plan

1. Low-level API: `build_datagram()` builds a single datagram from explicit `RawOption`s, and
   `decode_datagram()` parses a received datagram into payload, successful options, and option
   status reports.
2. High-level peer: `Peer` wraps the raw sockets, the receive pipeline, and a `ReassemblyCache`;
   `send(payload, options)` applies OCS and auto-fragments when the payload exceeds the configured
   single-datagram capacity; a send whose reassembled size exceeds the peer's MRDS fails before
   emitting fragments; `recv()` reassembles transparently and returns only completed user datagrams.
3. Consolidate socket errors into `SocketError`; add `SendError` for serialize/split/socket/config
   send failures and receive-policy construction errors for non-reportable required options.
4. API tests and property tests cover explicit raw options, typed send options, APC failure status,
   receive policy filtering, auto-FRAG within MRDS, and over-MRDS failure.

## Tasks

- [x] Low-level API surface.
- [x] High-level peer (transparent OCS + FRAG).
- [x] Error-type consolidation.
- [x] Doctests / API docs.

## Definition of Done

- `cargo doc` builds; a high-level send of a payload larger than a single datagram's capacity (but
  within the peer's MRDS) auto-fragments and a high-level receive reassembles it transparently; a
  send whose reassembled size exceeds the peer's MRDS fails with an error.

Verification:

- `cargo fmt --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test`
- `cargo doc --no-deps`
- `scripts/lean-gate.sh`
- `scripts/pre-pr.sh`
