# Step 18: RFC 9868 audit remediation

Status: done; full pre-PR gate (18 lanes incl. achim verify/root/wire) green on 2026-08-02

## Goal

Close the concrete endpoint-conformance, public-API, documentation, and evidence gaps recorded in
the RFC 9868 audit at `main@3551fa9`, without claiming external-path FF2 evidence that this step
itself did not measure.

Later note (2026-08-26): public-path campaigns after this step, sealed in the companion thesis
repository, answer FF2 for the observed pairs, directions, and windows. `Peer` still filters the
raw receiver by ports only, so FR-34 remains partial; that gap is documented rather than patched
here.

## Requirements

- Stop option processing at the first unsupported UNSAFE option. Bytes after that point are not
  options and cannot supply a FRAG key. If no FRAG was safely recognized before the UNSAFE option,
  deliver the normal legacy-compatible zero-length datagram and leave unrelated reassembly state
  untouched; a safely recognized FRAG followed by an unsupported UNSAFE remains a fragment-local
  failure with no synthetic zero-length delivery.
- Ensure every high-level FRAG Identification starts from a low-reuse-frequency OS-random seed and
  then advances monotonically without wrapping. Low-level callers must provide an explicit ID and
  own the RFC 9868 timeout-wide uniqueness precondition.
- Make OCS processing status available at the public receive boundary for the datagram and, after
  reassembly, for the fragment set. Required-OCS policy must accept only successfully processed OCS
  state.
- Delegate RES-token provenance explicitly to callers: a sent RES token must previously have been
  received by that endpoint in REQ. The library does not synthesize RES or retain that state.
- Preserve one reassembly cache per socket pair in the high-level API and document the same
  ownership precondition for the low-level API. Expire entries at the configured timeout boundary.
- Correct the normative documents, conformance matrix, historical step claims, and official Errata
  8834/8708 coverage without presenting local policy as RFC requirement.
- Strengthen the existing evidence with arbitrary fragment permutations, RES receive-socket
  coverage, an Erratum-8834 regression, and an independent wire check over production FRAG-split
  output. Keep FF2 limited to the paths actually measured and make receiver/checker failures fatal.

## Lean verification

Extend the receive-disposition model before the Rust change with the ordering fact that an
unsupported UNSAFE encountered before a later FRAG has the ordinary zero-length disposition; the
later FRAG is not interpreted. Keep the Lean claims explicitly limited to the modeled predicates and
arithmetic rather than Rust byte identity, cache state, or external network behavior.

## Plan

1. Add regression tests and the mirrored Lean disposition for UNSAFE-before-FRAG, then stop the
   pre-scan at that UNSAFE and route invalid UDP lengths through the shared sampled logger.
2. Make low-level Identification explicit, seed high-level peers from OS entropy, and define
   fail-closed exhaustion without wrap.
3. Add datagram/fragment-set OCS reports and required-OCS policy; document delegated RES provenance
   and per-socket-pair cache ownership.
4. Reconcile requirements, architecture, wire format, roadmap, step documents, Lean validation
   claims, README, and the audit with the verified RFC and errata.
5. Close the bounded property/socket/wire/evaluation evidence gaps and run the complete gate.

## Tasks

- [x] UNSAFE ordering, cache-preservation, UDP-length logging, and regressions.
- [x] FRAG Identification API, entropy seed, exhaustion contract, and tests.
- [x] OCS public reporting/policy, RES delegation, cache contract, and tests.
- [x] Normative documentation, matrix, errata, Lean-claim, and audit reconciliation.
- [x] Property, fuzz, receive-socket, production-wire, and FF2 harness evidence.
- [x] Living docs updated and deployed; full pre-PR gate green.

## Definition of Done

- Post-UNSAFE bytes cannot affect parsing or reassembly state; both UNSAFE/FRAG orderings have
  deterministic tests and the receive fuzz/property oracle agrees.
- Default high-level peers no longer restart at a constant Identification; direct fragmentation
  without an explicit caller-managed ID fails; `u32::MAX` is emitted at most once and never wraps.
- `ReceivedDatagram` exposes OCS status for datagram and fragment-set processing, all OCS states and
  required-policy outcomes are tested, and RES provenance is an explicit public precondition.
- The RFC-facing documents and matrix match RFC 9868 plus Errata 8834/8708 and distinguish runtime
  conformance, delegated contracts, local strictness, Lean model scope, and empirical FF2 scope.
- Arbitrary FRAG permutations, both RES receive-socket paths, the valid-then-overrun erratum case,
  and production splitter wire bytes are covered.
- `cargo fmt --check`, clippy with `-D warnings`, all host tests, `cargo doc`, Lean axiom audit,
  achim verify/root/wire lanes, and the configured libFuzzer smoke all pass through
  `scripts/pre-pr.sh`.
