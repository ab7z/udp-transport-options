# Step 15: Loopback integration suite

Status: done; predecessor suite verified on achim (Linux, requires CAP_NET_RAW); the 2026-07-13
FRAG/RES remediation passed the achim root lane (`vm-ubuntu-server.sh ignored`) on 2026-08-02

> Current evidence note (2026-07-13): the ignored lane now sends production-generated FRAG
> datagrams through `RawSender`/`RawReceiver` on loopback in terminal/first/rest-reversed order and
> completes reassembly only after the missing fragment arrives. It verifies the original payload,
> successful APC, and the caller-declared previously received RES token. The ordinary supported-
> option socket test also includes RES. The code/build/lint checks passed locally; the required
> `scripts/vm-ubuntu-server.sh ignored` rerun completed green on achim on 2026-08-02 (as the
> pre-PR gate's root lane).

## Goal

Exercise the full send/receive path over loopback in an automated, privilege-gated test suite.

## Requirements

- Integration tests under `tests/` covering: every option, OCS valid/invalid, fragmentation
  (in-order and out-of-order), and malformed surplus areas.
- Tests are `#[ignore]`-gated and skip (do not fail) when the process lacks `CAP_NET_RAW`, so the
  default `cargo test` stays runnable unprivileged.
- A documented privileged lane (`scripts/vm-ubuntu-server.sh ignored` or `setcap`).

## Lean verification

Not applicable: tests are oracles and regressions, not verification targets. The loopback suite is
the empirical complement to the Lean track -- it checks the system path that Lean deliberately
excludes (sockets, kernel, privileges). See `LEAN_RFC9868_VALIDATION.md`.

Note: this suite validates implementation-against-implementation through real sockets. Byte-level
independence from the implementation is the Step 10.5 wire lane (`scripts/vm-ubuntu-server.sh
wire`, `docs/plan/steps/10b-wire-check.md`), which stays alive alongside this suite.

## Plan

1. Add a `tests/` harness with a privilege preflight that skips (does not fail) without
   `CAP_NET_RAW`.
2. Cover each option, OCS valid/invalid, fragmentation in-order and out-of-order, and malformed
   surplus areas.
3. Document the `scripts/vm-ubuntu-server.sh ignored` and `setcap` lanes in the README.

## Tasks

- [x] Integration test harness + privilege preflight.
- [x] Per-option and OCS cases.
- [x] Fragmentation cases.
- [x] Malformed-input cases.
- [x] README documentation of the privileged lane.

## Definition of Done

- The suite passes under `scripts/vm-ubuntu-server.sh ignored` (or `setcap cap_net_raw+ep`), and is
  skipped (not failed) without privilege; the README documents how to run it.
