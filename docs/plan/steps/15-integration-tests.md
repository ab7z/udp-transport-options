# Step 15: Loopback integration suite

Status: pending (Linux, requires CAP_NET_RAW)

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

## Plan

1. Add a `tests/` harness with a privilege preflight that skips (does not fail) without
   `CAP_NET_RAW`.
2. Cover each option, OCS valid/invalid, fragmentation in-order and out-of-order, and malformed
   surplus areas.
3. Document the `scripts/vm-ubuntu-server.sh ignored` and `setcap` lanes in the README.

## Tasks

- [ ] Integration test harness + privilege preflight.
- [ ] Per-option and OCS cases.
- [ ] Fragmentation cases.
- [ ] Malformed-input cases.
- [ ] README documentation of the privileged lane.

## Definition of Done

- The suite passes under `scripts/vm-ubuntu-server.sh ignored` (or `setcap cap_net_raw+ep`), and is
  skipped (not failed) without privilege; the README documents how to run it.
