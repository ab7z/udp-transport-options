# Step 15: Loopback integration suite

Status: pending (Linux, requires CAP_NET_RAW)

## Goal

Exercise the full send/receive path over loopback in an automated, privilege-gated test suite.

## Requirements

- Integration tests under `tests/` covering: every option, OCS valid/invalid, fragmentation
  (in-order and out-of-order), and malformed surplus areas.
- Tests are `#[ignore]`-gated and skip (do not fail) when the process lacks `CAP_NET_RAW`, so the
  default `cargo test` stays runnable unprivileged.
- A documented privileged lane (`sudo -E cargo test -- --ignored` or `setcap`).

## Plan

To be detailed when the step starts.

## Tasks

- [ ] Integration test harness + privilege preflight.
- [ ] Per-option and OCS cases.
- [ ] Fragmentation cases.
- [ ] Malformed-input cases.
- [ ] README documentation of the privileged lane.

## Definition of Done

- The suite passes under `sudo -E cargo test -- --ignored` (or `setcap cap_net_raw+ep`), and is
  skipped (not failed) without privilege; the README documents how to run it.
