# Step 14: Example peer CLIs

Status: pending (Linux, requires CAP_NET_RAW to run)

## Goal

Provide `udpopt-send` and `udpopt-recv` example peers that exercise the library and generate
evaluation traffic.

## Requirements

- `clap`-based argument parsing for both binaries.
- The sender can attach options (APC, MDS, MRDS) and trigger fragmentation (FRAG) for large payloads.
- The receiver prints the decoded options and the payload.
- A clear, non-panicking error when the process lacks `CAP_NET_RAW`.
- Verbose / hexdump output to support inspection alongside `tcpdump`/Wireshark.

## Lean verification

Not applicable: the CLIs are I/O binaries over the library; the library behavior they exercise is
covered by the specs of Steps 3-13. No Lean obligations; see `LEAN_RFC9868_VALIDATION.md`.

## Plan

1. `udpopt-send`: clap arguments for destination, payload, options (APC, MDS, MRDS), and a
   fragmentation toggle, with verbose hexdump output.
2. `udpopt-recv`: receive, decode, and print the options and payload, with verbose hexdump output.
3. Without privilege, exit non-zero with a clear `PermissionDenied` message.
4. Document a loopback demonstration invocation.

## Tasks

- [ ] `udpopt-send` (options + fragmentation flags).
- [ ] `udpopt-recv` (decode + print).
- [ ] Privilege error handling.
- [ ] Documented loopback demo invocation.

## Definition of Done

- `--help` works for both; a documented loopback invocation sends an option-bearing datagram and the
  receiver prints the decoded options.
