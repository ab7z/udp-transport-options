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

## Plan

To be detailed when the step starts.

## Tasks

- [ ] `udpopt-send` (options + fragmentation flags).
- [ ] `udpopt-recv` (decode + print).
- [ ] Privilege error handling.
- [ ] Documented loopback demo invocation.

## Definition of Done

- `--help` works for both; a documented loopback invocation sends an option-bearing datagram and the
  receiver prints the decoded options.
