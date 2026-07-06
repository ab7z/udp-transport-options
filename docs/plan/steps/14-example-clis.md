# Step 14: Example peer CLIs

Status: done; verified on achim (Linux, requires CAP_NET_RAW to run)

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

- [x] `udpopt-send` (options + fragmentation flags).
- [x] `udpopt-recv` (decode + print).
- [x] Privilege error handling.
- [x] Documented loopback demo invocation.

## Loopback demo

In one root-capable shell on Linux or achim:

```sh
./bin/udpopt-recv --dst-port 41001 --timeout-ms 5000 --count 1 --json
```

In another shell:

```sh
./bin/udpopt-send --src 127.0.0.1 --dst 127.0.0.1 --src-port 40000 --dst-port 41001 \
  --payload wire --apc --mds 1500 --mrds-size 2926 --req deadbeef --hexdump
```

Through the repository driver, use `scripts/vm-ubuntu-server.sh eval veth` for the same CLI pair as
part of a captured path run.

## Definition of Done

- `--help` works for both; a documented loopback invocation sends an option-bearing datagram and the
  receiver prints the decoded options.
