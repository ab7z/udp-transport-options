# FF2/P2 Evaluation Runbook

This runbook describes the reproducible Linux lanes for measuring whether RFC 9868 UDP surplus bytes
survive a path. The endpoint implementation is the Step 14 CLI pair; tcpdump pcaps are the path
evidence; `scripts/eval-check.py` compares sender and receiver captures.

## What The Verdicts Mean

The checker classifies one destination-port-tagged scenario at a time:

- `intact`: receiver-side capture contains the same surplus bytes as the sender-side capture.
- `surplus-stripped`: sender-side capture had surplus bytes, while receiver-side IP Total Length
  ends at UDP Length.
- `packet-count-mismatch`: both sides captured traffic for the scenario, but the packet counts differ.
- `modified`: sender-side and receiver-side surplus bytes differ.
- `dropped`: sender-side capture exists, but no receiver-side packet was captured.
- `never-captured`: no sender-side packet was captured, so the experiment did not prove a send.

IPv4 fragments are rejected by the checker instead of being guessed. The controlled lanes keep every
emitted IP datagram within the veth MTU and use RFC 9868 FRAG for larger logical payloads, so IP
fragmentation would indicate that the runbook has been adapted to a different path and needs a
separate reassembly-aware oracle.

Wireshark/tshark is useful for IPv4 and UDP fields only. As recorded in Step 10.5, tshark 4.6 has no
RFC 9868 UDP-options dissector; the surplus bytes are the raw bytes after the UDP Length extent, and
the project checker is the options-level oracle.

## Prerequisites

The raw-socket sender, receiver, namespace setup, and tcpdump captures require Linux with root or
`CAP_NET_RAW`. The namespace lanes also need `iproute2`, `ethtool`, `nft`, `tcpdump`, and `python3`.
The achim workflow checks and syncs these through:

```sh
scripts/vm-ubuntu-server.sh bootstrap
```

The evaluation scripts disable common offloads on every veth endpoint with best-effort
`ethtool -K ... tx off rx off gso off tso off gro off`. Keep this step when adapting the runbook to
real NICs; otherwise a capture can show deferred checksums or coalesced packets rather than the
bytes the peer actually receives.

## Quick Start On achim

Run the direct veth baseline:

```sh
scripts/vm-ubuntu-server.sh eval veth
```

Run the routed, NAT, and filter topologies:

```sh
scripts/vm-ubuntu-server.sh eval router
scripts/vm-ubuntu-server.sh eval nat
scripts/vm-ubuntu-server.sh eval filter
```

Each run writes artifacts under `/tmp/uoe-<epoch>/` on achim:

- `sender.pcap` and `receiver.pcap`
- `*.tcpdump.log`
- `send-*.jsonl` and `recv-*.jsonl`
- `verdicts.jsonl`

The direct `veth` and plain `router` topologies are the controlled "no middlebox strips surplus"
baselines. `nat` measures Linux nftables masquerade behavior. `filter` intentionally drops the
experiment UDP port range and is the negative path-control case.

## Scenarios

The run uses one destination port per scenario, starting at 41000:

| Port | Scenario | Purpose |
|---:|---|---|
| 41000 | baseline, no options | path liveness with no surplus |
| 41001 | APC + MDS(1472) + MRDS + REQ | typed must-support options |
| 41002 | odd payload + REQ | odd surplus start and pre-OCS pad |
| 41003 | near-MTU payload + APC/MDS(1472) | MTU-adjacent surplus survival |
| 41004 | auto-FRAG payload | fragment surplus survival and reassembly input |

Large logical payloads are sent with RFC 9868 FRAG, not IP fragmentation. This follows the Step 0.5
finding that Linux `IP_HDRINCL` sends fail with `EMSGSIZE` instead of fragmenting packets that exceed
the link MTU.

## Reading Results

Use `verdicts.jsonl` as the primary machine-readable result. For manual inspection, open the pcaps in
Wireshark and compare:

```text
surplus length = ip.len - ip.hdr_len - udp.length
```

Do not infer stripping from receiver CLI output alone. A delivered payload with no decoded options
can mean "options were stripped", "options were never sent", "OCS failed and options were ignored",
or "the datagram carried no surplus"; the sender and receiver pcaps plus the manifest disambiguate
those cases.

## Scope Limits

The tunnel case is intentionally not treated as proof of middlebox surplus handling. A tunnel
encapsulates the original IP packet, so on-path devices see tunnel traffic rather than the inner UDP
surplus. Tunnel captures are useful for MTU and encapsulation checks, but native or staged NAT/filter
paths are the FF2 evidence for middlebox behavior.

## FF1 Soll-Ist Hook

For the thesis checklist, use `docs/requirements.md` as the "soll" side:

- endpoint wire/state-machine requirements are implemented in the pure modules and validated by
  unit/property/fuzz/Lean where applicable;
- raw-socket send/receive is partial-in-userspace because it requires Linux and `CAP_NET_RAW`;
- network-path survival is not enforceable by endpoint code and is measured empirically here.
