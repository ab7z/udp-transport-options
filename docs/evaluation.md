# FF2/P2 Evaluation Runbook

This runbook describes the reproducible Linux lanes for measuring whether RFC 9868 UDP surplus bytes
survive a path. The endpoint implementation is the Step 14 CLI pair; tcpdump pcaps are the path
evidence; `scripts/eval-check.py` compares sender and receiver captures. These are controlled local
experiments, not measurements over real external paths.

## What The Verdicts Mean

The checker classifies one destination-port-tagged scenario at a time:

- `intact`: receiver-side capture contains the same surplus bytes as the sender-side capture.
- `surplus-stripped`: sender-side capture had surplus bytes, while receiver-side IP Total Length
  ends at UDP Length.
- `packet-count-mismatch`: both sides captured traffic for the scenario, but the packet counts differ.
- `sender-surplus-missing`: a scenario that is meant to exercise UDP surplus/options produced at
  least one sender-side packet without surplus; this is a harness failure, not a path result.
- `modified`: sender-side and receiver-side surplus bytes differ.
- `dropped`: sender-side capture exists, but no receiver-side packet was captured.
- `never-captured`: no sender-side packet was captured, so the experiment did not prove a send.

IPv4 fragments are rejected by the checker instead of being guessed. The controlled lanes keep every
emitted IP datagram within the veth MTU and use RFC 9868 FRAG for larger logical payloads, so IP
fragmentation would indicate that the runbook has been adapted to a different path and needs a
separate reassembly-aware oracle.

Wireshark/tshark is useful for IPv4 and UDP fields only. As recorded in Step 10.5, tshark 4.6 has no
RFC 9868 UDP-options dissector; the surplus bytes are the raw bytes after the UDP Length extent, and
the Step 10.5 `scripts/wire-check.py` checker is the independent options-level oracle. The evaluation
checker is narrower: it classifies path survival by comparing captured surplus byte strings and
packet counts; it does not independently validate OCS, TLV semantics, FRAG fields, reassembly, or
application delivery.

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

Since Step 18 the lane is fail-closed end to end: `eval-run.sh` aborts a scenario when the
receiver process exits non-zero, and `eval-check.py` — beyond the pcap verdicts — validates the
full sender-side surplus grammar (pre-OCS pad, OCS recomputation, TLV order, APC CRC32C, FRAG
geometry) and correlates the sender manifests with the receiver JSON records. On `veth` and
`router` every manifest payload must reappear as a receiver delivery record; on `nat` receiver
records are validated but full delivery is not required; on `filter` any receiver record fails
the run. A passing `veth`/`router` run therefore also attests that the receiving endpoint
accepted or reassembled each expected payload.

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

There is no implemented tunnel topology or tunnel script. Conceptually, a future tunnel case must
not be treated as proof that on-path devices handled UDP surplus: a tunnel encapsulates the original
IP packet, so those devices see tunnel traffic rather than the inner UDP surplus. Such a lane would
be an encapsulation/MTU control only.

The `filter` topology drops the complete experiment port range. It is a negative control for the
capture/verdict machinery, not a surplus-specific filtering experiment. None of the current lanes
intentionally strips or rewrites only the surplus area. The veth/router/NAT/filter results establish
reproducible behavior for those local Linux topologies; real external paths and diverse
middleboxes remain future FF2 work.

## FF1 Soll-Ist Hook

For the thesis checklist, use `docs/requirements.md` as the "soll" side:

- endpoint wire/state-machine requirements and their remaining partial/delegated items are mapped
  in `docs/requirements.md`; unit/property/fuzz/Lean cover their stated subsets;
- raw-socket send/receive is partial-in-userspace because it requires Linux and `CAP_NET_RAW`;
- network-path survival is not enforceable by endpoint code and is measured empirically here.
