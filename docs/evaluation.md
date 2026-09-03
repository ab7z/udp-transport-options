# FF2/P2 Evaluation Runbook

This runbook describes the reproducible Linux lanes for measuring whether RFC 9868 UDP surplus bytes
survive a path. The endpoint implementation is the Step 14 CLI pair; tcpdump pcaps are the path
evidence; `scripts/eval-check.py` compares sender and receiver captures. These are controlled local
experiments. The separate external campaign described below reuses the same evidence principles but
is not a committed, reproducible lane of this runbook.

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

There is no implemented tunnel topology or tunnel script in the reproducible repository lanes. A
tunnel result must not be treated as proof that on-path devices handled UDP surplus: a tunnel
encapsulates the original IP packet, so those devices see tunnel traffic rather than the inner UDP
surplus. Such a result is an encapsulation/MTU control only.

The `filter` topology drops the complete experiment port range. It is a negative control for the
capture/verdict machinery, not a surplus-specific filtering experiment. None of the current lanes
intentionally strips or rewrites only the surplus area. The veth/router/NAT/filter results establish
reproducible behavior for those local Linux topologies. External public-path campaigns are summarized
below; they are not committed, turnkey lanes of this runbook.

## External Campaign: 2026-08-10/11

Campaign `20260810T200118Z` measured a Linux guest to a Hetzner host using repository commit
`7b11140a91ec730bf5d8351e7b00653d41f3c255`. It recorded sender-side, local Mac, and Hetzner
captures. The campaign is an initial external data point, not a new completed roadmap step.

The equal-size full UDP controls arrived intact at Hetzner over native IPv4 and native IPv6. In the
IPv4 control, both compared datagrams had IPv4 Total Length 58. The full datagram used UDP Length 38
with 30 payload bytes. The typed RFC 9868 datagram used UDP Length 12 with four payload bytes and a
26-byte surplus area. Both IPv6 probes used IPv6 Payload Length 38. The equal IP sizes exclude
packet size alone as the cause of the typed packets' different treatment. The IPv6 probe was a
campaign-only wire diagnostic and does not extend the crate's IPv4-only endpoint scope.

With VMware NAT enabled, the typed IPv4 datagram was intact before the local NAT boundary. After
that boundary, IPv4 Total Length was exactly `IPv4 IHL + UDP Length`: 32 bytes instead of 58, with
the four UDP payload bytes preserved and the 26 surplus bytes absent. The evidence places this
normalization at the VMware NAT/macOS VMnet boundary, but it cannot distinguish `vmnet-natd` from
the macOS VMnet API internally.

Bridging the guest directly to the physical network bypassed that normalization. The typed IPv4
datagram and a separate typed IPv6 datagram both retained the same 26 surplus bytes in the guest and
local `en0` captures. One typed packet of each IP version was not observed in the corresponding
Hetzner `eth0` capture, while its equal-size full UDP control arrived. This localizes loss to an
interval after `en0` and before Hetzner `eth0`; a single packet per IP version does not identify the
public device or provider that dropped it.

An ephemeral WireGuard control then carried the inner IPv4 datagrams over native outer IPv6. The
typed inner datagram was observed intact on Hetzner `wg-uoe`, with the same 26-byte surplus area and
a valid OCS. This proves that encapsulation can deliver a non-empty surplus area to the Hetzner host
after decapsulation. It does not prove that the public path carried native RFC 9868 UDP, because the
on-path devices saw WireGuard traffic instead of the inner datagram.

These observations provided the first FF2 boundaries. They did not by themselves complete FF2.

## Later public-path campaigns (2026-08-13 through 2026-08-16)

Drivers: `scripts/p0-campaign.sh`, `scripts/p1-campaign.sh`, `scripts/p2-campaign.sh`,
`scripts/pair-campaign.sh`, `scripts/checksumgate-cell.sh`. Binary source of the main suites:
`d7187eb` (NAT-split support `9d6c5bd`). Sealed archives and the thesis write-up live in
`../mcs-thesis-docs/thesis/evidence/` and thesis chapters 6 and 7.

Measured pairs included 1blu-mcs, mcs-helsinki, helsinki-1blu, aws-mcs, aws-hel, aws-1blu, GCP
us-east1 against mcs/1blu, six AWS AP regions, and a Telefónica iPhone-hotspot path (NAT and
bridged). The P0/P1/P2 suite ran on the six full host pairs (18 driver scenarios; S-51 was
deliberately dropped).

Three mechanism classes showed up:

- **Normalizer:** VMware NAT/VMnet rewrote `IPv4 Total Length` to `IHL + UDP Length` and could
  deliver empty 28-byte shells for atomic FRAG datagrams.
- **Checksum gate:** some provider edges delivered a surplus datagram only when a legacy
  one's-complement sum over the pseudo-header and the entire IP payload folded to `0xFFFF` (or
  the UDP checksum was zero). RFC-correct OCS with a non-zero pad failed those edges; a
  compensated OCS passed. Observed at Hetzner both ways and at 1blu ingress; not at Amazon.
- **Presence dropper:** some paths dropped every datagram with `UDP Length < IP payload`,
  independent of option content (Telefónica hotspot both ways after bridging; Google Andromeda;
  source-dependent AP transits toward Tokyo/Seoul/Sydney).

The EU cloud triangle and AWS-US transatlantic pairs preserved a well-formed surplus with a zero
pad. The companion thesis answers FF2 for those observed pairs, directions, and windows. Claims
are not Internet-wide. This crate still has no committed tunnel lane or surplus-only rewriting
middlebox.

## FF1 Soll-Ist Hook

For the thesis checklist, use `docs/requirements.md` as the "soll" side:

- endpoint wire/state-machine requirements and their remaining partial/delegated items are mapped
  in `docs/requirements.md`; unit/property/fuzz/Lean cover their stated subsets;
- raw-socket send/receive is partial-in-userspace because it requires Linux and `CAP_NET_RAW`;
- network-path survival is not enforceable by endpoint code and is measured empirically here.
