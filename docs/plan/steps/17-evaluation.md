# Step 17: Evaluation runbook + scripts

Status: done; verified on achim (Linux)

## Goal

Provide the reproducible evaluation harness for the thesis's staged network environments (chapter 5).

## Requirements

- Scripts to create the staged environments: network namespaces + veth pairs (local virtualized),
  routed paths, Linux nftables NAT, and Linux nftables filtering. Tunnel behavior is documented as
  an encapsulated control path, not as evidence that on-path middleboxes saw UDP surplus bytes.
- A runbook (README section) describing how to run the integration results across the environments,
  capture at the receiver NIC with `tcpdump`/Wireshark, and read off surplus-area survival and
  middlebox behavior (FF2).
- Capability/preflight notes (`CAP_NET_RAW`, root) and offload-disable notes (`ethtool -K`) for real
  interfaces.
- A short soll-ist (spec vs implementation) checklist supporting FF1.

## Lean verification

Not applicable: FF2 (surplus survival across real paths and middleboxes) is exactly the part Lean
cannot prove and is empirical by design. One hook: the FF1 soll-ist checklist may cite the Lean
theorems as the "soll" side where a requirement was formalized. See `LEAN_RFC9868_VALIDATION.md`.

## Plan

1. Scripts: an `ip netns` plus veth setup, routed/NAT/filter topologies, and a helper to capture at
   the sender and receiver NICs.
2. A runbook (README section) for the staged environments, with `ethtool -K` offload-disable notes
   and the capability requirements.
3. A soll-ist checklist tying results to FF1, plus surplus-survival and middlebox observations for
   FF2.

## Tasks

- [x] `ip netns` + veth setup script.
- [x] Routed, NAT, and filter topology scripts.
- [x] Runbook + capture instructions.
- [x] Soll-ist checklist.

## Definition of Done

- The scripts create the staged environments on a Linux host; the runbook reproduces the integration
  results; the README quick-start is verified end to end. Direct veth and plain routed topologies are
  the controlled intact baselines; NAT/filter topologies produce classified FF2 verdicts.
