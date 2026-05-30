# Step 17: Evaluation runbook + scripts

Status: pending (Linux)

## Goal

Provide the reproducible evaluation harness for the thesis's staged network environments (chapter 5).

## Requirements

- Scripts to create the staged environments: network namespaces + veth pairs (local virtualized) and
  a tunnel-based coupling of two endpoints.
- A runbook (README section) describing how to run the integration results across the environments,
  capture at the receiver NIC with `tcpdump`/Wireshark, and read off surplus-area survival and
  middlebox behavior (FF2).
- Capability/preflight notes (`CAP_NET_RAW`, root) and offload-disable notes (`ethtool -K`) for real
  interfaces.
- A short soll-ist (spec vs implementation) checklist supporting FF1.

## Plan

1. Scripts: an `ip netns` plus veth setup, a tunnel-based coupling, and a helper to capture at the
   receiver NIC.
2. A runbook (README section) for the staged environments, with `ethtool -K` offload-disable notes
   and the capability requirements.
3. A soll-ist checklist tying results to FF1, plus surplus-survival and middlebox observations for
   FF2.

## Tasks

- [ ] `ip netns` + veth setup script.
- [ ] Tunnel coupling script.
- [ ] Runbook + capture instructions.
- [ ] Soll-ist checklist.

## Definition of Done

- The scripts create the staged environments on a Linux host; the runbook reproduces the integration
  results; the README quick-start is verified end to end.
