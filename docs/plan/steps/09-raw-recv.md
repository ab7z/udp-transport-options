# Step 9: merged into Step 8

Status: merged into Step 8

## Goal

No separate implementation step. The raw receive socket is implemented and verified together with
the raw send path in Step 8 so the kernel-facing premise is tested as one root-gated round trip.

## Requirements

- Covered by Step 8.

## Lean verification

Covered by Step 8.

## Plan

1. Keep this file as a tombstone so later step numbers remain stable.
2. Implement and verify all raw receive behavior in Step 8.

## Tasks

- [x] Merged into Step 8.

## Definition of Done

- Step 8's Definition of Done covers raw send and raw receive together.
