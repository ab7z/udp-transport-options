# Bidirectional campaign 2026-08-10/11

Crate-side index for the first public-path runs at commit
`7b11140a91ec730bf5d8351e7b00653d41f3c255`. This file is a pointer, not a replacement for the
sealed archives.

## What this run showed

- Equal-size full UDP controls arrived intact at Hetzner over native IPv4 and IPv6.
- With VMware NAT enabled, a typed IPv4 datagram was normalized to `IPv4 IHL + UDP Length` at the
  VMware NAT / macOS VMnet boundary (surplus removed, payload kept).
- Bridging bypassed that local normalization. One native typed IPv4 packet and one native typed
  IPv6 packet were then not observed at Hetzner `eth0`.
- An ephemeral WireGuard-over-IPv6 control delivered the inner typed IPv4 datagram intact after
  decapsulation (26 surplus bytes, valid OCS). That is encapsulation, not native RFC 9868 transit.

## Where the evidence lives

Sealed archives in the companion thesis repository:

- `../mcs-thesis-docs/thesis/evidence/external-campaign-20260810T200118Z.tar.zst`
- `../mcs-thesis-docs/thesis/evidence/bidir-campaign-20260811.tar.zst`

Local working copies (not canonical): `target/external-campaign/20260810T200118Z/` and
`target/bidir-campaign-20260811/`.

## What superseded the "FF2 still open" reading

This pair of runs was the first external data point. It did not complete FF2. Campaigns from
2026-08-13 through 2026-08-16 (P0/P1/P2, Helsinki, AWS US/AP, GCP, hotspot series) are summarized
in [`evaluation.md`](evaluation.md). The companion thesis answers FF2 for the observed pairs,
directions, and windows (chapters 6 and 7).
