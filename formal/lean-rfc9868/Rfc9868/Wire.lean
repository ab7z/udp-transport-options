import Rfc9868.Checksum

/-!
# Step 02 spec: the wire model (IpRepr, UdpHeader, surplus location)

A manual Lean model of the RFC 9868 wire rules mirrored by `src/wire/{ip,udp,surplus}.rs`
(IPv4-only, matching the project scope cut).

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust
code itself. The coupling to Rust is via shared golden vectors: the `locate_surplus` unit-test
cases and the hand-verified "hello" UDP checksum of the Rust test suite are replicated below as
kernel-checked equalities (`decide`, never `native_decide`).

Model mapping:
- `IpReprS.headerLen` / `transportPayloadLen` ~ `IpRepr::{header_len, transport_payload_len}`
- `parseUdp`                                  ~ `UdpHeader::parse` (length rules only)
- `udpChecksumInputWords`                     ~ the scope of `UdpHeader::compute_checksum`:
   pseudo-header + UDP header (checksum field as zero) + user data, never the surplus area
- `computeUdpChecksum`                        ~ `compute_checksum` incl. the `0 -> 0xFFFF` rule
- `locateSurplus`                             ~ `locate_surplus`
-/

namespace Rfc9868

/-! ## IpRepr (IPv4) -/

/-- The IPv4 fields that the surplus math depends on. Addresses enter only through the
pseudo-header word list. -/
structure IpReprS where
  ihl : Nat
  totalLen : Nat
  deriving DecidableEq, Repr

/-- `IpRepr::header_len`: the IHL counts 4-byte words. -/
def IpReprS.headerLen (ip : IpReprS) : Nat := ip.ihl * 4

/-- `IpRepr::transport_payload_len`: IP Total Length minus the header. -/
def IpReprS.transportPayloadLen (ip : IpReprS) : Nat := ip.totalLen - ip.headerLen

/-- **`header_len = ihl * 4`** — definitional in the model. -/
theorem headerLen_def (ip : IpReprS) : ip.headerLen = ip.ihl * 4 := rfl

/-- **`transport_payload_len = total_len - ihl * 4`** — definitional in the model. -/
theorem transportPayloadLen_def (ip : IpReprS) :
    ip.transportPayloadLen = ip.totalLen - ip.ihl * 4 := rfl

/-- The invariants `IpRepr::parse` establishes before returning (`BadIhl` and `BadIpLength`
rejects): a minimum 5-word header that fits inside the Total Length. Theorems that mirror the
Rust proptest oracles assume them, because the oracle only ever sees parsed datagrams. -/
def IpReprS.Wf (ip : IpReprS) : Prop :=
  5 ≤ ip.ihl ∧ ip.headerLen ≤ ip.totalLen

/-! ## UdpHeader -/

/-- The four UDP header fields. -/
structure UdpHeaderS where
  srcPort : Nat
  dstPort : Nat
  length : Nat
  checksum : Nat
  deriving DecidableEq, Repr

/-- `UdpHeader::parse`, length rules only: needs at least 8 bytes and rejects a UDP Length
below 8 (RFC 768; FR-49 lower bound). -/
def parseUdp (bytes : List Nat) : Option UdpHeaderS :=
  if h : 8 ≤ bytes.length then
    if bytes[4]'(by omega) * 256 + bytes[5]'(by omega) < 8 then none
    else
      some
        { srcPort := bytes[0]'(by omega) * 256 + bytes[1]'(by omega)
          dstPort := bytes[2]'(by omega) * 256 + bytes[3]'(by omega)
          length := bytes[4]'(by omega) * 256 + bytes[5]'(by omega)
          checksum := bytes[6]'(by omega) * 256 + bytes[7]'(by omega) }
  else none

/-- **Parse accepts only buffers of at least 8 bytes.** -/
theorem parseUdp_requires_eight_bytes (bytes : List Nat) (h : bytes.length < 8) :
    parseUdp bytes = none := by
  unfold parseUdp
  rw [dif_neg (by omega)]

/-- **A parsed header has a UDP Length of at least 8** (the below-8 reject rule). -/
theorem parseUdp_length_at_least_eight (bytes : List Nat) (hdr : UdpHeaderS)
    (hp : parseUdp bytes = some hdr) : 8 ≤ hdr.length := by
  unfold parseUdp at hp
  split at hp
  · split at hp
    · exact absurd hp (by simp)
    · cases hp
      dsimp only
      omega
  · exact absurd hp (by simp)

/-- **Parsed fields of byte-valued input are 16-bit values**: the field bounds derive from the
byte-level input, they are not assumed. -/
theorem parseUdp_fields_bounded (bytes : List Nat) (hdr : UdpHeaderS)
    (hb : ∀ b ∈ bytes, b < 256) (hp : parseUdp bytes = some hdr) :
    hdr.srcPort < 65536 ∧ hdr.dstPort < 65536 ∧ hdr.length < 65536 ∧ hdr.checksum < 65536 := by
  unfold parseUdp at hp
  split at hp
  · split at hp
    · exact absurd hp (by simp)
    · cases hp
      rename_i h8 _
      have h0 := hb _ (bytes.getElem_mem (by omega : 0 < bytes.length))
      have h1 := hb _ (bytes.getElem_mem (by omega : 1 < bytes.length))
      have h2 := hb _ (bytes.getElem_mem (by omega : 2 < bytes.length))
      have h3 := hb _ (bytes.getElem_mem (by omega : 3 < bytes.length))
      have h4 := hb _ (bytes.getElem_mem (by omega : 4 < bytes.length))
      have h5 := hb _ (bytes.getElem_mem (by omega : 5 < bytes.length))
      have h6 := hb _ (bytes.getElem_mem (by omega : 6 < bytes.length))
      have h7 := hb _ (bytes.getElem_mem (by omega : 7 < bytes.length))
      refine ⟨?_, ?_, ?_, ?_⟩ <;> dsimp only <;> omega
  · exact absurd hp (by simp)

/-! ## The UDP checksum scope -/

/-- The pseudo-header words: source address, destination address (split into 16-bit words),
protocol 17, and the UDP Length (RFC 768). -/
def pseudoHeaderWords (src dst udpLen : Nat) : List Nat :=
  [src / 65536, src % 65536, dst / 65536, dst % 65536, 17, udpLen]

/-- The full checksum input of `UdpHeader::compute_checksum`: pseudo-header, the UDP header with
the checksum field taken as zero (omitted: zero words do not change a one's-complement sum), and
the user data. The surplus area is structurally absent. -/
def udpChecksumInputWords (src dst : Nat) (hdr : UdpHeaderS) (userData : List Nat) : List Nat :=
  pseudoHeaderWords src dst hdr.length ++ [hdr.srcPort, hdr.dstPort, hdr.length]
    ++ toWords userData

/-- `compute_checksum` including the RFC 768 rule: a computed zero is transmitted as `0xFFFF`. -/
def computeUdpChecksum (src dst : Nat) (hdr : UdpHeaderS) (userData : List Nat) : Nat :=
  if checksumWords (udpChecksumInputWords src dst hdr userData) = 0 then 65535
  else checksumWords (udpChecksumInputWords src dst hdr userData)

/-- **A computed zero is sent as `0xFFFF`.** -/
theorem computed_zero_sent_as_ffff (src dst : Nat) (hdr : UdpHeaderS) (userData : List Nat)
    (h : checksumWords (udpChecksumInputWords src dst hdr userData) = 0) :
    computeUdpChecksum src dst hdr userData = 0xffff := by
  unfold computeUdpChecksum
  rw [if_pos h]

/-- **The transmitted UDP checksum is never zero.** -/
theorem computeUdpChecksum_ne_zero (src dst : Nat) (hdr : UdpHeaderS) (userData : List Nat) :
    computeUdpChecksum src dst hdr userData ≠ 0 := by
  unfold computeUdpChecksum
  split
  · omega
  · assumption

/-- The precondition `UdpHeader::compute_checksum` enforces with a release-mode `assert_eq!`:
the UDP Length covers exactly the header plus the user data. The Lean model is total; this
predicate marks the domain on which it mirrors the Rust function. -/
def UdpHeaderS.covers (hdr : UdpHeaderS) (userData : List Nat) : Prop :=
  hdr.length = 8 + userData.length

/-- The user data of a transport payload (the bytes after the UDP header), cut at the UDP
Length: `payload[..udp_length - 8]`. Everything past it is the surplus area. -/
def userDataOf (hdr : UdpHeaderS) (payloadAfterHeader : List Nat) : List Nat :=
  payloadAfterHeader.take (hdr.length - 8)

/-- The checksum as a function of the whole transport payload: the input is cut at the UDP
Length, exactly as the receive path does. -/
def udpChecksumOfPayload (src dst : Nat) (hdr : UdpHeaderS) (payloadAfterHeader : List Nat) :
    Nat :=
  computeUdpChecksum src dst hdr (userDataOf hdr payloadAfterHeader)

/-- **The checksum covers the user data only, never the surplus area**: for a UDP Length that
covers exactly `userData`, *any* surplus bytes past the UDP Length — none, some, or different
ones — leave the payload-level checksum unchanged. This is the Lean counterpart of the Rust
property test that mutates the surplus bytes and re-checks the checksum; both sides reduce to
the checksum of `userData` *because* the UDP Length cuts the payload there. -/
theorem udp_checksum_ignores_surplus (src dst : Nat) (hdr : UdpHeaderS)
    (userData surplus surplus' : List Nat) (hcov : hdr.covers userData) :
    udpChecksumOfPayload src dst hdr (userData ++ surplus)
      = udpChecksumOfPayload src dst hdr (userData ++ surplus') := by
  unfold udpChecksumOfPayload userDataOf
  have hlen : hdr.length - 8 = userData.length := by
    unfold UdpHeaderS.covers at hcov
    omega
  rw [hlen, List.take_left, List.take_left]

/-- The payload-level checksum with surplus present equals the plain user-data checksum. -/
theorem udpChecksumOfPayload_eq (src dst : Nat) (hdr : UdpHeaderS)
    (userData surplus : List Nat) (hcov : hdr.covers userData) :
    udpChecksumOfPayload src dst hdr (userData ++ surplus)
      = computeUdpChecksum src dst hdr userData := by
  unfold udpChecksumOfPayload userDataOf
  have hlen : hdr.length - 8 = userData.length := by
    unfold UdpHeaderS.covers at hcov
    omega
  rw [hlen, List.take_left]

/-- **Receiver view: data plus the transmitted checksum folds to `0xffff`**, including the
`0x0000 -> 0xFFFF` normalization branch (an instance of the Step 01 theorems). -/
theorem udp_verify_folds_to_ones (src dst : Nat) (hdr : UdpHeaderS) (userData : List Nat)
    (hw : ∀ w ∈ udpChecksumInputWords src dst hdr userData, w < 65536) :
    foldSum (sumWords (udpChecksumInputWords src dst hdr userData
      ++ [computeUdpChecksum src dst hdr userData])) = 65535 := by
  unfold computeUdpChecksum
  exact data_plus_normalized_complement_folds_to_ones _ hw

/-- The word bound of the checksum input derives from byte/field-level well-formedness: 32-bit
addresses, 16-bit header fields, byte-valued user data. Wire-shaped inputs therefore satisfy
the `hw` hypothesis of the verification theorem by construction. -/
theorem udpChecksumInputWords_lt (src dst : Nat) (hdr : UdpHeaderS) (userData : List Nat)
    (hsrc : src < 4294967296) (hdst : dst < 4294967296) (hsp : hdr.srcPort < 65536)
    (hdp : hdr.dstPort < 65536) (hlen : hdr.length < 65536)
    (hdata : ∀ b ∈ userData, b < 256) :
    ∀ w ∈ udpChecksumInputWords src dst hdr userData, w < 65536 := by
  intro w hw
  unfold udpChecksumInputWords at hw
  rcases List.mem_append.mp hw with h | h
  · rcases List.mem_append.mp h with h | h
    · simp only [pseudoHeaderWords, List.mem_cons, List.not_mem_nil, or_false] at h
      rcases h with h | h | h | h | h | h <;> subst h <;> omega
    · simp only [List.mem_cons, List.not_mem_nil, or_false] at h
      rcases h with h | h | h <;> subst h <;> omega
  · exact toWords_lt userData hdata w h

/-- **Receiver view, byte-level inputs**: the verification theorem with the bound derived
instead of assumed. -/
theorem udp_verify_folds_to_ones_bytes (src dst : Nat) (hdr : UdpHeaderS) (userData : List Nat)
    (hsrc : src < 4294967296) (hdst : dst < 4294967296) (hsp : hdr.srcPort < 65536)
    (hdp : hdr.dstPort < 65536) (hlen : hdr.length < 65536)
    (hdata : ∀ b ∈ userData, b < 256) :
    foldSum (sumWords (udpChecksumInputWords src dst hdr userData
      ++ [computeUdpChecksum src dst hdr userData])) = 65535 :=
  udp_verify_folds_to_ones src dst hdr userData
    (udpChecksumInputWords_lt src dst hdr userData hsrc hdst hsp hdp hlen hdata)

/-! ## Surplus location -/

/-- `SurplusLayout`: offset, pad flag, and length of the surplus area. -/
structure SurplusLayoutS where
  startsAt : Nat
  needsPad : Bool
  len : Nat
  deriving DecidableEq, Repr

/-- `SurplusLayout::ocs_at`: past the pad byte when one is present. -/
def SurplusLayoutS.ocsAt (l : SurplusLayoutS) : Nat :=
  l.startsAt + (if l.needsPad then 1 else 0)

/-- `locate_surplus` (RFC 9868 Sections 7 and 8): the surplus is the transport payload past the
UDP Length; `None` when the UDP Length exceeds the payload (FR-49, defensive), when there is no
surplus, or when the area cannot hold the aligned OCS plus any required pad byte. -/
def locateSurplus (ip : IpReprS) (udp : UdpHeaderS) : Option SurplusLayoutS :=
  if udp.length > ip.transportPayloadLen then none
  else if ip.transportPayloadLen - udp.length = 0 then none
  else if ip.transportPayloadLen - udp.length < (ip.headerLen + udp.length) % 2 + 2 then none
  else
    some
      { startsAt := ip.headerLen + udp.length
        needsPad := (ip.headerLen + udp.length) % 2 == 1
        len := ip.transportPayloadLen - udp.length }

/-- Dissection of a successful `locateSurplus`: every field in terms of the inputs. -/
theorem locateSurplus_some_elim {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (hp : locateSurplus ip udp = some l) :
    udp.length ≤ ip.transportPayloadLen
      ∧ l.startsAt = ip.headerLen + udp.length
      ∧ l.needsPad = (l.startsAt % 2 == 1)
      ∧ l.len = ip.transportPayloadLen - udp.length
      ∧ l.startsAt % 2 + 2 ≤ l.len := by
  unfold locateSurplus at hp
  split at hp
  · exact absurd hp (by simp)
  · split at hp
    · exact absurd hp (by simp)
    · split at hp
      · exact absurd hp (by simp)
      · cases hp
        dsimp only
        refine ⟨by omega, rfl, rfl, rfl, by omega⟩

/-! ### Step 02 theorems (docs/plan/steps/02-wire-model.md, "Lean verification"; these are the
Lean counterparts of the proptest oracles in `tests/common/mod.rs`) -/

/-- **The surplus area starts where the UDP datagram ends**: `starts_at = header_len + UDP
Length`. -/
theorem surplus_starts_after_udp {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (hp : locateSurplus ip udp = some l) : l.startsAt = ip.headerLen + udp.length :=
  (locateSurplus_some_elim hp).2.1

/-- **The pad flag is set exactly for an odd natural start.** -/
theorem surplus_pad_iff_odd_start {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (hp : locateSurplus ip udp = some l) : l.needsPad = true ↔ l.startsAt % 2 = 1 := by
  have h := (locateSurplus_some_elim hp).2.2.1
  rw [h]
  simp

/-- **The OCS offset is the start plus the pad byte.** -/
theorem surplus_ocs_at {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (hp : locateSurplus ip udp = some l) : l.ocsAt = l.startsAt + l.startsAt % 2 := by
  have hpad := (locateSurplus_some_elim hp).2.2.1
  unfold SurplusLayoutS.ocsAt
  rw [hpad]
  rcases Nat.mod_two_eq_zero_or_one l.startsAt with h | h <;> simp [h]

/-- **The OCS is always 2-byte aligned** (RFC 9868 Section 8). -/
theorem surplus_ocs_even {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (hp : locateSurplus ip udp = some l) : l.ocsAt % 2 = 0 := by
  rw [surplus_ocs_at hp]
  omega

/-- **The surplus area ends exactly at the IP datagram end**: `starts_at + len = total_len`,
under the parse-time invariant [`IpReprS.Wf`] (the Rust oracle re-derives this from a buffer
that `IpRepr::parse` accepted, so the invariant holds there by construction). -/
theorem surplus_ends_at_datagram_end {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (wf : ip.Wf) (hp : locateSurplus ip udp = some l) :
    l.startsAt + l.len = ip.totalLen := by
  have h := locateSurplus_some_elim hp
  have htpl : ip.transportPayloadLen = ip.totalLen - ip.headerLen := rfl
  have hwf := wf.2
  omega

/-- **The OCS field lies fully inside the surplus area**: `ocs_at + 2 <= starts_at + len` (the
"index every claimed range" half of the Rust oracle). -/
theorem surplus_ocs_within {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (hp : locateSurplus ip udp = some l) : l.ocsAt + 2 ≤ l.startsAt + l.len := by
  have h1 := surplus_ocs_at hp
  have h2 := (locateSurplus_some_elim hp).2.2.2.2
  omega

/-- **The area always holds the pad plus the 2-byte OCS**: `len >= pad + 2`. -/
theorem surplus_holds_aligned_ocs {ip : IpReprS} {udp : UdpHeaderS} {l : SurplusLayoutS}
    (hp : locateSurplus ip udp = some l) :
    l.len ≥ (if l.needsPad then 1 else 0) + 2 := by
  have h := locateSurplus_some_elim hp
  have hpad := h.2.2.1
  rw [hpad]
  rcases Nat.mod_two_eq_zero_or_one l.startsAt with h2 | h2 <;> simp [h2] <;> omega

/-- **Completeness of the `None` cases**: a layout exists exactly when the UDP Length fits the
transport payload and the surplus can hold the aligned OCS (pad + 2 bytes); this subsumes the
no-surplus case. -/
theorem locateSurplus_isSome_iff (ip : IpReprS) (udp : UdpHeaderS) :
    (locateSurplus ip udp).isSome
      ↔ udp.length ≤ ip.transportPayloadLen
        ∧ (ip.headerLen + udp.length) % 2 + 2 ≤ ip.transportPayloadLen - udp.length := by
  unfold locateSurplus
  constructor
  · intro h
    split at h
    · simp at h
    · split at h
      · simp at h
      · split at h
        · simp at h
        · rename_i h1 h2 h3
          omega
  · intro ⟨h1, h2⟩
    rw [if_neg (by omega), if_neg (by omega), if_neg (by omega)]
    simp

/-! ## Golden vectors (mirroring the Rust unit tests; all kernel-checked) -/

/-- `surplus.rs::tests::even_natural_start`: header 20 + UDP Length 12 -> start 32, no pad. -/
theorem vector_even_natural_start :
    locateSurplus ⟨5, 36⟩ ⟨12345, 53, 12, 0⟩
      = some { startsAt := 32, needsPad := false, len := 4 } := by decide

/-- `surplus.rs::tests::odd_natural_start_pads_one_byte`: start 33 (odd) -> pad, OCS at 34. -/
theorem vector_odd_natural_start :
    locateSurplus ⟨5, 38⟩ ⟨12345, 53, 13, 0⟩
      = some { startsAt := 33, needsPad := true, len := 5 } := by decide

/-- `surplus.rs::tests::none_when_udp_length_fills_payload`. -/
theorem vector_none_when_udp_fills_payload :
    locateSurplus ⟨5, 33⟩ ⟨12345, 53, 13, 0⟩ = none := by decide

/-- `surplus.rs::tests::none_when_udp_length_exceeds_payload` (FR-49, defensive). -/
theorem vector_none_when_udp_exceeds_payload :
    locateSurplus ⟨5, 30⟩ ⟨12345, 53, 13, 0⟩ = none := by decide

/-- `surplus.rs::tests::none_when_no_room_for_aligned_ocs`: even start, surplus 1. -/
theorem vector_none_no_room_even :
    locateSurplus ⟨5, 33⟩ ⟨12345, 53, 12, 0⟩ = none := by decide

/-- `surplus.rs::tests::none_when_no_room_for_aligned_ocs`: odd start, surplus 2 (pad + OCS do
not fit). -/
theorem vector_none_no_room_odd :
    locateSurplus ⟨5, 35⟩ ⟨12345, 53, 13, 0⟩ = none := by decide

/-- `surplus.rs::tests::none_when_no_room_for_aligned_ocs`: odd start, surplus 3 (pad + OCS fit
exactly). -/
theorem vector_odd_minimal_fit :
    locateSurplus ⟨5, 36⟩ ⟨12345, 53, 13, 0⟩
      = some { startsAt := 33, needsPad := true, len := 3 } := by decide

/-- `surplus.rs::tests::even_minimal_surplus_holds_ocs_exactly`: surplus 2 is a valid layout. -/
theorem vector_even_minimal_fit :
    locateSurplus ⟨5, 34⟩ ⟨12345, 53, 12, 0⟩
      = some { startsAt := 32, needsPad := false, len := 2 } := by decide

/-- `surplus.rs::tests::v4_ip_options_shift_natural_start`: IHL 6 keeps the start even (an IPv4
header length is a multiple of 4). -/
theorem vector_ihl_shift :
    locateSurplus ⟨6, 40⟩ ⟨12345, 53, 12, 0⟩
      = some { startsAt := 36, needsPad := false, len := 4 } := by decide

/-- `udp.rs::tests::checksum_matches_known_good_v4_datagram`: the hand-verified "hello" datagram
(src 192.0.2.1, dst 198.51.100.2, ports 12345 -> 53, UDP Length 13, odd-length payload): folded
sum `0x60a3`. -/
theorem vector_hello_sum :
    sumWords (udpChecksumInputWords 0xC0000201 0xC6336402 ⟨12345, 53, 13, 0x9f5c⟩
      [0x68, 0x65, 0x6c, 0x6c, 0x6f]) = 0x60a3 := by decide

/-- The "hello" datagram's transmitted checksum is `0x9f5c`, as receiver-side verified on Linux
and asserted by the Rust test. -/
theorem vector_hello_checksum :
    computeUdpChecksum 0xC0000201 0xC6336402 ⟨12345, 53, 13, 0x9f5c⟩
      [0x68, 0x65, 0x6c, 0x6c, 0x6f] = 0x9f5c := by
  unfold computeUdpChecksum
  rw [checksumWords, complement16, vector_hello_sum, foldSum_eq_self (by omega)]
  simp

/-- `ip.rs::tests`: the "hello" pseudo-header sum is `0xec55` (mirrors the Rust golden value of
`pseudo_header_sum`). -/
theorem vector_hello_pseudo_sum :
    sumWords (pseudoHeaderWords 0xC0000201 0xC6336402 13) = 0xec55 := by decide

/-- `udp.rs::tests::computed_zero_transmits_as_ffff`: the crafted two-byte payload `[0xe3, 0x34]`
drives the folded sum to `0xffff` (complement zero). -/
theorem vector_computed_zero_sum :
    sumWords (udpChecksumInputWords 0xC0000201 0xC6336402 ⟨12345, 53, 10, 0⟩
      [0xe3, 0x34]) = 0xffff := by decide

/-- ... and the transmitted checksum for it is `0xFFFF`, never the computed `0`. -/
theorem vector_computed_zero_transmits_ffff :
    computeUdpChecksum 0xC0000201 0xC6336402 ⟨12345, 53, 10, 0⟩ [0xe3, 0x34] = 0xffff := by
  apply computed_zero_sent_as_ffff
  rw [checksumWords, complement16, vector_computed_zero_sum, foldSum_eq_self (by omega)]

/-- `tests/fuzz_regressions.rs::seed_udp_checksums_match_independent_computation`: the
`v4_hello_surplus_even` seed (user data "hell", UDP Length 12) checksums to `0x0e5f`
(independently computed in Python). -/
theorem vector_surplus_even_checksum :
    computeUdpChecksum 0xC0000201 0xC6336402 ⟨12345, 53, 12, 0x0e5f⟩
      [0x68, 0x65, 0x6c, 0x6c] = 0x0e5f := by
  unfold computeUdpChecksum
  rw [checksumWords, complement16,
    show sumWords (udpChecksumInputWords 0xC0000201 0xC6336402 ⟨12345, 53, 12, 0x0e5f⟩
      [0x68, 0x65, 0x6c, 0x6c]) = 0xf1a0 from by decide,
    foldSum_eq_self (by omega)]
  simp

/-- The same seed at payload level, *with its real surplus bytes `01 02 03 04` present*: the
payload-level checksum still equals `0x0e5f` — the surplus does not enter the sum (the
kernel-checked instance of `udp_checksum_ignores_surplus` on the actual regression datagram). -/
theorem vector_surplus_even_payload_checksum :
    udpChecksumOfPayload 0xC0000201 0xC6336402 ⟨12345, 53, 12, 0x0e5f⟩
      [0x68, 0x65, 0x6c, 0x6c, 0x01, 0x02, 0x03, 0x04] = 0x0e5f := by
  rw [show ([0x68, 0x65, 0x6c, 0x6c, 0x01, 0x02, 0x03, 0x04] : List Nat)
      = [0x68, 0x65, 0x6c, 0x6c] ++ [0x01, 0x02, 0x03, 0x04] from rfl,
    udpChecksumOfPayload_eq _ _ _ _ _ (by unfold UdpHeaderS.covers; rfl)]
  exact vector_surplus_even_checksum

end Rfc9868
