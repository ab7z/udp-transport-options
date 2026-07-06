import Rfc9868.FragSplit
import Rfc9868.Reassembly

/-!
# Step 13 spec: two-tier API composition

This is a small composition model for the public API layer. It deliberately introduces no new wire
rules: low-level send is serialization plus datagram assembly, high-level send is serialization plus
optional FRAG splitting, and high-level receive is the existing pipeline plus reassembly.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored constants, API tests, property tests, and the existing
Step 4-12 model files.
-/

namespace Rfc9868

/-! ## API send composition model -/

inductive ApiSendPath where
  | singleDatagram
  | fragmented
  deriving DecidableEq, Repr

def apiSendPath (payloadLen optionsBodyLen singleDatagramTailCapacity : Nat) : ApiSendPath :=
  if originalTailLen payloadLen optionsBodyLen ≤ singleDatagramTailCapacity then
    ApiSendPath.singleDatagram
  else
    ApiSendPath.fragmented

def apiSendWithinPeerMrds (payloadLen optionsBodyLen peerMrds : Nat) : Prop :=
  withinMrds payloadLen optionsBodyLen peerMrds

def apiFragmentedRoundTripTailLen (payloadLen optionsBodyLen : Nat) : Nat :=
  originalTailLen payloadLen optionsBodyLen

/-! ## Theorems over Step 13 composition -/

/-- **The API keeps small sends on the non-FRAG path.** -/
theorem api_send_uses_single_datagram_when_tail_fits
    (payloadLen optionsBodyLen singleDatagramTailCapacity : Nat)
    (hfit : originalTailLen payloadLen optionsBodyLen ≤ singleDatagramTailCapacity) :
    apiSendPath payloadLen optionsBodyLen singleDatagramTailCapacity = ApiSendPath.singleDatagram := by
  unfold apiSendPath
  simp [hfit]

/-- **The API switches to FRAG when the original tail does not fit one datagram.** -/
theorem api_send_uses_frag_when_tail_exceeds_capacity
    (payloadLen optionsBodyLen singleDatagramTailCapacity : Nat)
    (hover : singleDatagramTailCapacity < originalTailLen payloadLen optionsBodyLen) :
    apiSendPath payloadLen optionsBodyLen singleDatagramTailCapacity = ApiSendPath.fragmented := by
  unfold apiSendPath
  simp [Nat.not_le_of_gt hover]

/-- **The high-level send MRDS gate is exactly the Step 11 reassembled-datagram bound.** -/
theorem api_mrds_gate_matches_frag_split_model
    (payloadLen optionsBodyLen peerMrds : Nat) :
    apiSendWithinPeerMrds payloadLen optionsBodyLen peerMrds ↔
      reassembledDatagramLen payloadLen optionsBodyLen ≤ peerMrds := by
  unfold apiSendWithinPeerMrds withinMrds
  rfl

/-- **The receive side reassembles the original tail shape used by the send-side splitter.** -/
theorem api_fragmented_round_trip_tail_len_matches_original_tail
    (payloadLen optionsBodyLen : Nat) :
    apiFragmentedRoundTripTailLen payloadLen optionsBodyLen =
      payloadLen + originalOptionsPadLen payloadLen optionsBodyLen + optionsBodyLen := by
  unfold apiFragmentedRoundTripTailLen originalTailLen
  rfl

/-- **The reassembled UDP Length remains RDOS: UDP header plus original payload bytes.** -/
theorem api_fragmented_round_trip_udp_length_is_rdos
    (payloadLen : Nat) :
    rdosForPayload payloadLen = fragUdpHeaderLength + payloadLen := by
  exact rdos_is_original_udp_length payloadLen

end Rfc9868
