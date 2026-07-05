import Rfc9868.Kind

/-!
# Step 11 spec: send-side FRAG splitting

This is a small arithmetic model of the Step 11 splitter. It mirrors the Rust split layer, not the
socket layer: the model covers the reassembled tail after the UDP header, the RDOS pointer, the
optional pad before a carried per-datagram options body, and the segment/MRDS bounds.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored unit tests, property tests, and the `frag_split` fuzz
target.
-/

namespace Rfc9868

/-! ## FRAG split model -/

def fragUdpHeaderLength : Nat := 8
def fragOcsLength : Nat := 2
def fragNonTerminalMeasuredBodyLen : Nat := 12
def fragTerminalMeasuredBodyLen : Nat := 14
def mrdsDefaultIpv4 : Nat := 2926
def minReassemblySegments : Nat := 2

def rdosForPayload (payloadLen : Nat) : Nat :=
  fragUdpHeaderLength + payloadLen

def originalOptionsPadLen (payloadLen optionsBodyLen : Nat) : Nat :=
  if optionsBodyLen = 0 then 0
  else if rdosForPayload payloadLen % 2 = 1 then 1
  else 0

def originalTailLen (payloadLen optionsBodyLen : Nat) : Nat :=
  payloadLen + originalOptionsPadLen payloadLen optionsBodyLen + optionsBodyLen

def reassembledDatagramLen (payloadLen optionsBodyLen : Nat) : Nat :=
  fragUdpHeaderLength + originalTailLen payloadLen optionsBodyLen

structure FragmentS where
  fragOffset : Nat
  dataLen : Nat
  terminal : Bool
  rdos : Option Nat
  deriving DecidableEq, Repr

def atomicFragment (payloadLen optionsBodyLen : Nat) : FragmentS :=
  {
    fragOffset := 0,
    dataLen := originalTailLen payloadLen optionsBodyLen,
    terminal := true,
    rdos := some (rdosForPayload payloadLen)
  }

def nonTerminalFits (maxSurplus bodyLen dataLen : Nat) : Prop :=
  bodyLen + dataLen ≤ maxSurplus

def terminalFits (maxSurplus bodyLen dataLen : Nat) : Prop :=
  bodyLen + dataLen ≤ maxSurplus

def withinMrds (payloadLen optionsBodyLen mrds : Nat) : Prop :=
  reassembledDatagramLen payloadLen optionsBodyLen ≤ mrds

def withinSegmentLimit (needed maxSegments : Nat) : Prop :=
  needed ≤ maxSegments

structure SplitShape where
  nonTerminalBytes : Nat
  terminalBytes : Nat
  deriving DecidableEq, Repr

def terminalDataLen (tailLen terminalCapacity : Nat) : Nat :=
  if tailLen ≤ terminalCapacity then tailLen else terminalCapacity

def nonTerminalDataLen (tailLen terminalCapacity : Nat) : Nat :=
  tailLen - terminalDataLen tailLen terminalCapacity

def splitShape (tailLen terminalCapacity : Nat) : SplitShape :=
  {
    nonTerminalBytes := nonTerminalDataLen tailLen terminalCapacity,
    terminalBytes := terminalDataLen tailLen terminalCapacity
  }

def terminalOffset (shape : SplitShape) : Nat :=
  fragUdpHeaderLength + shape.nonTerminalBytes

def terminalEnd (shape : SplitShape) : Nat :=
  terminalOffset shape + shape.terminalBytes

/-! ## Theorems over Step 11 invariants -/

/-- **RDOS is the original UDP Length: header plus payload, before any surplus pad/options.** -/
theorem rdos_is_original_udp_length (payloadLen : Nat) :
    rdosForPayload payloadLen = fragUdpHeaderLength + payloadLen := by
  rfl

/-- **No carried per-datagram options means no reassembled surplus pad.** -/
theorem no_options_have_no_pad (payloadLen : Nat) :
    originalOptionsPadLen payloadLen 0 = 0 := by
  simp [originalOptionsPadLen]

/-- **An odd RDOS with carried per-datagram options inserts one pad byte before the OCS body.** -/
theorem odd_rdos_with_options_adds_one_pad :
    originalOptionsPadLen 3 4 = 1 := by
  decide

/-- **The RFC standalone/atomic FRAG variant uses offset zero.** -/
theorem atomic_offset_is_zero (payloadLen optionsBodyLen : Nat) :
    (atomicFragment payloadLen optionsBodyLen).fragOffset = 0 := by
  rfl

/-- **The atomic fragment carries exactly the reassembled tail bytes.** -/
theorem atomic_covers_reassembled_tail (payloadLen optionsBodyLen : Nat) :
    (atomicFragment payloadLen optionsBodyLen).dataLen = originalTailLen payloadLen optionsBodyLen := by
  rfl

/-- **The atomic fragment is terminal and carries RDOS.** -/
theorem atomic_is_terminal_with_rdos (payloadLen optionsBodyLen : Nat) :
    (atomicFragment payloadLen optionsBodyLen).terminal = true ∧
      (atomicFragment payloadLen optionsBodyLen).rdos = some (rdosForPayload payloadLen) := by
  simp [atomicFragment]

/-- **The default IPv4 MRDS values match RFC 9868 Section 11.6.** -/
theorem default_ipv4_mrds_values :
    mrdsDefaultIpv4 = 2926 ∧ minReassemblySegments = 2 := by
  decide

/-- **The measured Step 11 fragment bodies include only OCS plus FRAG before fragment data.** -/
theorem measured_fragment_body_lengths :
    fragNonTerminalMeasuredBodyLen = 12 ∧ fragTerminalMeasuredBodyLen = 14 := by
  decide

/-- **The shape model splits the reassembled tail into a non-terminal prefix and terminal suffix.** -/
theorem split_shape_covers_tail (tailLen terminalCapacity : Nat) :
    (splitShape tailLen terminalCapacity).nonTerminalBytes +
      (splitShape tailLen terminalCapacity).terminalBytes = tailLen := by
  by_cases h : tailLen ≤ terminalCapacity
  · simp [splitShape, nonTerminalDataLen, terminalDataLen, h]
  · have hCap : terminalCapacity ≤ tailLen := Nat.le_of_lt (Nat.lt_of_not_ge h)
    simp [splitShape, nonTerminalDataLen, terminalDataLen, h]
    omega

/-- **The terminal suffix is never larger than the measured terminal payload budget.** -/
theorem split_shape_terminal_data_respects_capacity (tailLen terminalCapacity : Nat) :
    (splitShape tailLen terminalCapacity).terminalBytes ≤ terminalCapacity := by
  by_cases h : tailLen ≤ terminalCapacity
  · simp [splitShape, terminalDataLen, h]
  · simp [splitShape, terminalDataLen, h]

/-- **If the terminal body itself fits, the terminal fragment fits the fragment surplus budget.** -/
theorem split_shape_terminal_fragment_respects_budget (tailLen maxSurplus : Nat)
    (h : fragTerminalMeasuredBodyLen ≤ maxSurplus) :
    (splitShape tailLen (maxSurplus - fragTerminalMeasuredBodyLen)).terminalBytes +
      fragTerminalMeasuredBodyLen ≤ maxSurplus := by
  have hData := split_shape_terminal_data_respects_capacity tailLen (maxSurplus - fragTerminalMeasuredBodyLen)
  omega

/-- **The terminal fragment starts after all non-terminal bytes.** -/
theorem terminal_offset_follows_non_terminal_prefix (tailLen terminalCapacity : Nat) :
    terminalOffset (splitShape tailLen terminalCapacity) =
      fragUdpHeaderLength + (splitShape tailLen terminalCapacity).nonTerminalBytes := by
  rfl

/-- **The modeled fragment sequence covers through the end of the reassembled tail.** -/
theorem terminal_end_matches_reassembled_tail_end (tailLen terminalCapacity : Nat) :
    terminalEnd (splitShape tailLen terminalCapacity) = fragUdpHeaderLength + tailLen := by
  unfold terminalEnd terminalOffset
  have hCover := split_shape_covers_tail tailLen terminalCapacity
  omega

/-- **A zero terminal data budget is still representable: all data is non-terminal, terminal is empty.** -/
theorem zero_terminal_capacity_has_empty_terminal (tailLen : Nat) :
    (splitShape tailLen 0).terminalBytes = 0 ∧
      (splitShape tailLen 0).nonTerminalBytes = tailLen := by
  by_cases h : tailLen ≤ 0
  · have hZero : tailLen = 0 := by omega
    simp [splitShape, nonTerminalDataLen, terminalDataLen, h, hZero]
  · simp [splitShape, nonTerminalDataLen, terminalDataLen, h]

/-- **A datagram larger than MRDS is outside the accepted split domain.** -/
theorem larger_than_mrds_is_rejected_condition (payloadLen optionsBodyLen mrds : Nat)
    (h : mrds < reassembledDatagramLen payloadLen optionsBodyLen) :
    ¬ withinMrds payloadLen optionsBodyLen mrds := by
  unfold withinMrds
  omega

/-- **A split needing more fragments than MRDS segs is outside the accepted split domain.** -/
theorem too_many_segments_is_rejected_condition (needed maxSegments : Nat)
    (h : maxSegments < needed) :
    ¬ withinSegmentLimit needed maxSegments := by
  unfold withinSegmentLimit
  omega

/-- **A non-terminal chunk accepted by the Rust budget check is no larger than the measured budget.** -/
theorem non_terminal_chunk_respects_measured_budget (maxSurplus bodyLen dataLen : Nat)
    (h : nonTerminalFits maxSurplus bodyLen dataLen) :
    dataLen ≤ maxSurplus - bodyLen := by
  unfold nonTerminalFits at h
  omega

/-- **A terminal chunk accepted by the Rust budget check is no larger than the measured budget.** -/
theorem terminal_chunk_respects_measured_budget (maxSurplus bodyLen dataLen : Nat)
    (h : terminalFits maxSurplus bodyLen dataLen) :
    dataLen ≤ maxSurplus - bodyLen := by
  unfold terminalFits at h
  omega

end Rfc9868
