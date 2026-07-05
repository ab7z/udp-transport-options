import Rfc9868.FragSplit

/-!
# Step 12 spec: receive-side FRAG reassembly

This is a small model of the Step 12 reassembly cache. It captures the load-bearing arithmetic:
fragment offsets are normalized into the reconstructed tail after the UDP header, adjacent intervals
do not overlap, terminal RDOS is the reconstructed UDP Length, and timeout/limit values are explicit
caller-driven parameters.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored unit tests, property tests, and the `frag_reassembly`
fuzz target.
-/

namespace Rfc9868

/-! ## Reassembly model -/

def reassemblyTimeoutMaxSeconds : Nat := 120
def reassemblyMaxPendingPartials : Nat := 64

structure ReassemblySegment where
  start : Nat
  stop : Nat
  deriving DecidableEq, Repr

def segmentOverlaps (a b : ReassemblySegment) : Prop :=
  a.start < b.stop ∧ b.start < a.stop

def normalizedFragOffset (fragOffset : Nat) (terminal : Bool) : Option Nat :=
  if fragOffset = 0 ∧ terminal then some 0
  else if fragUdpHeaderLength ≤ fragOffset then some (fragOffset - fragUdpHeaderLength)
  else none

def terminalUdpLengthValid (rdos terminalEnd : Nat) : Prop :=
  fragUdpHeaderLength ≤ rdos ∧ rdos - fragUdpHeaderLength ≤ terminalEnd

def completeTwoSegments (a b : ReassemblySegment) (terminalEnd : Nat) : Prop :=
  a.start = 0 ∧ a.stop = b.start ∧ b.stop = terminalEnd

/-! ## Theorems over Step 12 invariants -/

theorem reassembly_timeout_is_at_most_two_minutes :
    reassemblyTimeoutMaxSeconds ≤ 120 := by
  decide

theorem default_global_partial_cap_is_explicit :
    reassemblyMaxPendingPartials = 64 := by
  rfl

theorem atomic_terminal_offset_normalizes_to_tail_zero :
    normalizedFragOffset 0 true = some 0 := by
  rfl

theorem non_terminal_offset_is_udp_header_relative :
    normalizedFragOffset 12 false = some 4 := by
  decide

theorem below_udp_header_non_terminal_offset_is_invalid :
    normalizedFragOffset 7 false = none := by
  decide

theorem adjacent_segments_do_not_overlap :
    ¬ segmentOverlaps { start := 0, stop := 4 } { start := 4, stop := 8 } := by
  unfold segmentOverlaps
  simp

theorem partial_overlap_is_detected :
    segmentOverlaps { start := 0, stop := 4 } { start := 3, stop := 8 } := by
  unfold segmentOverlaps
  simp

theorem terminal_rdos_must_not_exceed_reassembled_tail :
    ¬ terminalUdpLengthValid 20 8 := by
  unfold terminalUdpLengthValid fragUdpHeaderLength
  simp

theorem terminal_rdos_may_point_before_options_tail :
    terminalUdpLengthValid 13 9 := by
  unfold terminalUdpLengthValid fragUdpHeaderLength
  simp

theorem gap_free_two_segment_completion :
    completeTwoSegments { start := 0, stop := 6 } { start := 6, stop := 10 } 10 := by
  unfold completeTwoSegments
  simp

theorem missing_prefix_is_not_complete :
    ¬ completeTwoSegments { start := 2, stop := 6 } { start := 6, stop := 10 } 10 := by
  unfold completeTwoSegments
  simp

end Rfc9868
