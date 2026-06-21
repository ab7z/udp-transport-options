import Rfc9868.Checksum

/-!
# Step 06 spec: Option Checksum (OCS)

A small model of the RFC 9868 OCS rule, built on the Step 1 one's-complement checksum model. The
model is word-level: `bodyWords` are the 16-bit words after the OCS field has been treated as zero,
and `surplusLen` is the full surplus-area length, including any pre-OCS pad byte.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored unit tests, property tests, and the `options_ocs` fuzz
target.
-/

namespace Rfc9868

/-! ## OCS model -/

def normalizeOcs (raw : Nat) : Nat :=
  if raw = 0 then 65535 else raw

def computeOcsWords (bodyWords : List Nat) (surplusLen : Nat) : Nat :=
  normalizeOcs (checksumWords (bodyWords ++ [surplusLen]))

def validateOcsWords (bodyWords : List Nat) (surplusLen storedOcs : Nat) : Prop :=
  foldSum (sumWords ((bodyWords ++ [surplusLen]) ++ [storedOcs])) = 65535

def padValid (pad : Nat) (needsPad : Bool) : Bool :=
  if needsPad then pad = 0 else true

/-! ## Theorems over Step 6 invariants -/

/-- **Compute then validate succeeds** for well-formed 16-bit words and a 16-bit surplus length. -/
theorem computeOcsWords_validates
    (bodyWords : List Nat)
    (surplusLen : Nat)
    (hbody : ∀ w ∈ bodyWords, w < 65536)
    (hlen : surplusLen < 65536) :
    validateOcsWords bodyWords surplusLen (computeOcsWords bodyWords surplusLen) := by
  unfold validateOcsWords computeOcsWords normalizeOcs
  have hwords : ∀ w ∈ bodyWords ++ [surplusLen], w < 65536 := by
    intro w hw
    rw [List.mem_append] at hw
    rcases hw with h | h
    · exact hbody w h
    · simp at h
      rw [h]
      exact hlen
  exact data_plus_normalized_complement_folds_to_ones (bodyWords ++ [surplusLen]) hwords

/-- **The forced-zero wire normalization remains valid**: a raw complement of zero can be stored as
`0xffff` and still validate. -/
theorem normalized_zero_ocs_validates
    (bodyWords : List Nat)
    (surplusLen : Nat)
    (hwords : ∀ w ∈ bodyWords ++ [surplusLen], w < 65536)
    (hzero : checksumWords (bodyWords ++ [surplusLen]) = 0) :
    foldSum (sumWords ((bodyWords ++ [surplusLen]) ++ [65535])) = 65535 := by
  have h := data_plus_normalized_complement_folds_to_ones (bodyWords ++ [surplusLen]) hwords
  simp [hzero] at h
  simpa [List.append_assoc] using h

/-- **Forced-zero representative**: `0xfffb + 4` computes raw zero, stores `0xffff`, and validates. -/
theorem forced_zero_representative :
    computeOcsWords [0xfffb] 4 = 0xffff ∧ validateOcsWords [0xfffb] 4 0xffff := by
  have hcompute : computeOcsWords [0xfffb] 4 = 0xffff := by
    unfold computeOcsWords normalizeOcs checksumWords complement16
    have hsum : sumWords ([0xfffb] ++ [4]) = 0xffff := by decide
    rw [hsum, foldSum_eq_self (by omega)]
    simp
  constructor
  · exact hcompute
  · rw [← hcompute]
    exact computeOcsWords_validates [0xfffb] 4 (by intro w hw; simp at hw; omega) (by omega)

/-- **A non-zero present pad byte is invalid.** -/
theorem nonzero_present_pad_invalid :
    padValid 1 true = false := by
  decide

end Rfc9868
