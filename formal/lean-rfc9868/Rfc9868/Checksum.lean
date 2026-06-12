/-!
# Step 01 spec: the RFC 1071 one's-complement Internet checksum

A manual Lean model of the RFC 1071 rules mirrored by `src/wire/checksum.rs`.

**Honesty note (no extraction):** without a Rust-to-Lean extraction pipeline (Aeneas), these
theorems are about this Lean model, not about the Rust code itself. The coupling to Rust is via
shared golden vectors: the RFC 1071 Section 3 worked example and the unit-test vectors of
`checksum.rs` are replicated below as kernel-checked equalities (`decide`, never `native_decide`).

Model mapping:
- `addU16`        ~ `Checksum::add_u16` (eager end-around fold; accumulator stays <= 65536)
- `sumWords`      ~ feeding a word sequence into the accumulator
- `foldSum`       ~ `Checksum::sum` (the final fold loop)
- `checksumWords` ~ `Checksum::finish` (`!x` on `u16` is `65535 - x` for `x < 65536`)
- `toWords`       ~ `Checksum::add_slice` byte pairing (trailing odd byte = high byte)
-/

namespace Rfc9868

/-- One accumulator step: add a 16-bit word and eagerly fold the end-around carry once
(`Checksum::add_u16`). For `acc <= 65536` and `v < 65536` the result is again `<= 65536`. -/
def addU16 (acc v : Nat) : Nat :=
  (acc + v) % 65536 + (acc + v) / 65536

/-- Folded sum of a word list from an empty accumulator. -/
def sumWords (ws : List Nat) : Nat :=
  ws.foldl addU16 0

/-- The final fold loop (`Checksum::sum`): fold until the value fits in 16 bits. -/
def foldSum (s : Nat) : Nat :=
  if _h : s < 65536 then s
  else foldSum (s % 65536 + s / 65536)
termination_by s
decreasing_by omega

/-- The one's complement of a folded sum (`Checksum::finish`; `!x` on `u16`). -/
def complement16 (x : Nat) : Nat := 65535 - x

/-- The stored checksum of a word list: the complement of the folded sum. -/
def checksumWords (ws : List Nat) : Nat :=
  complement16 (foldSum (sumWords ws))

/-- Big-endian byte pairing (`Checksum::add_slice`): two bytes form one word; a trailing odd
byte is the high byte of a final word whose low byte is zero (RFC 1071 Section 2(A)). -/
def toWords : List Nat → List Nat
  | [] => []
  | [b] => [b * 256]
  | b₁ :: b₂ :: rest => (b₁ * 256 + b₂) :: toWords rest

/-- `internet_checksum`: the stored checksum of a byte slice. -/
def bytesChecksum (bytes : List Nat) : Nat :=
  checksumWords (toWords bytes)

/-! ## Accumulator invariant -/

/-- One step keeps the accumulator at or below 65536 (the Rust "below 2^17" overflow argument:
`acc + v <= 65536 + 65535 < 2^17`, and one eager fold brings that back to `<= 65536`). -/
theorem addU16_le {acc v : Nat} (ha : acc ≤ 65536) (hv : v < 65536) : addU16 acc v ≤ 65536 := by
  unfold addU16
  omega

/-- The invariant holds along any word list. -/
theorem foldl_addU16_le :
    ∀ (ws : List Nat) (acc : Nat), acc ≤ 65536 → (∀ w ∈ ws, w < 65536) →
      ws.foldl addU16 acc ≤ 65536
  | [], _, ha, _ => ha
  | w :: rest, acc, ha, hw =>
    foldl_addU16_le rest (addU16 acc w)
      (addU16_le ha (hw w (List.mem_cons_self w rest)))
      (fun x hx => hw x (List.mem_cons_of_mem w hx))

/-- The folded sum of well-formed words stays at or below 65536. -/
theorem sumWords_le (ws : List Nat) (hw : ∀ w ∈ ws, w < 65536) : sumWords ws ≤ 65536 :=
  foldl_addU16_le ws 0 (by omega) hw

/-! ## The final fold -/

/-- A value already in 16 bits folds to itself. -/
theorem foldSum_eq_self {s : Nat} (h : s < 65536) : foldSum s = s := by
  unfold foldSum
  simp [h]

/-- The boundary case of the accumulator invariant folds to 1. -/
theorem foldSum_65536 : foldSum 65536 = 1 := by
  unfold foldSum
  rw [dif_neg (by omega)]
  have h : (65536 : Nat) % 65536 + 65536 / 65536 = 1 := by omega
  rw [h]
  exact foldSum_eq_self (by omega)

/-! ## Step 01 theorems (docs/plan/steps/01-checksum.md, "Lean verification") -/

/-- **`finish` is the complement of the folded sum** — definitional in the model. -/
theorem checksum_is_complement_of_fold (ws : List Nat) :
    checksumWords ws = 65535 - foldSum (sumWords ws) := rfl

/-- **Data plus the stored complement folds to `0xffff`** (one's-complement zero): verifying a
checksummed region means appending the stored value and checking the folded sum is all-ones. -/
theorem data_plus_complement_folds_to_ones (ws : List Nat) (hw : ∀ w ∈ ws, w < 65536) :
    foldSum (sumWords (ws ++ [checksumWords ws])) = 65535 := by
  have hS : sumWords ws ≤ 65536 := sumWords_le ws hw
  rw [sumWords, List.foldl_append]
  show foldSum (addU16 (sumWords ws) (checksumWords ws)) = 65535
  by_cases h : sumWords ws < 65536
  · rw [checksumWords, complement16, foldSum_eq_self h]
    have : addU16 (sumWords ws) (65535 - sumWords ws) = 65535 := by
      unfold addU16
      omega
    rw [this]
    exact foldSum_eq_self (by omega)
  · have h6 : sumWords ws = 65536 := by omega
    rw [checksumWords, complement16, h6, foldSum_65536]
    have : addU16 65536 (65535 - 1) = 65535 := by
      unfold addU16
      omega
    rw [this]
    exact foldSum_eq_self (by omega)

/-- **Data plus the zero-normalized complement also folds to `0xffff`**: when a computed zero is
transmitted as `0xffff` instead (the RFC 768 UDP rule), verification still succeeds — the all-ones
word is one's-complement zero, so it cannot change a folded sum of `0xffff`. -/
theorem data_plus_normalized_complement_folds_to_ones (ws : List Nat)
    (hw : ∀ w ∈ ws, w < 65536) :
    foldSum (sumWords (ws ++ [if checksumWords ws = 0 then 65535 else checksumWords ws]))
      = 65535 := by
  by_cases hzero : checksumWords ws = 0
  · rw [if_pos hzero]
    have hS : sumWords ws ≤ 65536 := sumWords_le ws hw
    have hS' : sumWords ws = 65535 := by
      unfold checksumWords complement16 at hzero
      by_cases hlt : sumWords ws < 65536
      · rw [foldSum_eq_self hlt] at hzero
        omega
      · have h6 : sumWords ws = 65536 := by omega
        rw [h6, foldSum_65536] at hzero
        omega
    rw [sumWords, List.foldl_append]
    show foldSum (addU16 (sumWords ws) 65535) = 65535
    rw [hS']
    have h : addU16 65535 65535 = 65535 := by
      unfold addU16
      omega
    rw [h]
    exact foldSum_eq_self (by omega)
  · rw [if_neg hzero]
    exact data_plus_complement_folds_to_ones ws hw

/-- **Incremental accumulation equals the one-shot sum** (word level): summing `xs` then
continuing with `ys` is the sum of the concatenation (`Checksum` as a resumable accumulator). -/
theorem incremental_eq_one_shot (xs ys : List Nat) :
    sumWords (xs ++ ys) = ys.foldl addU16 (sumWords xs) := by
  simp [sumWords, List.foldl_append]

/-- Byte pairing distributes over append when the first region is word-aligned (even length). -/
theorem toWords_append (ys : List Nat) :
    ∀ (xs : List Nat), xs.length % 2 = 0 → toWords (xs ++ ys) = toWords xs ++ toWords ys
  | [], _ => rfl
  | [_], h => by simp at h
  | x :: y :: rest, h => by
    simp only [List.cons_append, toWords, List.length_cons] at *
    exact congrArg _ (toWords_append ys rest (by omega))

/-- **Incremental accumulation equals the one-shot sum** (byte level), for word-aligned region
splits. The alignment hypothesis is the documented `add_slice` contract itself (every region
except the last must be word-aligned, RFC 1071 Section 2(A)) — not a weakening: each `add_slice`
pads its own slice, so an odd split genuinely differs from the one-shot sum (e.g. `[0x01]` then
`[0x02]` sums `0x0100 + 0x0200`, the one-shot `[0x01, 0x02]` sums `0x0102`). -/
theorem incremental_eq_one_shot_bytes (xs ys : List Nat) (h : xs.length % 2 = 0) :
    sumWords (toWords (xs ++ ys)) = (toWords ys).foldl addU16 (sumWords (toWords xs)) := by
  rw [toWords_append ys xs h]
  exact incremental_eq_one_shot (toWords xs) (toWords ys)

/-- **A trailing odd byte is the high byte of a final word**: appending one byte to an
even-length byte sequence appends exactly the word `b * 256`. -/
theorem trailing_odd_byte_is_high_byte (b : Nat) (l : List Nat) (h : l.length % 2 = 0) :
    toWords (l ++ [b]) = toWords l ++ [b * 256] :=
  toWords_append [b] l h

/-- Bytes below 256 pair into words below 65536 (feeds the verification theorem). -/
theorem toWords_lt :
    ∀ (l : List Nat), (∀ b ∈ l, b < 256) → ∀ w ∈ toWords l, w < 65536
  | [], _, w, hw => by simp [toWords] at hw
  | [b], hb, w, hw => by
    simp [toWords] at hw
    have := hb b (List.mem_cons_self b [])
    omega
  | b₁ :: b₂ :: rest, hb, w, hw => by
    simp only [toWords, List.mem_cons] at hw
    rcases hw with h | h
    · have h1 := hb b₁ (by simp)
      have h2 := hb b₂ (by simp)
      omega
    · exact toWords_lt rest (fun x hx => hb x (by simp [hx])) w h

/-! ## Golden vectors (the Rust-Lean coupling; all kernel-checked) -/

/-- The RFC 1071 Section 3 worked example: folded sum `0xddf2` (mirrors
`checksum.rs::tests::rfc1071_worked_example`). -/
theorem rfc1071_worked_example_sum :
    sumWords (toWords [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]) = 0xddf2 := by decide

/-- The RFC 1071 Section 3 worked example: stored checksum `0x220d`. -/
theorem rfc1071_worked_example_checksum :
    bytesChecksum [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7] = 0x220d := by
  rw [bytesChecksum, checksumWords, complement16, rfc1071_worked_example_sum,
    foldSum_eq_self (by omega)]

/-- Odd-length input: `0x0102 + 0x0300 = 0x0402` (mirrors
`tests::odd_length_trailing_byte_is_high_byte`). -/
theorem odd_length_vector : sumWords (toWords [0x01, 0x02, 0x03]) = 0x0402 := by decide

/-- A single byte is the high byte of the only word. -/
theorem single_byte_vector : sumWords (toWords [0xab]) = 0xab00 := by decide

/-- End-around carry: `0xffff + 0xffff` folds to `0xffff` (mirrors
`tests::end_around_carry_folds`). -/
theorem end_around_carry_vector_ones :
    sumWords (toWords [0xff, 0xff, 0xff, 0xff]) = 0xffff := by decide

/-- End-around carry: `0x8000 + 0x8001` folds to `0x0002`. -/
theorem end_around_carry_vector_two :
    sumWords (toWords [0x80, 0x00, 0x80, 0x01]) = 0x0002 := by decide

/-- The empty input checksums to `0xffff` (mirrors `tests::all_zero_input`). -/
theorem empty_input_checksum : bytesChecksum [] = 0xffff := by
  rw [bytesChecksum, checksumWords, complement16]
  rw [show sumWords (toWords []) = 0 from rfl, foldSum_eq_self (by omega)]

end Rfc9868
