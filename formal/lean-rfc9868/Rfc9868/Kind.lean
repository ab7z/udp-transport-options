/-!
# Step 03 spec: UDP option Kind classification

A manual Lean model of the RFC 9868 Kind-byte table mirrored by `src/options/kind.rs`.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via the same constants and exhaustive Rust tests over all 256 Kind
bytes.

Model mapping:
- `fromByte` / `toByte`          ~ `OptionKind::{from_byte,to_byte}`
- `isSafe` / `isUnsafe`          ~ `OptionKind::{is_safe,is_unsafe}`
- `isMustSupport`                ~ `OptionKind::is_must_support`
- `isSingleByte`                 ~ `OptionKind::is_single_byte`
- `fixedTlvLengthsByte`          ~ `OptionKind::fixed_tlv_lengths`
-/

namespace Rfc9868

/-! ## Constants -/

def kindEol : Nat := 0
def kindNop : Nat := 1
def kindApc : Nat := 2
def kindFrag : Nat := 3
def kindMds : Nat := 4
def kindMrds : Nat := 5
def kindReq : Nat := 6
def kindRes : Nat := 7
def unsafeMin : Nat := 192
def extendedLengthMarker : Nat := 255

def lenApc : Nat := 6
def lenFragNonTerminal : Nat := 10
def lenFragTerminal : Nat := 12
def lenMds : Nat := 4
def lenMrds : Nat := 5
def lenReq : Nat := 6
def lenRes : Nat := 6

/-! ## Kind mapping -/

inductive OptionKindS where
  | eol
  | nop
  | apc
  | frag
  | mds
  | mrds
  | req
  | res
  | other (byte : Nat)
  deriving DecidableEq, Repr

def fromByte (byte : Nat) : OptionKindS :=
  if byte = kindEol then OptionKindS.eol
  else if byte = kindNop then OptionKindS.nop
  else if byte = kindApc then OptionKindS.apc
  else if byte = kindFrag then OptionKindS.frag
  else if byte = kindMds then OptionKindS.mds
  else if byte = kindMrds then OptionKindS.mrds
  else if byte = kindReq then OptionKindS.req
  else if byte = kindRes then OptionKindS.res
  else OptionKindS.other byte

def toByte : OptionKindS → Nat
  | OptionKindS.eol => kindEol
  | OptionKindS.nop => kindNop
  | OptionKindS.apc => kindApc
  | OptionKindS.frag => kindFrag
  | OptionKindS.mds => kindMds
  | OptionKindS.mrds => kindMrds
  | OptionKindS.req => kindReq
  | OptionKindS.res => kindRes
  | OptionKindS.other byte => byte

/-- **Kind mapping round-trips every raw byte value.** -/
theorem toByte_fromByte (byte : Nat) : toByte (fromByte byte) = byte := by
  unfold fromByte
  by_cases h0 : byte = 0
  · simp [h0, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
  · by_cases h1 : byte = 1
    · simp [h0, h1, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
    · by_cases h2 : byte = 2
      · simp [h0, h1, h2, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
      · by_cases h3 : byte = 3
        · simp [h0, h1, h2, h3, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
        · by_cases h4 : byte = 4
          · simp [h0, h1, h2, h3, h4, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
          · by_cases h5 : byte = 5
            · simp [h0, h1, h2, h3, h4, h5, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
            · by_cases h6 : byte = 6
              · simp [h0, h1, h2, h3, h4, h5, h6, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
              · by_cases h7 : byte = 7
                · simp [h0, h1, h2, h3, h4, h5, h6, h7, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]
                · simp [h0, h1, h2, h3, h4, h5, h6, h7, toByte, kindEol, kindNop, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]

/-! ## Classification predicates -/

def isSafe (kind : OptionKindS) : Prop :=
  toByte kind < unsafeMin

def isUnsafe (kind : OptionKindS) : Prop :=
  unsafeMin ≤ toByte kind

def isMustSupport (kind : OptionKindS) : Prop :=
  toByte kind ≤ kindRes

def isSingleByte (kind : OptionKindS) : Prop :=
  toByte kind = kindEol ∨ toByte kind = kindNop

/-- **SAFE is exactly the byte range `0..=191`.** -/
theorem isSafe_fromByte_iff (byte : Nat) : isSafe (fromByte byte) ↔ byte < unsafeMin := by
  unfold isSafe
  rw [toByte_fromByte]

/-- **UNSAFE is exactly the byte range `192..=255` for byte-valued inputs.** -/
theorem isUnsafe_fromByte_iff (byte : Nat) : isUnsafe (fromByte byte) ↔ unsafeMin ≤ byte := by
  unfold isUnsafe
  rw [toByte_fromByte]

/-- **Must-support is exactly the byte range `0..=7`.** -/
theorem isMustSupport_fromByte_iff (byte : Nat) :
    isMustSupport (fromByte byte) ↔ byte ≤ kindRes := by
  unfold isMustSupport
  rw [toByte_fromByte]

/-- **Single-byte options are exactly EOL and NOP.** -/
theorem isSingleByte_fromByte_iff (byte : Nat) :
    isSingleByte (fromByte byte) ↔ byte = kindEol ∨ byte = kindNop := by
  unfold isSingleByte
  rw [toByte_fromByte]

/-! ## Fixed TLV length table -/

def fixedTlvLengthsByte (byte : Nat) : List Nat :=
  if byte = kindApc then [lenApc]
  else if byte = kindFrag then [lenFragNonTerminal, lenFragTerminal]
  else if byte = kindMds then [lenMds]
  else if byte = kindMrds then [lenMrds]
  else if byte = kindReq then [lenReq]
  else if byte = kindRes then [lenRes]
  else []

/-- **APC has total TLV length 6.** -/
theorem fixed_lengths_apc : fixedTlvLengthsByte kindApc = [lenApc] := by
  simp [fixedTlvLengthsByte]

/-- **FRAG has total TLV lengths 10 (non-terminal) and 12 (terminal).** -/
theorem fixed_lengths_frag :
    fixedTlvLengthsByte kindFrag = [lenFragNonTerminal, lenFragTerminal] := by
  simp [fixedTlvLengthsByte, kindApc, kindFrag]

/-- **MDS has total TLV length 4.** -/
theorem fixed_lengths_mds : fixedTlvLengthsByte kindMds = [lenMds] := by
  simp [fixedTlvLengthsByte, kindApc, kindFrag, kindMds]

/-- **MRDS has total TLV length 5.** -/
theorem fixed_lengths_mrds : fixedTlvLengthsByte kindMrds = [lenMrds] := by
  simp [fixedTlvLengthsByte, kindApc, kindFrag, kindMds, kindMrds]

/-- **REQ has total TLV length 6.** -/
theorem fixed_lengths_req : fixedTlvLengthsByte kindReq = [lenReq] := by
  simp [fixedTlvLengthsByte, kindApc, kindFrag, kindMds, kindMrds, kindReq]

/-- **RES has total TLV length 6.** -/
theorem fixed_lengths_res : fixedTlvLengthsByte kindRes = [lenRes] := by
  simp [fixedTlvLengthsByte, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes]

/-- **All other Kinds have no fixed TLV length at this layer.** -/
theorem fixed_lengths_other_empty (byte : Nat) (h2 : byte ≠ kindApc) (h3 : byte ≠ kindFrag)
    (h4 : byte ≠ kindMds) (h5 : byte ≠ kindMrds) (h6 : byte ≠ kindReq) (h7 : byte ≠ kindRes) :
    fixedTlvLengthsByte byte = [] := by
  unfold kindApc kindFrag kindMds kindMrds kindReq kindRes at *
  simp [fixedTlvLengthsByte, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes, h2, h3, h4, h5, h6, h7]

/-- **The extended-length marker is a Length-field sentinel, not a fixed Kind table entry.** -/
theorem extended_length_marker_has_no_fixed_kind_length :
    fixedTlvLengthsByte extendedLengthMarker = [] := by
  simp [fixedTlvLengthsByte, kindApc, kindFrag, kindMds, kindMrds, kindReq, kindRes, extendedLengthMarker]

end Rfc9868
