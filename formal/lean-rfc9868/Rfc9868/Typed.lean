import Rfc9868.Kind

/-!
# Step 07 spec: typed must-support option values

A small model of the fixed-size typed option codecs. This covers the value bytes after Kind/Length
framing for APC, MDS, MRDS, REQ, RES, and the two FRAG layouts.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored constants, unit tests, property tests, and the
`options_typed` fuzz target. APC's CRC32C primitive is deliberately trusted here; the Lean model only
covers its 32-bit big-endian wire field.
-/

namespace Rfc9868

/-! ## Typed value model -/

def typedTlvHeaderLen : Nat := 2

def valueLenOfTotal (totalLen : Nat) : Nat :=
  totalLen - typedTlvHeaderLen

def byteAt (value : List Nat) (offset : Nat) : Nat :=
  value.getD offset 0

def be16At (value : List Nat) (offset : Nat) : Nat :=
  byteAt value offset * 256 + byteAt value (offset + 1)

def be32At (value : List Nat) (offset : Nat) : Nat :=
  byteAt value offset * 16777216 +
    byteAt value (offset + 1) * 65536 +
    byteAt value (offset + 2) * 256 +
    byteAt value (offset + 3)

def u16Bytes (value : Nat) : List Nat :=
  [value / 256, value % 256]

def u32Bytes (value : Nat) : List Nat :=
  [value / 16777216, (value / 65536) % 256, (value / 256) % 256, value % 256]

inductive TypedError where
  | invalidLength (kind len : Nat)
  deriving DecidableEq, Repr

def invalidTypedLength (kind : Nat) (value : List Nat) : TypedError :=
  TypedError.invalidLength kind (value.length + typedTlvHeaderLen)

structure ApcS where
  crc32c : Nat
  deriving DecidableEq, Repr

structure MdsS where
  maxDatagramSize : Nat
  deriving DecidableEq, Repr

structure MrdsS where
  maxReassembledSize : Nat
  maxSegments : Nat
  deriving DecidableEq, Repr

structure ReqS where
  token : List Nat
  deriving DecidableEq, Repr

structure ResS where
  token : List Nat
  deriving DecidableEq, Repr

structure FragS where
  fragStart : Nat
  identification : Nat
  fragOffset : Nat
  rdos : Option Nat
  deriving DecidableEq, Repr

def decodeApc (value : List Nat) : Except TypedError ApcS :=
  if value.length = valueLenOfTotal lenApc then
    Except.ok { crc32c := be32At value 0 }
  else
    Except.error (invalidTypedLength kindApc value)

def decodeMds (value : List Nat) : Except TypedError MdsS :=
  if value.length = valueLenOfTotal lenMds then
    Except.ok { maxDatagramSize := be16At value 0 }
  else
    Except.error (invalidTypedLength kindMds value)

def decodeMrds (value : List Nat) : Except TypedError MrdsS :=
  if value.length = valueLenOfTotal lenMrds then
    Except.ok { maxReassembledSize := be16At value 0, maxSegments := byteAt value 2 }
  else
    Except.error (invalidTypedLength kindMrds value)

def decodeReq (value : List Nat) : Except TypedError ReqS :=
  if value.length = valueLenOfTotal lenReq then
    Except.ok { token := value }
  else
    Except.error (invalidTypedLength kindReq value)

def decodeRes (value : List Nat) : Except TypedError ResS :=
  if value.length = valueLenOfTotal lenRes then
    Except.ok { token := value }
  else
    Except.error (invalidTypedLength kindRes value)

def decodeFrag (value : List Nat) : Except TypedError FragS :=
  if value.length = valueLenOfTotal lenFragNonTerminal then
    Except.ok
      {
        fragStart := be16At value 0,
        identification := be32At value 2,
        fragOffset := be16At value 6,
        rdos := none
      }
  else if value.length = valueLenOfTotal lenFragTerminal then
    Except.ok
      {
        fragStart := be16At value 0,
        identification := be32At value 2,
        fragOffset := be16At value 6,
        rdos := some (be16At value 8)
      }
  else
    Except.error (invalidTypedLength kindFrag value)

def encodeApcValue (option : ApcS) : List Nat :=
  u32Bytes option.crc32c

def encodeMdsValue (option : MdsS) : List Nat :=
  u16Bytes option.maxDatagramSize

def encodeMrdsValue (option : MrdsS) : List Nat :=
  u16Bytes option.maxReassembledSize ++ [option.maxSegments]

def encodeReqValue (option : ReqS) : List Nat :=
  option.token

def encodeResValue (option : ResS) : List Nat :=
  option.token

def encodeFragValue (option : FragS) : List Nat :=
  u16Bytes option.fragStart ++
    u32Bytes option.identification ++
    u16Bytes option.fragOffset ++
    match option.rdos with
    | none => []
    | some rdos => u16Bytes rdos

def encodeApc (option : ApcS) : List Nat :=
  [kindApc, lenApc] ++ encodeApcValue option

def encodeMds (option : MdsS) : List Nat :=
  [kindMds, lenMds] ++ encodeMdsValue option

def encodeMrds (option : MrdsS) : List Nat :=
  [kindMrds, lenMrds] ++ encodeMrdsValue option

def encodeReq (option : ReqS) : List Nat :=
  [kindReq, lenReq] ++ encodeReqValue option

def encodeRes (option : ResS) : List Nat :=
  [kindRes, lenRes] ++ encodeResValue option

def encodeFrag (option : FragS) : List Nat :=
  [kindFrag, if option.rdos.isSome then lenFragTerminal else lenFragNonTerminal] ++ encodeFragValue option

/-! ## Theorems over Step 7 invariants -/

/-- **APC accepts exactly the 4-byte value length.** -/
theorem decodeApc_accepts_iff (value : List Nat) :
    (∃ apc, decodeApc value = Except.ok apc) ↔ value.length = valueLenOfTotal lenApc := by
  unfold decodeApc
  by_cases h : value.length = valueLenOfTotal lenApc
  · simp [h]
  · simp [h]

/-- **MDS accepts exactly the 2-byte value length.** -/
theorem decodeMds_accepts_iff (value : List Nat) :
    (∃ mds, decodeMds value = Except.ok mds) ↔ value.length = valueLenOfTotal lenMds := by
  unfold decodeMds
  by_cases h : value.length = valueLenOfTotal lenMds
  · simp [h]
  · simp [h]

/-- **MRDS accepts exactly the 3-byte value length.** -/
theorem decodeMrds_accepts_iff (value : List Nat) :
    (∃ mrds, decodeMrds value = Except.ok mrds) ↔ value.length = valueLenOfTotal lenMrds := by
  unfold decodeMrds
  by_cases h : value.length = valueLenOfTotal lenMrds
  · simp [h]
  · simp [h]

/-- **REQ accepts exactly the 4-byte value length.** -/
theorem decodeReq_accepts_iff (value : List Nat) :
    (∃ req, decodeReq value = Except.ok req) ↔ value.length = valueLenOfTotal lenReq := by
  unfold decodeReq
  by_cases h : value.length = valueLenOfTotal lenReq
  · simp [h]
  · simp [h]

/-- **RES accepts exactly the 4-byte value length.** -/
theorem decodeRes_accepts_iff (value : List Nat) :
    (∃ res, decodeRes value = Except.ok res) ↔ value.length = valueLenOfTotal lenRes := by
  unfold decodeRes
  by_cases h : value.length = valueLenOfTotal lenRes
  · simp [h]
  · simp [h]

/-- **FRAG accepts exactly the non-terminal and terminal value lengths.** -/
theorem decodeFrag_accepts_iff (value : List Nat) :
    (∃ frag, decodeFrag value = Except.ok frag) ↔
      value.length = valueLenOfTotal lenFragNonTerminal ∨
        value.length = valueLenOfTotal lenFragTerminal := by
  unfold decodeFrag
  by_cases h8 : value.length = valueLenOfTotal lenFragNonTerminal
  · simp [h8]
  · by_cases h10 : value.length = valueLenOfTotal lenFragTerminal
    · simp [h8, h10, valueLenOfTotal, lenFragNonTerminal, lenFragTerminal, typedTlvHeaderLen]
    · simp [h8, h10]

/-- **Representative APC value bytes decode in big-endian order.** -/
theorem decodeApc_big_endian_representative :
    decodeApc [0x12, 0x34, 0x56, 0x78] = Except.ok { crc32c := 0x12345678 } := by
  rfl

/-- **Representative MDS value bytes decode in big-endian order.** -/
theorem decodeMds_big_endian_representative :
    decodeMds [0x05, 0xdc] = Except.ok { maxDatagramSize := 1500 } := by
  rfl

/-- **Representative MRDS value bytes decode in big-endian order plus the segment byte.** -/
theorem decodeMrds_big_endian_representative :
    decodeMrds [0x0b, 0x6e, 4] = Except.ok { maxReassembledSize := 2926, maxSegments := 4 } := by
  rfl

/-- **Representative REQ encode-value then decode round-trips.** -/
theorem req_encode_decode_round_trip_representative :
    decodeReq (encodeReqValue { token := [0xde, 0xad, 0xbe, 0xef] }) =
      Except.ok { token := [0xde, 0xad, 0xbe, 0xef] } := by
  rfl

/-- **Representative RES encode-value then decode round-trips.** -/
theorem res_encode_decode_round_trip_representative :
    decodeRes (encodeResValue { token := [0xca, 0xfe, 0xba, 0xbe] }) =
      Except.ok { token := [0xca, 0xfe, 0xba, 0xbe] } := by
  rfl

/-- **The non-terminal FRAG length determines that RDOS is absent.** -/
theorem frag_non_terminal_length_has_no_rdos :
    decodeFrag [0, 10, 0, 0, 0, 1, 0, 20] =
      Except.ok { fragStart := 10, identification := 1, fragOffset := 20, rdos := none } := by
  rfl

/-- **The terminal FRAG length determines that RDOS is present.** -/
theorem frag_terminal_length_has_rdos :
    decodeFrag [0, 10, 0, 0, 0, 1, 0, 20, 0, 30] =
      Except.ok { fragStart := 10, identification := 1, fragOffset := 20, rdos := some 30 } := by
  rfl

end Rfc9868
