import Rfc9868.Tlv

/-!
# Step 05 spec: canonical UDP option serialization

A small model of the Step 5 serializer contract. The model emits the OCS-led body, not the optional
pre-OCS pad byte used when the surplus area starts at an odd IP-datagram offset.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored constants, unit tests, property tests, and the
`options_serialize` fuzz target. The model covers accepted builder inputs and canonical emission; it
does not model the Rust builder's rejection errors for reserved/UNSAFE kinds or oversized bodies.
-/

namespace Rfc9868

/-! ## Serialize model -/

def ocsPlaceholderLength : Nat := 2
def udpHeaderLength : Nat := 8
def defaultValueLengthMax : Nat := 252
def extendedValueLengthMax : Nat := 65531
def freeRawSafeMin : Nat := 10
def freeRawSafeMax : Nat := 126

structure RawOptionS where
  kind : Nat
  valueLen : Nat
  deriving DecidableEq, Repr

def isFreeRawSafeKind (kind : Nat) : Prop :=
  freeRawSafeMin ≤ kind ∧ kind ≤ freeRawSafeMax

def isBuilderAcceptedKind (kind : Nat) : Prop :=
  kind = kindApc ∨ kind = kindFrag ∨ kind = kindMds ∨ kind = kindMrds ∨
    kind = kindReq ∨ kind = kindRes ∨ isFreeRawSafeKind kind

def canonicalRank (kind : Nat) : Nat :=
  if kind = kindFrag then 0
  else if kind = kindApc then 1
  else if kind = kindMds then 2
  else if kind = kindMrds then 3
  else if kind = kindReq then 4
  else if kind = kindRes then 5
  else 1000 + kind

def optionTotalLength (option : RawOptionS) : Nat :=
  if option.valueLen ≤ defaultValueLengthMax then
    option.valueLen + minDefaultTlvLength
  else
    option.valueLen + extendedHeaderLength

def zeroBytes (n : Nat) : List Nat :=
  List.replicate n 0

def encodeOption (option : RawOptionS) : List Nat :=
  if option.valueLen ≤ defaultValueLengthMax then
    [option.kind, option.valueLen + minDefaultTlvLength] ++ zeroBytes option.valueLen
  else
    let totalLen := option.valueLen + extendedHeaderLength
    [option.kind, extendedLengthMarker, totalLen / 256, totalLen % 256] ++ zeroBytes option.valueLen

def valueBytesWithFragStart (fragStart : Nat) (option : RawOptionS) : List Nat :=
  if option.kind = kindFrag ∧ 2 ≤ option.valueLen then
    [fragStart / 256, fragStart % 256] ++ zeroBytes (option.valueLen - 2)
  else
    zeroBytes option.valueLen

def encodeOptionWithFragStart (fragStart : Nat) (option : RawOptionS) : List Nat :=
  if option.valueLen ≤ defaultValueLengthMax then
    [option.kind, option.valueLen + minDefaultTlvLength] ++ valueBytesWithFragStart fragStart option
  else
    let totalLen := option.valueLen + extendedHeaderLength
    [option.kind, extendedLengthMarker, totalLen / 256, totalLen % 256] ++ valueBytesWithFragStart fragStart option

def alignBeforeTlv (body : List Nat) : List Nat :=
  if body.length % 2 = 0 then body else body ++ [kindNop]

def appendOption (body : List Nat) (option : RawOptionS) : List Nat :=
  alignBeforeTlv body ++ encodeOption option

def appendOptionWithFragStart (fragStart : Nat) (body : List Nat) (option : RawOptionS) : List Nat :=
  alignBeforeTlv body ++ encodeOptionWithFragStart fragStart option

def insertCanonical (option : RawOptionS) : List RawOptionS → List RawOptionS
  | [] => [option]
  | head :: tail =>
      if canonicalRank option.kind < canonicalRank head.kind then
        option :: head :: tail
      else
        head :: insertCanonical option tail

def canonicalOrder (options : List RawOptionS) : List RawOptionS :=
  options.foldl (fun sorted option => insertCanonical option sorted) []

def zeroFillEven (bytes : List Nat) : List Nat :=
  if bytes.length % 2 = 0 then bytes else bytes ++ [0]

def canonicalBodyLength (options : List RawOptionS) : Nat :=
  (zeroFillEven (options.foldl appendOption (zeroBytes ocsPlaceholderLength) ++ [kindEol])).length

def canonicalBody (options : List RawOptionS) : List Nat :=
  let ordered := canonicalOrder options
  let fragStart := udpHeaderLength + canonicalBodyLength ordered
  zeroFillEven (ordered.foldl (appendOptionWithFragStart fragStart) (zeroBytes ocsPlaceholderLength) ++ [kindEol])

def optionsAfterOcs (body : List Nat) : List Nat :=
  body.drop ocsPlaceholderLength

/-! ## Theorems over Step 5 invariants and representative cases -/

/-- **The default-format boundary is value length 252, total TLV length 254.** -/
theorem optionTotalLength_default_boundary :
    optionTotalLength { kind := 10, valueLen := 252 } = 254 := by
  simp [optionTotalLength, defaultValueLengthMax, minDefaultTlvLength]

/-- **The extended-format boundary starts at value length 253, total TLV length 257.** -/
theorem optionTotalLength_extended_boundary :
    optionTotalLength { kind := 10, valueLen := 253 } = 257 := by
  simp [optionTotalLength, defaultValueLengthMax, extendedHeaderLength]

/-- **Zero-fill always returns an even-length byte list.** -/
theorem zeroFillEven_length_even (bytes : List Nat) :
    (zeroFillEven bytes).length % 2 = 0 := by
  unfold zeroFillEven
  split
  · assumption
  · simp
    omega

/-- **Every canonical serialized body has even length.** -/
theorem canonicalBody_length_even (options : List RawOptionS) :
    (canonicalBody options).length % 2 = 0 := by
  unfold canonicalBody
  exact zeroFillEven_length_even _

/-- **REQ and FRAG are representative accepted builder input kinds.** -/
theorem req_frag_are_builder_accepted :
    isBuilderAcceptedKind kindReq ∧ isBuilderAcceptedKind kindFrag := by
  simp [isBuilderAcceptedKind]

/-- **TIME is assigned but out of scope for the Step 5 raw builder.** -/
theorem time_is_not_builder_accepted :
    ¬ isBuilderAcceptedKind kindTime := by
  unfold isBuilderAcceptedKind isFreeRawSafeKind
  unfold kindTime kindApc kindFrag kindMds kindMrds kindReq kindRes freeRawSafeMin freeRawSafeMax
  omega

/-- **Canonical ordering moves FRAG ahead of a later REQ.** -/
theorem canonicalOrder_reorders_req_frag :
    canonicalOrder
      [
        { kind := kindReq, valueLen := 4 },
        { kind := kindFrag, valueLen := 8 }
      ] =
      [
        { kind := kindFrag, valueLen := 8 },
        { kind := kindReq, valueLen := 4 }
      ] := by
  decide

/-- **The serialized body for non-canonical REQ,FRAG input emits FRAG first.** -/
theorem canonicalBody_reorders_req_frag :
    canonicalBody
      [
        { kind := kindReq, valueLen := 4 },
        { kind := kindFrag, valueLen := 8 }
      ] =
      [0, 0, kindFrag, 10, 0, 28, 0, 0, 0, 0, 0, 0, kindReq, 6, 0, 0, 0, 0, kindEol, 0] := by
  decide

/-- **FRAG Start is patched to UDP header length plus final body length.** -/
theorem canonicalBody_patches_frag_start :
    canonicalBody [{ kind := kindFrag, valueLen := 8 }] =
      [0, 0, kindFrag, 10, 0, 22, 0, 0, 0, 0, 0, 0, kindEol, 0] := by
  decide

/-- **An empty option set serializes to OCS placeholder, EOL, and one zero-fill byte.** -/
theorem canonicalBody_empty :
    canonicalBody [] = [0, 0, kindEol, 0] := by
  decide

/-- **The empty canonical body parses as a single EOL after the OCS placeholder.** -/
theorem parse_empty_canonical_body_eol :
    (parse (optionsAfterOcs (canonicalBody []))).items =
      [
        ParseItem.option
          { kind := kindEol, start := 0, headerLen := 1, valueLen := 0, nextPos := 1, isEol := true }
      ] := by
  decide

/-- **A representative odd-length TLV is followed by one inter-option NOP before the next TLV.** -/
theorem canonicalBody_inserts_inter_option_nop :
    canonicalBody
      [
        { kind := kindMrds, valueLen := 3 },
        { kind := kindReq, valueLen := 4 }
      ] =
      [0, 0, kindMrds, 5, 0, 0, 0, kindNop, kindReq, 6, 0, 0, 0, 0, kindEol, 0] := by
  decide

set_option maxRecDepth 10000

/-- **A representative extended-boundary option is well-formed under the Step 4 parser model.** -/
theorem parse_extended_boundary_canonical_body :
    (parse
      (optionsAfterOcs
        (canonicalBody [{ kind := 10, valueLen := 253 }]))).items =
      [
        ParseItem.option
          { kind := 10, start := 0, headerLen := extendedHeaderLength, valueLen := 253, nextPos := 257, isEol := false },
        ParseItem.option
          { kind := kindEol, start := 257, headerLen := 1, valueLen := 0, nextPos := 258, isEol := true }
      ] := by
  decide

end Rfc9868
