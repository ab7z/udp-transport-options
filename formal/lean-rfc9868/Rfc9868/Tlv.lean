import Rfc9868.Kind

/-!
# Step 04 spec: UDP option TLV parsing

A small, total model of the RFC 9868 option stream after the OCS field. This mirrors the Step 4 Rust
iterator contract: EOL and NOP are single-byte options, all other Kinds use default or extended
length framing, the first malformed frame yields one error, and parsing then stops.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored constants, Rust unit tests, property tests, and the
`options_tlv` fuzz target. The model operates over `List Nat`; byte-valued inputs are stated
explicitly with `bytesInU8Range`.
-/

namespace Rfc9868

/-! ## Parse model -/

def minDefaultTlvLength : Nat := 2
def extendedHeaderLength : Nat := 4
def firstExtendedOnlyLength : Nat := 255

def be16 (hi lo : Nat) : Nat :=
  hi * 256 + lo

def bytesInU8Range (bytes : List Nat) : Prop :=
  ∀ byte ∈ bytes, byte < 256

inductive TlvError where
  | invalidLength (kind len : Nat)
  | overrun (offset : Nat)
  deriving DecidableEq, Repr

structure ParsedOption where
  kind : Nat
  start : Nat
  headerLen : Nat
  valueLen : Nat
  nextPos : Nat
  isEol : Bool
  deriving DecidableEq, Repr

inductive ParseStep where
  | done
  | option (option : ParsedOption) (currentNopRun maxNopRun : Nat)
  | error (error : TlvError)
  deriving DecidableEq, Repr

inductive ParseItem where
  | option (option : ParsedOption)
  | error (error : TlvError)
  deriving DecidableEq, Repr

structure ParseTrace where
  items : List ParseItem
  pos : Nat
  maxNopRun : Nat
  stopped : Bool
  deriving DecidableEq, Repr

def parseOne (bytes : List Nat) (pos currentNopRun maxNopRun : Nat) : ParseStep :=
  match bytes.drop pos with
  | [] => ParseStep.done
  | kind :: rest =>
      if kind = kindEol then
        ParseStep.option
          { kind := kind, start := pos, headerLen := 1, valueLen := 0, nextPos := pos + 1, isEol := true }
          0
          maxNopRun
      else if kind = kindNop then
        let run := currentNopRun + 1
        ParseStep.option
          { kind := kind, start := pos, headerLen := 1, valueLen := 0, nextPos := pos + 1, isEol := false }
          run
          (Nat.max maxNopRun run)
      else
        match rest with
        | [] => ParseStep.error (TlvError.overrun pos)
        | len :: restAfterLen =>
            if len = extendedLengthMarker then
              match restAfterLen with
              | hi :: lo :: _ =>
                  let extLen := be16 hi lo
                  if extLen < firstExtendedOnlyLength then
                    ParseStep.error (TlvError.invalidLength kind extLen)
                  else if bytes.length < pos + extLen then
                    ParseStep.error (TlvError.overrun pos)
                  else
                    ParseStep.option
                      {
                        kind := kind,
                        start := pos,
                        headerLen := extendedHeaderLength,
                        valueLen := extLen - extendedHeaderLength,
                        nextPos := pos + extLen,
                        isEol := false
                      }
                      0
                      maxNopRun
              | _ => ParseStep.error (TlvError.overrun pos)
            else if len < minDefaultTlvLength then
              ParseStep.error (TlvError.invalidLength kind len)
            else if bytes.length < pos + len then
              ParseStep.error (TlvError.overrun pos)
            else
              ParseStep.option
                {
                  kind := kind,
                  start := pos,
                  headerLen := minDefaultTlvLength,
                  valueLen := len - minDefaultTlvLength,
                  nextPos := pos + len,
                  isEol := false
                }
                0
                maxNopRun

def parseLoop : Nat → List Nat → Nat → Nat → Nat → ParseTrace
  | 0, _, pos, _, maxNopRun => { items := [], pos := pos, maxNopRun := maxNopRun, stopped := true }
  | fuel + 1, bytes, pos, currentNopRun, maxNopRun =>
      match parseOne bytes pos currentNopRun maxNopRun with
      | ParseStep.done => { items := [], pos := pos, maxNopRun := maxNopRun, stopped := true }
      | ParseStep.error error =>
          { items := [ParseItem.error error], pos := pos, maxNopRun := maxNopRun, stopped := true }
      | ParseStep.option option currentNopRun' maxNopRun' =>
          if option.isEol then
            {
              items := [ParseItem.option option],
              pos := option.nextPos,
              maxNopRun := maxNopRun',
              stopped := true
            }
          else
            let rest := parseLoop fuel bytes option.nextPos currentNopRun' maxNopRun'
            {
              items := ParseItem.option option :: rest.items,
              pos := rest.pos,
              maxNopRun := rest.maxNopRun,
              stopped := rest.stopped
            }

def parse (bytes : List Nat) : ParseTrace :=
  parseLoop (bytes.length + 1) bytes 0 0 0

/-! ## Theorems over representative Step 4 cases -/

/-- **The byte-domain assumption is explicit for representative parser inputs.** -/
theorem sample_bytes_in_u8_range :
    bytesInU8Range [kindNop, kindApc, 2, kindEol] := by
  intro byte h
  simp [bytesInU8Range, kindNop, kindApc, kindEol] at h
  omega

/-- **Every bounded parser loop reduces to a stopped trace.** -/
theorem parseLoop_stopped
    (fuel : Nat)
    (bytes : List Nat)
    (pos currentNopRun maxNopRun : Nat) :
    (parseLoop fuel bytes pos currentNopRun maxNopRun).stopped = true := by
  induction fuel generalizing pos currentNopRun maxNopRun with
  | zero =>
      simp [parseLoop]
  | succ fuel ih =>
      simp [parseLoop]
      split
      · rfl
      · rfl
      · split
        · rfl
        · exact ih _ _ _

/-- **The parser model is total in the Lean sense: every input reduces to a stopped trace.** -/
theorem parse_stopped (bytes : List Nat) : (parse bytes).stopped = true := by
  exact parseLoop_stopped (bytes.length + 1) bytes 0 0 0

/-- **Empty option bytes are accepted as the end of the stream.** -/
theorem parseOne_empty : parseOne [] 0 0 0 = ParseStep.done := by
  rfl

/-- **EOL is a one-byte option and terminates the stream.** -/
theorem parse_eol_stops (tail : List Nat) :
    (parse (kindEol :: tail)).items.length = 1 := by
  simp [parse, parseLoop, parseOne, kindEol, kindNop]

/-- **NOP is a one-byte option that advances the consecutive-NOP run.** -/
theorem parseOne_nop_run :
    parseOne [kindNop] 0 2 4 =
      ParseStep.option
        { kind := kindNop, start := 0, headerLen := 1, valueLen := 0, nextPos := 1, isEol := false }
        3
        (Nat.max 4 3) := by
  simp [parseOne, kindEol, kindNop]

/-- **A non-single-byte Kind without a Length field is an overrun at the option start.** -/
theorem parseOne_missing_length :
    parseOne [kindApc] 0 0 0 = ParseStep.error (TlvError.overrun 0) := by
  simp [parseOne, kindEol, kindNop, kindApc]

/-- **Default Length values below two are malformed.** -/
theorem parseOne_default_length_too_short :
    parseOne [kindApc, 1] 0 0 0 = ParseStep.error (TlvError.invalidLength kindApc 1) := by
  simp [parseOne, kindEol, kindNop, kindApc, extendedLengthMarker, minDefaultTlvLength]

/-- **Extended Length values below 255 are malformed in the strict RFC model.** -/
theorem parseOne_extended_length_too_short :
    parseOne [kindApc, extendedLengthMarker, 0, 254] 0 0 0 =
      ParseStep.error (TlvError.invalidLength kindApc 254) := by
  simp [parseOne, kindEol, kindNop, kindApc, extendedLengthMarker, firstExtendedOnlyLength, be16]

/-- **Any `parseOne` error yields exactly one error item and stops the loop.** -/
theorem parseLoop_error_stops_after_one
    (fuel : Nat)
    (bytes : List Nat)
    (pos currentNopRun maxNopRun : Nat)
    (error : TlvError)
    (h : parseOne bytes pos currentNopRun maxNopRun = ParseStep.error error) :
    parseLoop (fuel + 1) bytes pos currentNopRun maxNopRun =
      { items := [ParseItem.error error], pos := pos, maxNopRun := maxNopRun, stopped := true } := by
  simp [parseLoop, h]

/-- **The first malformed representative option yields exactly one error item and stops.** -/
theorem parse_missing_length_error_stops_after_one :
    (parse [kindApc]).items = [ParseItem.error (TlvError.overrun 0)] := by
  simp [parse, parseLoop, parseOne, kindEol, kindNop, kindApc]

/-- **Default TLVs are yielded in stream order and advance by their total Length.** -/
theorem parse_default_options_in_stream_order :
    (parse [kindApc, 2, kindMds, 4, 0, 0]).items =
      [
        ParseItem.option
          { kind := kindApc, start := 0, headerLen := minDefaultTlvLength, valueLen := 0, nextPos := 2, isEol := false },
        ParseItem.option
          { kind := kindMds, start := 2, headerLen := minDefaultTlvLength, valueLen := 2, nextPos := 6, isEol := false }
      ] := by
  simp [parse, parseLoop, parseOne, kindEol, kindNop, kindApc, kindMds, extendedLengthMarker, minDefaultTlvLength]

set_option maxRecDepth 10000

/-- **Extended TLVs advance by the 16-bit total Extended Length.** -/
theorem parse_extended_option_advances_by_total_length :
    parseOne (kindApc :: extendedLengthMarker :: 0 :: 255 :: List.replicate 251 0) 0 0 0 =
      ParseStep.option
        {
          kind := kindApc,
          start := 0,
          headerLen := extendedHeaderLength,
          valueLen := 251,
          nextPos := 255,
          isEol := false
        }
        0
        0 := by
  rfl

end Rfc9868
