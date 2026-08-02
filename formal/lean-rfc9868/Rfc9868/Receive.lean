/-!
# Step 10 spec: receive-pipeline disposition

This is a deliberately small model of the RFC 9868 receive gate. It captures the ordering decisions
that Step 10 mirrors in Rust: a failed UDP checksum drops the datagram; a trusted or unused OCS
allows option processing; legacy-emulation OCS cases deliver the UDP user data while discarding all
options; and the Step 10 TLV/FRAG boundary resolves UNSAFE, malformed FRAG, and fragment deferral.

**Honesty note (no extraction):** these theorems are about this Lean model, not about the Rust code
itself. The coupling to Rust is via mirrored table tests, property tests, and the `process_datagram`
fuzz target.
-/

namespace Rfc9868

/-! ## Receive disposition model -/

inductive UdpChecksumState where
  | failed
  | passed
  | zero
  deriving DecidableEq, Repr

inductive OcsState where
  | valid
  | unused
  | ignoreOptions
  | invalid
  deriving DecidableEq, Repr

inductive ReceiveDisposition where
  | dropDatagram
  | processOptions
  | deliverWithoutOptions
  deriving DecidableEq, Repr

inductive TrustedOptionsState where
  | ordinary
  | malformedTlv
  | unsupportedUnsafe
  | unsupportedUnsafeBeforeFrag
  | unsupportedUnsafeThenMalformed
  | validFragEmpty
  | validFragEmptyWithUnsupportedUnsafe
  | validFragEmptyWithMalformedPerFragmentOption
  | validFragEmptyWithDataBytesAfterStart
  | validFragNonEmpty
  | malformedFrag
  | subMinimumFrag
  | duplicateFrag
  | duplicateFragAfterValidEmpty
  | invalidFragStart
  | duplicateKnownSubMinimum
  | assignedSafeSubMinimum
  deriving DecidableEq, Repr

inductive OptionsDisposition where
  | deliverWithOptions
  | deliverWithoutOptions
  | zeroLengthDelivery
  | buffered
  | dropped
  deriving DecidableEq, Repr

def receiveDisposition (udp : UdpChecksumState) (ocs : OcsState) : ReceiveDisposition :=
  match udp with
  | .failed => .dropDatagram
  | .passed =>
      match ocs with
      | .valid | .unused => .processOptions
      | .ignoreOptions | .invalid => .deliverWithoutOptions
  | .zero =>
      match ocs with
      | .valid | .unused => .processOptions
      | .ignoreOptions | .invalid => .deliverWithoutOptions

def trustedOptionsDisposition (state : TrustedOptionsState) : OptionsDisposition :=
  match state with
  | .ordinary => .deliverWithOptions
  | .malformedTlv => .deliverWithoutOptions
  | .unsupportedUnsafe => .zeroLengthDelivery
  | .unsupportedUnsafeBeforeFrag => .zeroLengthDelivery
  | .unsupportedUnsafeThenMalformed => .zeroLengthDelivery
  | .validFragEmpty => .buffered
  | .validFragEmptyWithUnsupportedUnsafe => .dropped
  | .validFragEmptyWithMalformedPerFragmentOption => .dropped
  | .validFragEmptyWithDataBytesAfterStart => .buffered
  | .validFragNonEmpty => .deliverWithoutOptions
  | .malformedFrag => .zeroLengthDelivery
  | .subMinimumFrag => .deliverWithoutOptions
  | .duplicateFrag => .deliverWithoutOptions
  | .duplicateFragAfterValidEmpty => .dropped
  | .invalidFragStart => .zeroLengthDelivery
  | .duplicateKnownSubMinimum => .deliverWithoutOptions
  | .assignedSafeSubMinimum => .deliverWithoutOptions

/-! ## Theorems over the Step 10 matrix -/

/-- **A failed UDP checksum drops the whole datagram before OCS or option processing.** -/
theorem failed_udp_checksum_drops (ocs : OcsState) :
    receiveDisposition .failed ocs = .dropDatagram := by
  cases ocs <;> rfl

/-- **A valid non-zero OCS permits option processing after the UDP checksum gate passes.** -/
theorem passed_udp_valid_ocs_processes_options :
    receiveDisposition .passed .valid = .processOptions := by
  rfl

/-- **Zero UDP checksum plus zero OCS treats the options as assumed correct.** -/
theorem zero_udp_unused_ocs_processes_options :
    receiveDisposition .zero .unused = .processOptions := by
  rfl

/-- **Zero OCS with a non-zero UDP checksum discards options but still delivers user data.** -/
theorem nonzero_udp_zero_ocs_discards_options :
    receiveDisposition .passed .ignoreOptions = .deliverWithoutOptions := by
  rfl

/-- **A bad non-zero OCS discards options but still delivers user data.** -/
theorem invalid_ocs_discards_options (udp : UdpChecksumState)
    (h : udp ≠ UdpChecksumState.failed) :
    receiveDisposition udp .invalid = .deliverWithoutOptions := by
  cases udp with
  | failed => contradiction
  | passed => rfl
  | zero => rfl

/-! ## Theorems over trusted TLV/FRAG option disposition -/

/-- **An unsupported UNSAFE option keeps the zero-length delivery disposition even if later TLV
bytes would be malformed.** -/
theorem unsupported_unsafe_precedes_later_malformed_tlv :
    trustedOptionsDisposition .unsupportedUnsafeThenMalformed = .zeroLengthDelivery := by
  rfl

/-- **An unsupported UNSAFE option terminates processing before a later FRAG can establish fragment
context, so the ordinary legacy-compatible zero-length disposition applies.** -/
theorem unsupported_unsafe_precedes_later_frag :
    trustedOptionsDisposition .unsupportedUnsafeBeforeFrag = .zeroLengthDelivery := by
  rfl

/-- **A malformed FRAG is treated as unsupported UNSAFE, not as the valid-FRAG non-empty-data
exception.** -/
theorem malformed_frag_is_zero_length_delivery :
    trustedOptionsDisposition .malformedFrag = .zeroLengthDelivery := by
  rfl

/-- **A valid empty-payload FRAG with an unsupported UNSAFE per-fragment option produces no user
delivery in Step 10 rather than pretending to be a successfully buffered fragment.** -/
theorem valid_frag_with_unsafe_is_dropped :
    trustedOptionsDisposition .validFragEmptyWithUnsupportedUnsafe = .dropped := by
  rfl

/-- **A malformed per-fragment option before Frag. Start produces no user delivery; individual UDP
fragments are not forwarded to the user.** -/
theorem valid_frag_with_malformed_per_fragment_option_is_dropped :
    trustedOptionsDisposition .validFragEmptyWithMalformedPerFragmentOption = .dropped := by
  rfl

/-- **For an empty-payload FRAG, bytes at or after Frag. Start are fragment data and are not parsed
as more UDP options.** -/
theorem valid_frag_data_bytes_are_not_options :
    trustedOptionsDisposition .validFragEmptyWithDataBytesAfterStart = .buffered := by
  rfl

/-- **A valid FRAG with non-empty UDP user data ignores all options and delivers the user data.** -/
theorem valid_frag_non_empty_discards_options_only :
    trustedOptionsDisposition .validFragNonEmpty = .deliverWithoutOptions := by
  rfl

/-- **A Frag. Start that points before the end of the valid FRAG option is malformed and therefore
follows the unsupported-UNSAFE disposition.** -/
theorem invalid_frag_start_is_zero_length_delivery :
    trustedOptionsDisposition .invalidFragStart = .zeroLengthDelivery := by
  rfl

/-- **A FRAG TLV below the FRAG minimum length follows the generic Sec. 10 malformed-surplus
disposition: discard options but deliver the original UDP user data.** -/
theorem sub_minimum_frag_discards_options :
    trustedOptionsDisposition .subMinimumFrag = .deliverWithoutOptions := by
  rfl

/-- **A duplicate FRAG makes the options area malformed rather than buffering the datagram.** -/
theorem duplicate_frag_discards_options :
    trustedOptionsDisposition .duplicateFrag = .deliverWithoutOptions := by
  rfl

/-- **A duplicate FRAG inside a valid empty-payload fragment option area drops the fragment without
an application-visible zero-length frame.** -/
theorem duplicate_frag_after_valid_empty_is_dropped :
    trustedOptionsDisposition .duplicateFragAfterValidEmpty = .dropped := by
  rfl

/-- **A duplicate known SAFE option still makes the whole options area malformed when its Length is
below that Kind's RFC minimum.** -/
theorem duplicate_known_sub_minimum_discards_options :
    trustedOptionsDisposition .duplicateKnownSubMinimum = .deliverWithoutOptions := by
  rfl

/-- **Assigned but out-of-scope SAFE options such as TIME/EXP are ignored only when their Length is
not below the RFC minimum.** -/
theorem assigned_safe_sub_minimum_discards_options :
    trustedOptionsDisposition .assignedSafeSubMinimum = .deliverWithoutOptions := by
  rfl

end Rfc9868
