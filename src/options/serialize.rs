//! The option serializer.
//!
//! Added in Step 5: an `OptionsBuilder` that emits options in canonical order (must-support first),
//! pads with NOP for alignment, terminates with EOL, and zero-fills to a 2-byte boundary. The OCS is
//! reserved as the first option and back-patched in Step 6.
