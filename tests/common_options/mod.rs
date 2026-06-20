// Shared TLV parser invariant oracle.
//
// Used by `mod common_options;` from the property tests and spliced into the `options_tlv` fuzz
// target via `include!`. The oracle stays at the parser boundary: it checks totality, halt
// behavior, borrowed value ranges, and NOP-run accounting without applying receive-pipeline policy.

use udp_transport_options::options::kind::OptionKind;
use udp_transport_options::options::parse::OptionsIter;

/// Asserts parser invariants over arbitrary option bytes after the OCS field.
///
/// Returns silently for malformed input after confirming that the iterator reports exactly one
/// error and then halts. Arbitrary fuzz input must never panic or loop forever.
pub fn check_tlv_parser_invariants(bytes: &[u8]) {
    let mut iter = OptionsIter::new(bytes);
    let mut yielded = 0usize;
    let mut current_nop_run = 0usize;
    let mut max_nop_run = 0usize;
    let base = bytes.as_ptr() as usize;
    let end = base + bytes.len();

    while let Some(item) = iter.next() {
        yielded += 1;
        assert!(yielded <= bytes.len() + 1);

        match item {
            Ok(option) => {
                match option.kind {
                    OptionKind::Eol => {
                        assert!(option.value.is_empty());
                        assert_eq!(iter.next(), None);
                        assert_eq!(iter.max_nop_run(), max_nop_run);
                        return;
                    }
                    OptionKind::Nop => {
                        assert!(option.value.is_empty());
                        current_nop_run += 1;
                        max_nop_run = max_nop_run.max(current_nop_run);
                    }
                    _ => {
                        current_nop_run = 0;
                        if !option.value.is_empty() {
                            let value_start = option.value.as_ptr() as usize;
                            assert!(value_start >= base);
                            assert!(value_start + option.value.len() <= end);
                        }
                    }
                }
                assert_eq!(iter.max_nop_run(), max_nop_run);
            }
            Err(_) => {
                assert_eq!(iter.next(), None);
                assert_eq!(iter.max_nop_run(), max_nop_run);
                return;
            }
        }
    }

    assert_eq!(iter.max_nop_run(), max_nop_run);
}
