//! The one's-complement Internet checksum (RFC 1071).
//!
//! This primitive backs both the UDP checksum and the RFC 9868 Option Checksum (OCS), so it is
//! hand-rolled rather than pulled from a crate.

/// Incremental one's-complement sum accumulator.
///
/// Callers feed in several regions (for example a pseudo-header plus a payload) without copying
/// them into one buffer, then take either the folded sum (OCS validation expects the all-ones
/// pattern) or its complement (the value stored on the wire).
#[derive(Debug, Clone, Copy, Default)]
pub struct Checksum {
    sum: u32,
}

impl Checksum {
    /// Creates an empty accumulator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a byte slice as a sequence of 16-bit big-endian words.
    ///
    /// A trailing odd byte is treated as the high byte of a final word whose low byte is zero;
    /// each call therefore pads its own slice to an even length. Callers that sum multiple
    /// regions must keep every region except the last word-aligned (RFC 1071 Section 2(A): the
    /// even/odd byte assignment must be respected).
    pub fn add_slice(&mut self, bytes: &[u8]) {
        let mut words = bytes.chunks_exact(2);
        for word in words.by_ref() {
            self.add_u16(u16::from_be_bytes([word[0], word[1]]));
        }
        if let &[last] = words.remainder() {
            self.add_u16(u16::from_be_bytes([last, 0]));
        }
    }

    /// Adds a single 16-bit scalar field (for example the surplus length or a pseudo-header
    /// field).
    pub fn add_u16(&mut self, value: u16) {
        // Eager end-around folding keeps the running sum below 2^17, so the u32 accumulator
        // cannot overflow regardless of input length.
        self.sum += u32::from(value);
        self.sum = (self.sum & 0xffff) + (self.sum >> 16);
    }

    /// Returns the folded, non-complemented sum. Data summed together with its stored complement
    /// yields `0xffff` (one's-complement zero) here.
    pub fn sum(&self) -> u16 {
        let mut sum = self.sum;
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        sum as u16
    }

    /// Returns the one's complement of the folded sum: the value stored in a checksum field.
    ///
    /// This is the raw RFC 1071 complement and is `0x0000` whenever the folded sum is `0xffff`.
    /// It is not normalized for any wire format: UDP transmits `0xffff` in place of a computed
    /// zero (RFC 768), and the OCS must be non-zero whenever the UDP checksum is non-zero
    /// (RFC 9868 Section 9; FR-21). Those zero rules belong to the UDP/OCS writers, not here.
    pub fn finish(&self) -> u16 {
        !self.sum()
    }
}

/// One-shot convenience over [`Checksum`]: the complemented checksum of a single byte slice.
///
/// Returns the raw complement; the zero-normalization caveat on [`Checksum::finish`] applies.
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut checksum = Checksum::new();
    checksum.add_slice(bytes);
    checksum.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example from RFC 1071 Section 3.
    const RFC1071_EXAMPLE: [u8; 8] = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];

    #[test]
    fn rfc1071_worked_example() {
        let mut checksum = Checksum::new();
        checksum.add_slice(&RFC1071_EXAMPLE);
        assert_eq!(checksum.sum(), 0xddf2);
        assert_eq!(checksum.finish(), 0x220d);
        assert_eq!(internet_checksum(&RFC1071_EXAMPLE), 0x220d);
    }

    #[test]
    fn odd_length_trailing_byte_is_high_byte() {
        // 0x0102 + 0x0300 = 0x0402.
        assert_eq!(internet_checksum(&[0x01, 0x02, 0x03]), !0x0402);
        // A single byte is the high byte of the only word.
        assert_eq!(internet_checksum(&[0xab]), !0xab00);
    }

    #[test]
    fn all_zero_input() {
        let mut checksum = Checksum::new();
        checksum.add_slice(&[0x00; 6]);
        assert_eq!(checksum.sum(), 0x0000);
        assert_eq!(checksum.finish(), 0xffff);
        assert_eq!(internet_checksum(&[]), 0xffff);
    }

    #[test]
    fn end_around_carry_folds() {
        // 0xffff + 0xffff = 0x1fffe -> fold -> 0xffff.
        assert_eq!(internet_checksum(&[0xff, 0xff, 0xff, 0xff]), 0x0000);
        // 0x8000 + 0x8001 = 0x10001 -> fold -> 0x0002.
        assert_eq!(internet_checksum(&[0x80, 0x00, 0x80, 0x01]), !0x0002);
    }

    #[test]
    fn data_plus_stored_complement_sums_to_ones() {
        for data in [
            &RFC1071_EXAMPLE[..],
            &[0x00; 6][..],
            &[0xff; 5][..],
            &[0xde, 0xad, 0xbe, 0xef, 0x01][..],
        ] {
            let stored = internet_checksum(data);
            let mut verify = Checksum::new();
            verify.add_slice(data);
            verify.add_u16(stored);
            assert_eq!(verify.sum(), 0xffff, "data {data:02x?}");
            assert_eq!(verify.finish(), 0x0000, "data {data:02x?}");
        }
    }

    #[test]
    fn incremental_matches_one_shot() {
        let (head, tail) = RFC1071_EXAMPLE.split_at(4);
        let mut split = Checksum::new();
        split.add_slice(head);
        split.add_slice(tail);
        assert_eq!(split.finish(), internet_checksum(&RFC1071_EXAMPLE));

        let mut scalar = Checksum::new();
        scalar.add_u16(0xf203);
        let mut slice = Checksum::new();
        slice.add_slice(&[0xf2, 0x03]);
        assert_eq!(scalar.sum(), slice.sum());
    }
}
