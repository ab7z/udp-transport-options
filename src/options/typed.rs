//! Strongly typed option values and the [`TypedOption`] trait.
//!
//! Every typed option in scope is fixed-length, so these are `Copy` plain-old-data with no lifetime;
//! `decode` borrows the value bytes only transiently and returns an owned value.

use crate::error::ParseError;
use crate::model::{kind, length};
use crate::options::kind::OptionKind;

const TLV_HEADER_LEN: usize = 2;
const APC_VALUE_LEN: usize = length::APC as usize - TLV_HEADER_LEN;
const FRAG_NON_TERMINAL_VALUE_LEN: usize = length::FRAG_NON_TERMINAL as usize - TLV_HEADER_LEN;
const FRAG_TERMINAL_VALUE_LEN: usize = length::FRAG_TERMINAL as usize - TLV_HEADER_LEN;
const MDS_VALUE_LEN: usize = length::MDS as usize - TLV_HEADER_LEN;
const MRDS_VALUE_LEN: usize = length::MRDS as usize - TLV_HEADER_LEN;
const REQ_VALUE_LEN: usize = length::REQ as usize - TLV_HEADER_LEN;
const RES_VALUE_LEN: usize = length::RES as usize - TLV_HEADER_LEN;

/// A strongly typed UDP option that can be decoded from, and encoded to, its wire bytes.
pub trait TypedOption: Copy {
    /// The Kind this type represents.
    const KIND: OptionKind;

    /// Decode the option's value bytes (no framing) into an owned value.
    fn decode(value: &[u8]) -> Result<Self, ParseError>;

    /// Append the complete option (Kind + Length + Value) to `out`.
    fn encode(&self, out: &mut Vec<u8>);
}

fn invalid_value_len(kind: u8, value_len: usize) -> ParseError {
    ParseError::InvalidLength {
        kind,
        len: value_len + TLV_HEADER_LEN,
    }
}

fn expect_value_len(value: &[u8], kind: u8, expected: usize) -> Result<(), ParseError> {
    if value.len() == expected {
        Ok(())
    } else {
        Err(invalid_value_len(kind, value.len()))
    }
}

fn write_header(out: &mut Vec<u8>, kind: u8, total_len: u8) {
    out.extend_from_slice(&[kind, total_len]);
}

fn read_u16(value: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([value[offset], value[offset + 1]])
}

fn read_u32(value: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([value[offset], value[offset + 1], value[offset + 2], value[offset + 3]])
}

/// Additional Payload Checksum: a CRC32C over the UDP user data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Apc {
    /// CRC32C (Castagnoli) of the UDP user data.
    pub crc32c: u32,
}

impl Apc {
    /// Computes the APC CRC32C over the conventional UDP user data.
    pub fn compute(udp_user_data: &[u8]) -> Self {
        Self {
            crc32c: crc32c::crc32c(udp_user_data),
        }
    }
}

impl TypedOption for Apc {
    const KIND: OptionKind = OptionKind::Apc;

    fn decode(value: &[u8]) -> Result<Self, ParseError> {
        expect_value_len(value, kind::APC, APC_VALUE_LEN)?;
        Ok(Self {
            crc32c: read_u32(value, 0),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_header(out, kind::APC, length::APC);
        out.extend_from_slice(&self.crc32c.to_be_bytes());
    }
}

/// Maximum Datagram Size: the largest datagram the sender can receive without IP fragmentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mds {
    /// Maximum datagram size, in bytes.
    pub max_datagram_size: u16,
}

impl TypedOption for Mds {
    const KIND: OptionKind = OptionKind::Mds;

    fn decode(value: &[u8]) -> Result<Self, ParseError> {
        expect_value_len(value, kind::MDS, MDS_VALUE_LEN)?;
        Ok(Self {
            max_datagram_size: read_u16(value, 0),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_header(out, kind::MDS, length::MDS);
        out.extend_from_slice(&self.max_datagram_size.to_be_bytes());
    }
}

/// Maximum Reassembled Datagram Size and the maximum number of fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mrds {
    /// Maximum reassembled datagram size, in bytes.
    pub max_reassembled_size: u16,
    /// Maximum number of fragments the sender can reassemble.
    pub max_segments: u8,
}

impl TypedOption for Mrds {
    const KIND: OptionKind = OptionKind::Mrds;

    fn decode(value: &[u8]) -> Result<Self, ParseError> {
        expect_value_len(value, kind::MRDS, MRDS_VALUE_LEN)?;
        Ok(Self {
            max_reassembled_size: read_u16(value, 0),
            max_segments: value[2],
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_header(out, kind::MRDS, length::MRDS);
        out.extend_from_slice(&self.max_reassembled_size.to_be_bytes());
        out.push(self.max_segments);
    }
}

/// Echo Request: an opaque 4-byte token the peer may echo back in a [`Res`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Req {
    /// Opaque request token.
    pub token: [u8; 4],
}

impl TypedOption for Req {
    const KIND: OptionKind = OptionKind::Req;

    fn decode(value: &[u8]) -> Result<Self, ParseError> {
        expect_value_len(value, kind::REQ, REQ_VALUE_LEN)?;
        Ok(Self {
            token: value.try_into().expect("REQ value length was validated"),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_header(out, kind::REQ, length::REQ);
        out.extend_from_slice(&self.token);
    }
}

/// Echo Response: echoes the token from a received [`Req`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Res {
    /// Echoed request token.
    pub token: [u8; 4],
}

impl TypedOption for Res {
    const KIND: OptionKind = OptionKind::Res;

    fn decode(value: &[u8]) -> Result<Self, ParseError> {
        expect_value_len(value, kind::RES, RES_VALUE_LEN)?;
        Ok(Self {
            token: value.try_into().expect("RES value length was validated"),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_header(out, kind::RES, length::RES);
        out.extend_from_slice(&self.token);
    }
}

/// The Fragmentation option (RFC 9868). `rdos` distinguishes terminal from non-terminal fragments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frag {
    /// Byte offset, from the start of the UDP header, where this fragment's data begins.
    pub frag_start: u16,
    /// Identifier shared by all fragments of one original datagram.
    pub identification: u32,
    /// Byte offset, in the reassembled datagram, where this fragment's data belongs.
    pub frag_offset: u16,
    /// `Some(rdos)` for a terminal fragment (the Reassembled-Datagram-Option-Start); `None` for a
    /// non-terminal fragment.
    pub rdos: Option<u16>,
}

impl TypedOption for Frag {
    const KIND: OptionKind = OptionKind::Frag;

    fn decode(value: &[u8]) -> Result<Self, ParseError> {
        if value.len() != FRAG_NON_TERMINAL_VALUE_LEN && value.len() != FRAG_TERMINAL_VALUE_LEN {
            return Err(invalid_value_len(kind::FRAG, value.len()));
        }

        Ok(Self {
            frag_start: read_u16(value, 0),
            identification: read_u32(value, 2),
            frag_offset: read_u16(value, 6),
            rdos: (value.len() == FRAG_TERMINAL_VALUE_LEN).then(|| read_u16(value, 8)),
        })
    }

    fn encode(&self, out: &mut Vec<u8>) {
        write_header(
            out,
            kind::FRAG,
            if self.rdos.is_some() {
                length::FRAG_TERMINAL
            } else {
                length::FRAG_NON_TERMINAL
            },
        );
        out.extend_from_slice(&self.frag_start.to_be_bytes());
        out.extend_from_slice(&self.identification.to_be_bytes());
        out.extend_from_slice(&self.frag_offset.to_be_bytes());
        if let Some(rdos) = self.rdos {
            out.extend_from_slice(&rdos.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Apc, Frag, Mds, Mrds, Req, Res, TypedOption};
    use crate::error::ParseError;
    use crate::model::{kind, length};
    use crate::options::parse::OptionsIter;
    use std::fmt::Debug;

    fn round_trip<T>(option: T)
    where
        T: TypedOption + Debug + PartialEq,
    {
        let mut bytes = Vec::new();
        option.encode(&mut bytes);

        let mut iter = OptionsIter::new(&bytes);
        let parsed = iter.next().expect("encoded option").expect("valid encoded option");
        assert_eq!(parsed.kind, T::KIND);
        assert_eq!(T::decode(parsed.value), Ok(option));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn typed_options_encode_parse_decode_round_trip() {
        round_trip(Apc { crc32c: 0x1234_5678 });
        round_trip(Mds {
            max_datagram_size: 1500,
        });
        round_trip(Mrds {
            max_reassembled_size: 2926,
            max_segments: 4,
        });
        round_trip(Req {
            token: [0xde, 0xad, 0xbe, 0xef],
        });
        round_trip(Res {
            token: [0xca, 0xfe, 0xba, 0xbe],
        });
        round_trip(Frag {
            frag_start: 32,
            identification: 0x0102_0304,
            frag_offset: 8,
            rdos: None,
        });
        round_trip(Frag {
            frag_start: 48,
            identification: 0x1112_1314,
            frag_offset: 16,
            rdos: Some(4096),
        });
    }

    #[test]
    fn encodes_big_endian_wire_bytes() {
        let mut bytes = Vec::new();
        Mrds {
            max_reassembled_size: 0x0b6e,
            max_segments: 0x04,
        }
        .encode(&mut bytes);
        assert_eq!(bytes, [kind::MRDS, length::MRDS, 0x0b, 0x6e, 0x04]);

        bytes.clear();
        Frag {
            frag_start: 0x0018,
            identification: 0x0102_0304,
            frag_offset: 0x0506,
            rdos: Some(0x0708),
        }
        .encode(&mut bytes);
        assert_eq!(
            bytes,
            [
                kind::FRAG,
                length::FRAG_TERMINAL,
                0x00,
                0x18,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08
            ]
        );
    }

    #[test]
    fn apc_compute_matches_crc32c_vector() {
        let user_data = b"123456789";
        assert_eq!(crc32c::crc32c(user_data), 0xe306_9283);
        assert_eq!(Apc::compute(user_data), Apc { crc32c: 0xe306_9283 });
    }

    #[test]
    fn typed_decoders_reject_wrong_value_lengths() {
        fn assert_invalid_len<T: TypedOption + Debug + PartialEq>(
            actual: Result<T, ParseError>,
            option_kind: u8,
            len: usize,
        ) {
            assert_eq!(actual, Err(ParseError::InvalidLength { kind: option_kind, len }));
        }

        assert_invalid_len(Apc::decode(&[0; 3]), kind::APC, 5);
        assert_invalid_len(Mds::decode(&[0; 1]), kind::MDS, 3);
        assert_invalid_len(Mrds::decode(&[0; 2]), kind::MRDS, 4);
        assert_invalid_len(Req::decode(&[0; 5]), kind::REQ, 7);
        assert_invalid_len(Res::decode(&[0; 0]), kind::RES, 2);
        assert_invalid_len(Frag::decode(&[0; 9]), kind::FRAG, 11);
    }

    #[test]
    fn frag_length_selects_terminal_flag() {
        assert_eq!(
            Frag::decode(&[0, 10, 0, 0, 0, 1, 0, 20]),
            Ok(Frag {
                frag_start: 10,
                identification: 1,
                frag_offset: 20,
                rdos: None,
            })
        );
        assert_eq!(
            Frag::decode(&[0, 10, 0, 0, 0, 1, 0, 20, 0, 30]),
            Ok(Frag {
                frag_start: 10,
                identification: 1,
                frag_offset: 20,
                rdos: Some(30),
            })
        );
    }
}
