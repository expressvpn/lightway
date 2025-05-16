use bytes::{Buf, BufMut, BytesMut};

use super::{FromWireError, FromWireResult};
use crate::borrowed_bytesmut::BorrowedBytesMut;
/// Encoding Response in lightway-core
///
/// Wire format (fixed length):
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               id                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                               id                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      enable   |
/// +-+-+-+-+-+-+-+-+
/// ```
///
/// Frame size is fixed at 9 bytes.
#[derive(PartialEq, Debug)]
pub(crate) struct EncodingResponse {
    pub(crate) id: u64,
    pub(crate) enable: bool,
}

impl EncodingResponse {
    /// Wire Size in bytes
    const WIRE_SIZE: usize = 9;

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(FromWireError::InsufficientData);
        };

        let id = buf.get_u64();
        let enable = buf.get_u8();

        match enable {
            0 => Ok(Self { id, enable: false }),
            1 => Ok(Self { id, enable: true }),
            _ => Err(FromWireError::InvalidBool),
        }
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(Self::WIRE_SIZE);

        let encoding_enabled = if self.enable { 1 } else { 0 };

        buf.put_u64(self.id);
        buf.put_u8(encoding_enabled);
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;
    use test_case::test_case;

    #[test]
    fn from_wire_enabled() {
        let mut buf = ImmutableBytesMut::from(&b"\x00\x00\x00\x00\x00\x00\x02\x01\x01"[..]);
        let mut buf = buf.as_borrowed_bytesmut();

        let wire = EncodingResponse::try_from_wire(&mut buf).expect("enabled");
        assert_eq!(wire.id, 513_u64);
        assert!(wire.enable);
    }

    #[test]
    fn from_wire_disabled() {
        let mut buf = ImmutableBytesMut::from(&b"\x00\x00\x00\x00\x00\x00\x02\x02\x00"[..]);
        let mut buf = buf.as_borrowed_bytesmut();

        let wire = EncodingResponse::try_from_wire(&mut buf).expect("disabled");
        assert_eq!(wire.id, 514_u64);
        assert!(!wire.enable);
    }

    #[test]
    fn try_from_wire_too_short() {
        let mut buf = ImmutableBytesMut::from(&[0u8; EncodingResponse::WIRE_SIZE - 1][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            EncodingResponse::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test_case(EncodingResponse{id: 513, enable: true} => b"\x00\x00\x00\x00\x00\x00\x02\x01\x01".to_vec(); "enable")]
    #[test_case(EncodingResponse{id: 514, enable: false} => b"\x00\x00\x00\x00\x00\x00\x02\x02\x00".to_vec(); "disable")]
    fn test_append_to_wire(te: EncodingResponse) -> Vec<u8> {
        let mut buf = BytesMut::new();
        te.append_to_wire(&mut buf);
        buf.to_vec()
    }
}
