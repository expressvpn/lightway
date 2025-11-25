use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::{FromWireError, FromWireResult};
use crate::borrowed_bytesmut::BorrowedBytesMut;

/// A pong request in response to a ping
///
/// Wire Format (variable length):
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         id                    |       payload length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  payload length bytes...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub(crate) struct Pong {
    pub(crate) id: u16,
    /// Payload
    pub(crate) payload: Bytes,
}

impl Pong {
    /// Wire overhead in bytes, does not include the payload itself.
    pub(crate) const WIRE_OVERHEAD: usize = 4;

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < Self::WIRE_OVERHEAD {
            return Err(FromWireError::InsufficientData);
        };

        let id = buf.get_u16();
        let payload_length = buf.get_u16() as usize;

        if buf.len() < payload_length {
            return Err(FromWireError::InsufficientData);
        }

        let payload = buf.copy_to_bytes(payload_length);

        Ok(Self { id, payload })
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(Self::WIRE_OVERHEAD + self.payload.len());

        buf.put_u16(self.id);
        buf.put_u16(self.payload.len() as u16);
        buf.put(&self.payload[..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;

    #[test]
    fn try_from_wire_too_short() {
        let mut buf = ImmutableBytesMut::from(&[0u8; Pong::WIRE_OVERHEAD - 1][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            Pong::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_payload_too_short() {
        let mut buf = ImmutableBytesMut::from(&b"\x00\x00\x03\x00\x01\x02"[..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            Pong::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_no_payload() {
        let mut buf = ImmutableBytesMut::from(&b"\x12\x34\x00\x00"[..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert_eq!(
            Pong::try_from_wire(&mut buf).unwrap(),
            Pong {
                id: 0x1234,
                payload: Default::default(),
            }
        );
        assert!(buf.is_empty(), "buf should be consumed");
    }

    #[test]
    fn try_from_wire_with_payload() {
        let mut buf = ImmutableBytesMut::from(
            &b"\x12\x34\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"[..],
        );
        let mut buf = buf.as_borrowed_bytesmut();

        assert_eq!(
            Pong::try_from_wire(&mut buf).unwrap(),
            Pong {
                id: 0x1234,
                payload: Bytes::from_static(&[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
            }
        );
    }

    #[test]
    fn append_to_wire_no_payload() {
        let pong = Pong {
            id: 0xdee4,
            payload: Default::default(),
        };
        let mut buf = BytesMut::new();
        pong.append_to_wire(&mut buf);
        assert_eq!(&buf[..], b"\xde\xe4\x00\x00");
    }

    #[test]
    fn append_to_wire_with_payload() {
        let pong = Pong {
            id: 0xdee4,
            payload: Bytes::from_static(b"\xff\xfe"),
        };
        let mut buf = BytesMut::new();
        pong.append_to_wire(&mut buf);
        assert_eq!(&buf[..], b"\xde\xe4\x00\x02\xff\xfe");
    }
}
