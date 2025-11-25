use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::borrowed_bytesmut::BorrowedBytesMut;

use super::{FromWireError, FromWireResult};

/// A ping request to the other side.
///
/// Currently this message type is used by keepalive and plpmtud modules.
/// Field `id` in the packet header differentiates between this two types
/// id =0 For keepalive messages
/// id != 0 for PLPMTUD messages
///
/// Wire Format (variable length):
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |             id                |       payload length          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  payload length bytes...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub(crate) struct Ping {
    /// Identifier, will be reflected in [`super::pong::Pong`].
    pub(crate) id: u16,
    /// Payload
    pub(crate) payload: Bytes,
}

impl Ping {
    /// Wire overhead in bytes, does not include the payload itself.
    pub(crate) const WIRE_OVERHEAD: usize = 4;

    /// Identifier used in keepalive messages
    pub const KEEPALIVE_ID: u16 = 0;

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
    use test_case::test_case;

    #[test]
    fn try_from_wire_header_too_short() {
        let mut buf = ImmutableBytesMut::from(&[0u8; 3][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            Ping::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_header_payload_too_short() {
        let mut buf = ImmutableBytesMut::from(&b"\x00\x00\x03\x00\x01\x02"[..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            Ping::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_header_no_payload() {
        let mut buf = ImmutableBytesMut::from(&b"\x12\x34\x00\x00"[..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert_eq!(
            Ping::try_from_wire(&mut buf).unwrap(),
            Ping {
                id: 0x1234,
                payload: Default::default()
            }
        );
        assert!(buf.is_empty(), "buf should be consumed");
    }

    #[test]
    fn try_from_wire_header_payload() {
        let mut buf = ImmutableBytesMut::from(
            &b"\x12\x34\x00\x10\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"[..],
        );
        let mut buf = buf.as_borrowed_bytesmut();

        assert_eq!(
            Ping::try_from_wire(&mut buf).unwrap(),
            Ping {
                id: 0x1234,
                payload: Bytes::from_static(&[
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                ]),
            }
        );
    }

    #[test_case(Ping { id: 0xdee4, payload: Default::default() } => b"\xde\xe4\x00\x00".to_vec(); "no payload")]
    #[test_case(Ping { id: 0xdee4, payload: Bytes::from_static(b"\xff\xfe") } => b"\xde\xe4\x00\x02\xff\xfe".to_vec(); "payload")]
    fn append_to_wire(ping: Ping) -> Vec<u8> {
        let mut buf = BytesMut::new();
        ping.append_to_wire(&mut buf);
        buf.to_vec()
    }
}
