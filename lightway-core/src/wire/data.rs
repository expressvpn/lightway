use std::borrow::Cow;

use crate::borrowed_bytesmut::BorrowedBytesMut;
use bytes::{Buf, BufMut, BytesMut};
use more_asserts::*;

use super::{FromWireError, FromWireResult};

/// A data frame
///
/// This is a variable sized request.
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        data length            | ... length bytes of data
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// Note if the other end is running protocol v1.0 then the length
/// field is the native endianness of the peer.

#[derive(PartialEq, Debug)]
pub(crate) struct Data<'data> {
    pub(crate) data: Cow<'data, BytesMut>,
}

impl Data<'_> {
    /// Wire overhead in bytes
    pub(crate) const WIRE_OVERHEAD: usize = 2;

    /// The maximum payload size for a given Packetization Layer PMTU
    pub(crate) fn maximum_packet_size_for_plpmtu(plpmtu: usize) -> usize {
        debug_assert_gt!(
            plpmtu,
            std::mem::size_of::<crate::wire::FrameKind>() + Self::WIRE_OVERHEAD,
            "plpmtu too small"
        );
        plpmtu - Self::WIRE_OVERHEAD - std::mem::size_of::<crate::wire::FrameKind>()
    }

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < Self::WIRE_OVERHEAD {
            return Err(FromWireError::InsufficientData);
        };

        // TODO: in protocol 1.0 this field native endian for the other end (so little endian in practice).
        let data_len = buf.get_u16() as usize;

        if buf.len() < data_len {
            return Err(FromWireError::InsufficientData);
        }

        let data = buf.commit_and_split_to(data_len);

        Ok(Self {
            data: Cow::Owned(data),
        })
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        debug_assert_le!(self.data.len(), u16::MAX as usize);

        buf.reserve(Self::WIRE_OVERHEAD + self.data.len());

        // TODO: in protocol 1.0 this field native endian for the other end (so little endian in practice).
        buf.put_u16(self.data.len() as u16);
        buf.put(&self.data[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;
    use test_case::test_case;

    #[cfg(debug_assertions)]
    #[test_case(0 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(1 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(2 => panics "plpmtu too small")]
    #[cfg(debug_assertions)]
    #[test_case(3 => panics "plpmtu too small")]
    #[test_case(4 => 1)]
    #[test_case(1200 => 1197)]
    #[test_case(1300 => 1297)]
    #[test_case(1500 => 1497)]
    fn maximum_packet_size_for_plpmtu(size: usize) -> usize {
        Data::maximum_packet_size_for_plpmtu(size)
    }

    #[test_case(&[0_u8; 0]; "no data")]
    #[test_case(&[0_u8; 1]; "only one length byte")]
    #[test_case(&[0x00, 0x02, 0x00]; "fewer bytes than length says")]
    fn try_from_wire_too_short(buf: &'static [u8]) {
        let mut buf = ImmutableBytesMut::from(buf);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            Data::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }
}
