use crate::borrowed_bytesmut::BorrowedBytesMut;
use bitfield_struct::bitfield;
use bytes::{Buf, BufMut, BytesMut};

use super::{FromWireError, FromWireResult, expresslane_data::ExpresslaneKey};

#[repr(u8)]
#[derive(PartialEq, Debug, Copy, Clone, Default)]
pub enum ExpresslaneVersion {
    Unknown = 0,
    #[default]
    Version1 = 1,
}

impl From<u8> for ExpresslaneVersion {
    fn from(value: u8) -> Self {
        match value {
            1 => Self::Version1,
            _ => Self::Unknown,
        }
    }
}

/// Header byte layout: |E|A|unused|
#[bitfield(u8, order = Msb)]
struct Header {
    enabled: bool,
    ack: bool,
    #[bits(6)]
    unused: u8,
}

/// A expresslane config frame
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   version     |E|A|   unused  |      Reserved                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Counter                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Counter                              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Key                                 |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// E - enabled
/// A - Ack

#[derive(PartialEq, Debug, Default, Clone, Copy)]
pub(crate) struct ExpresslaneConfig {
    pub(crate) version: ExpresslaneVersion,
    pub(crate) enabled: bool,
    pub(crate) ack: bool,
    pub(crate) counter: u64,
    pub(crate) key: ExpresslaneKey,
}

impl ExpresslaneConfig {
    /// Wire overhead in bytes
    const WIRE_OVERHEAD: usize = 44;

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<ExpresslaneConfig> {
        if buf.len() < Self::WIRE_OVERHEAD {
            return Err(FromWireError::InsufficientData);
        };

        let version = buf.get_u8().into();
        let header_byte = buf.get_u8();
        let header = Header::from(header_byte);
        let ack = header.ack();
        let enabled = header.enabled();

        let _reserved = buf.get_u16();

        let counter = buf.get_u64();
        let mut key = [0u8; 32];
        buf.copy_to_slice(&mut key);
        let key = key.into();

        Ok(ExpresslaneConfig {
            version,
            enabled,
            ack,
            counter,
            key,
        })
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(Self::WIRE_OVERHEAD);

        let header = Header::new()
            .with_enabled(self.enabled)
            .with_ack(self.ack)
            .with_unused(0);
        let reserved: u16 = 0;

        buf.put_u8(self.version as u8);
        buf.put_u8(header.into());
        buf.put_u16(reserved);

        buf.put_u64(self.counter);
        buf.put(&self.key.0[..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;
    use test_case::test_case;

    #[test]
    fn default() {
        let config = ExpresslaneConfig::default();
        assert_eq!(config.version, ExpresslaneVersion::Version1);
        assert!(!config.enabled);
        assert!(!config.ack);
        assert_eq!(config.counter, 0);
        assert_eq!(config.key, ExpresslaneKey::default());
    }

    #[test_case(&[0_u8; 0]; "no data")]
    #[test_case(&[0_u8; 43]; "insufficient data")]
    fn try_from_wire_insufficient_data(buf: &'static [u8]) {
        let mut buf = ImmutableBytesMut::from(buf);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            ExpresslaneConfig::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_success() {
        let mut test_data = vec![0u8; 44];
        test_data[0] = 1; // version
        test_data[1] = 0b11000000; // header: enabled=1, ack=1
        // test_data[2..4] reserved
        test_data[4..12].copy_from_slice(&0x123456789abcdef0u64.to_be_bytes());
        for i in 0..32 {
            test_data[12 + i] = (i + 1) as u8;
        }

        let mut buf = ImmutableBytesMut::from(test_data);
        let mut buf = buf.as_borrowed_bytesmut();

        let config = ExpresslaneConfig::try_from_wire(&mut buf).unwrap();
        assert_eq!(config.version, ExpresslaneVersion::Version1);
        assert!(config.enabled);
        assert!(config.ack);
        assert_eq!(config.counter, 0x123456789abcdef0);

        let expected_key = ExpresslaneKey([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        assert_eq!(config.key, expected_key);
        assert!(buf.is_empty(), "buf should be consumed");
    }

    #[test_case(ExpresslaneConfig { version: ExpresslaneVersion::Version1, enabled: false, ack: false, counter: 0, key: ExpresslaneKey([0u8; 32]) }; "zero values")]
    #[test_case(ExpresslaneConfig { version: ExpresslaneVersion::Version1, enabled: true, ack: true, counter: 0x123456789abcdef0, key: ExpresslaneKey([0xffu8; 32]) }; "max values")]
    fn append_to_wire(config: ExpresslaneConfig) {
        let mut buf = BytesMut::new();
        config.append_to_wire(&mut buf);

        assert_eq!(buf.len(), ExpresslaneConfig::WIRE_OVERHEAD);

        let mut read_buf = ImmutableBytesMut::from(buf.freeze());
        let mut read_buf = read_buf.as_borrowed_bytesmut();
        let parsed = ExpresslaneConfig::try_from_wire(&mut read_buf).unwrap();

        assert_eq!(parsed, config);
    }

    #[test]
    fn version_enum_conversions() {
        assert_eq!(ExpresslaneVersion::from(1), ExpresslaneVersion::Version1);
        assert_eq!(ExpresslaneVersion::from(0), ExpresslaneVersion::Unknown);
        assert_eq!(ExpresslaneVersion::from(255), ExpresslaneVersion::Unknown);

        assert_eq!(ExpresslaneVersion::Version1 as u8, 1);
        assert_eq!(ExpresslaneVersion::Unknown as u8, 0);
    }
}
