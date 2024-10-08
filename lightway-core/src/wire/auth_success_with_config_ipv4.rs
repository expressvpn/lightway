use std::fmt::Debug;

use crate::wire::SessionId;

use super::{FromWireError, FromWireResult};
use crate::borrowed_bytesmut::BorrowedBytesMut;
use bytes::{Buf, BufMut, BytesMut};
use more_asserts::*;

/// Authentication Success, contains IPV4 configuration (server -> client only)
///
/// See [`super::Frame::AuthRequest`] for the corresponding request.
///
/// Note this is _not_ a variable length structure. All of `local
/// ip`, `peer ip`, `dns ip` and `mtu` are strings which are NULL
/// terminated within the datastructure and take the full 24 bytes of
/// space.
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         local ip[0..=3]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         local ip[4..=7]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         local ip[8..=11]                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         local ip[12..=15]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         local ip[16..=19]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         local ip[20..=23]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          peer ip[0..=3]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          peer ip[4..=7]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          peer ip[8..=11]                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          peer ip[12..=15]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          peer ip[16..=19]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          peer ip[20..=23]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           dns ip[0..=3]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           dns ip[4..=7]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           dns ip[8..=11]                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           dns ip[12..=15]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           dns ip[16..=19]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           dns ip[20..=23]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              mtu[0..=3]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              mtu[4..=7]                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              mtu[8..=11]                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              mtu[12..=15]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              mtu[16..=19]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                              mtu[20..=23]                     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Session                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Session                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
///
/// NOTE: In the lightway-core C implementation this is
/// `HE_MSGID_CONFIG_IPV4` with `he_msg_config_ipv4_t` as the payload,
/// however it is sent as the response to an auth request.
#[derive(PartialEq)]
pub(crate) struct AuthSuccessWithConfigV4 {
    pub(crate) local_ip: String,
    pub(crate) peer_ip: String,
    pub(crate) dns_ip: String,
    pub(crate) mtu: String,
    pub(crate) session: SessionId,
}

impl Debug for AuthSuccessWithConfigV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthSuccessWithConfigV4").finish()
    }
}

impl AuthSuccessWithConfigV4 {
    /// Maximum length of each string field (not *including* a NULL terminating byte)
    const MAX_STR_SIZE: usize = 23;

    /// Wire Size in bytes, includes the NULL terminating bytes
    const WIRE_SIZE: usize = 4 * (Self::MAX_STR_SIZE + 1) + 8;

    fn try_fixed_len_string_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<String> {
        if buf.len() < Self::MAX_STR_SIZE {
            return Err(FromWireError::InsufficientData);
        };

        // Find the first NULL byte
        let null_idx = buf[0..=Self::MAX_STR_SIZE]
            .iter()
            .position(|b| b == &0)
            .unwrap_or(Self::MAX_STR_SIZE);

        // Clamp to the max length, ignoring the fact that the final NULL byte isn't NULL.
        let null_idx = std::cmp::min(Self::MAX_STR_SIZE, null_idx);

        let s = String::from_utf8(buf[0..null_idx].to_vec())
            .map_err(|_| FromWireError::InvalidStringEncoding)?;

        debug_assert_le!(s.len(), Self::MAX_STR_SIZE);

        // Skip over the field and the NULL terminator in one go.
        buf.advance(Self::MAX_STR_SIZE + 1);

        Ok(s)
    }

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        if buf.len() < Self::WIRE_SIZE {
            return Err(FromWireError::InsufficientData);
        };

        let local_ip = Self::try_fixed_len_string_from_wire(buf)?;
        let peer_ip = Self::try_fixed_len_string_from_wire(buf)?;
        let dns_ip = Self::try_fixed_len_string_from_wire(buf)?;
        let mtu = Self::try_fixed_len_string_from_wire(buf)?;

        let mut session = SessionId::EMPTY;
        buf.copy_to_slice(session.as_mut_slice());

        Ok(Self {
            local_ip,
            peer_ip,
            dns_ip,
            mtu,
            session,
        })
    }

    fn append_fixed_len_string_to_wire(s: &str, buf: &mut BytesMut) {
        let len = s.len();
        let pad = Self::MAX_STR_SIZE - len + 1;

        debug_assert!(pad > 0, "String must be NULL terminated");

        buf.put(s.as_bytes());
        buf.put_bytes(0, pad);
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        // Reminder: we need space for a NULL byte too
        debug_assert_le!(self.local_ip.len(), Self::MAX_STR_SIZE);
        debug_assert_le!(self.peer_ip.len(), Self::MAX_STR_SIZE);
        debug_assert_le!(self.dns_ip.len(), Self::MAX_STR_SIZE);
        debug_assert_le!(self.mtu.len(), Self::MAX_STR_SIZE);

        buf.reserve(Self::WIRE_SIZE);

        Self::append_fixed_len_string_to_wire(&self.local_ip, buf);
        Self::append_fixed_len_string_to_wire(&self.peer_ip, buf);
        Self::append_fixed_len_string_to_wire(&self.dns_ip, buf);
        Self::append_fixed_len_string_to_wire(&self.mtu, buf);

        buf.put(self.session.as_slice());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;
    use test_case::test_case;

    #[test]
    fn try_fixed_len_string_from_wire_too_short() {
        let mut buf =
            ImmutableBytesMut::from(&[0u8; AuthSuccessWithConfigV4::MAX_STR_SIZE - 1][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            AuthSuccessWithConfigV4::try_fixed_len_string_from_wire(&mut buf)
                .err()
                .unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_too_short() {
        let mut buf = ImmutableBytesMut::from(&[0u8; AuthSuccessWithConfigV4::WIRE_SIZE - 1][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            AuthSuccessWithConfigV4::try_from_wire(&mut buf)
                .err()
                .unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test_case(1; "local ip")]
    #[test_case(2; "peer ip")]
    #[test_case(3; "dns ip")]
    #[test_case(4; "mtu")]
    fn try_from_wire_invalid_utf8(nth_string_is_invalid: usize) {
        let mut buf = BytesMut::with_capacity(AuthSuccessWithConfigV4::WIRE_SIZE);
        for i in 1..=4 {
            if i == nth_string_is_invalid {
                buf.extend_from_slice(b"\xc3\x28\x00_______________________________")
            } else {
                buf.extend_from_slice(b"\x00_______________________")
            }
        }
        buf.put_u64(0); // session id

        let mut buf = ImmutableBytesMut::from(buf.freeze());
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            AuthSuccessWithConfigV4::try_from_wire(&mut buf)
                .err()
                .unwrap(),
            FromWireError::InvalidStringEncoding
        ));
    }

    #[test]
    fn max_config_length_to_wire() {
        let cfg = AuthSuccessWithConfigV4 {
            local_ip: "l".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
            peer_ip: "p".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
            dns_ip: "d".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
            mtu: "m".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
            session: SessionId([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]),
        };

        let mut buf = BytesMut::new();
        cfg.append_to_wire(&mut buf);

        assert_eq!(b"lllllllllllllllllllllll\x00ppppppppppppppppppppppp\x00ddddddddddddddddddddddd\x00mmmmmmmmmmmmmmmmmmmmmmm\x00\x12\x34\x56\x78\x90\xab\xcd\xef", &buf[..]);
    }

    #[test]
    fn max_config_length_from_wire() {
        let buf = b"lllllllllllllllllllllll\x00ppppppppppppppppppppppp\x00ddddddddddddddddddddddd\x00mmmmmmmmmmmmmmmmmmmmmmm\x00\x12\x34\x56\x78\x90\xab\xcd\xef";
        let mut buf = ImmutableBytesMut::from(&buf[..]);
        let mut buf = buf.as_borrowed_bytesmut();
        let cfg = AuthSuccessWithConfigV4::try_from_wire(&mut buf).unwrap();

        assert_eq!(
            cfg,
            AuthSuccessWithConfigV4 {
                local_ip: "l".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                peer_ip: "p".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                dns_ip: "d".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                mtu: "m".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                session: SessionId([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]),
            }
        );
    }

    /// We don't care if the 24th byte is actually a NULL.
    #[test]
    fn max_config_length_from_wire_final_null_byte_assumed_to_be_null() {
        let buf = b"lllllllllllllllllllllllApppppppppppppppppppppppBdddddddddddddddddddddddCmmmmmmmmmmmmmmmmmmmmmmmD\x12\x34\x56\x78\x90\xab\xcd\xef";
        let mut buf = ImmutableBytesMut::from(&buf[..]);
        let mut buf = buf.as_borrowed_bytesmut();
        let cfg = AuthSuccessWithConfigV4::try_from_wire(&mut buf).unwrap();

        assert_eq!(
            cfg,
            AuthSuccessWithConfigV4 {
                local_ip: "l".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                peer_ip: "p".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                dns_ip: "d".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                mtu: "m".repeat(AuthSuccessWithConfigV4::MAX_STR_SIZE),
                session: SessionId([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]),
            }
        );
    }
}
