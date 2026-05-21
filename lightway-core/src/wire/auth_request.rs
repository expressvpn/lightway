use crate::{Version, borrowed_bytesmut::BorrowedBytesMut};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use more_asserts::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};

use super::{FromWireError, FromWireResult};

/// Encoding of the authentication method kind
// Needs repr(u8) in order to be able to convert to and from primitives
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, TryFromPrimitive, IntoPrimitive)]
pub(crate) enum AuthMethodKind {
    /// Authenticate with username and password
    UserPass = 1,
    /// Authenticate with token
    Token = 2,
    /// Authenticate with token and lightway version
    VersionedToken = 3,
    /// Authenticate with custom callback
    CustomCallback = 23,
}

#[cfg(test)]
mod test_auth_method_kind {
    use super::*;
    use test_case::test_case;

    #[test_case(AuthMethodKind::UserPass => 1)]
    #[test_case(AuthMethodKind::Token => 2)]
    #[test_case(AuthMethodKind::VersionedToken => 3)]
    #[test_case(AuthMethodKind::CustomCallback => 23)]
    fn into_primitive(ty: AuthMethodKind) -> u8 {
        ty.into()
    }

    #[test_case( 1 => AuthMethodKind::UserPass)]
    #[test_case( 2 => AuthMethodKind::Token)]
    #[test_case( 3 => AuthMethodKind::VersionedToken)]
    #[test_case(23 => AuthMethodKind::CustomCallback)]
    fn try_from_primitive(b: u8) -> AuthMethodKind {
        AuthMethodKind::try_from(b).unwrap()
    }

    #[test]
    fn try_from_primitive_out_of_range() {
        for b in 4..23 {
            assert!(AuthMethodKind::try_from(b).is_err())
        }
        for b in 24..=255 {
            assert!(AuthMethodKind::try_from(b).is_err())
        }
    }
}

// We don't want to export `AuthRequest` but we do want a link if we are building private docs.
#[allow(rustdoc::private_intra_doc_links)]
/// The auth method to use.
///
/// See [`AuthRequest`] for the containing wire format.
#[derive(Clone, PartialEq, Debug)]
pub enum AuthMethod {
    /// Authenticate with username and password
    ///
    /// Wire format (fixed length):
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |       1       |  user length  |  pass length  |    user[0]    |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                          user[1..=4]                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | ............................................................. |
    /// | ~~~~~~~~~~~~~~~~~~~~~~~~ user[5..=44] ~~~~~~~~~~~~~~~~~~~~~~~ |
    /// | ............................................................. |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                          user[45..=48]                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |   user[49]    |               password[0..=2]                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                        password[3..=6]                        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// | ............................................................. |
    /// | ~~~~~~~~~~~~~~~~~~~~~~ password[7..=46] ~~~~~~~~~~~~~~~~~~~~~ |
    /// | ............................................................. |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                 password[47..=49]             |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    UserPass {
        /// Username to authenticate.
        user: String,
        /// The password to use.
        password: String,
    },

    /// Authenticate with token
    ///
    /// Wire format (variable length):
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |       2       |         token_length          | ... token
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    Token {
        /// The authentication token
        ///
        /// It's recommended to use a signed JSON Web Token (JWT - RFC
        /// 7519) as the auth token, but implementations might choose
        /// to use other formats.
        token: String,
    },

    /// Authenticate with token and Lightway protocol version
    ///
    /// Wire format (variable length):
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |       3       |     major     |     minor     | token_length..|
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |..token_length | ... token
    /// +-+-+-+-+-+-+-+-+
    /// ```
    VersionedToken {
        /// Lightway version
        version: Version,
        /// The authentication token
        ///
        /// It's recommended to use a signed JSON Web Token (JWT - RFC
        /// 7519) as the auth token, but implementations might choose
        /// to use other formats.
        token: String,
    },

    /// Authenticate with custom callback
    ///
    /// Wire format (variable length):
    ///
    /// ```text
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |      23       |         data_length           | ... data
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    CustomCallback {
        /// Application defined data buffer with authentication data
        data: Bytes,
    },
}

impl AuthMethod {
    /// The maximum size of each of the user and length fields in [`AuthMethodKind::UserPass`].
    const MAX_USER_PASS_LENGTH: usize = 50;

    /// The maximum size of the token in [`AuthMethodKind::Token`].
    ///
    /// Must fit within an MTU, including [`AuthMethodKind`] and 2 bytes of length.
    const MAX_TOKEN_BYTES: usize =
        1350 - std::mem::size_of::<AuthMethodKind>() - std::mem::size_of::<u16>();

    /// The maximum size of the token in [`AuthMethodKind::VersionedToken`].
    ///
    /// Must fit within an MTU, including [`AuthMethodKind`], 2 bytes of version
    /// (major + minor) and 2 bytes of length.
    const MAX_VERSIONED_TOKEN_BYTES: usize = 1350
        - std::mem::size_of::<AuthMethodKind>()
        - std::mem::size_of::<Version>()
        - std::mem::size_of::<u16>();

    /// The maximum size of the data in [`AuthMethodKind::CustomCallback`].
    ///
    /// Must fit within an MTU, including [`AuthMethodKind`] and including 2 bytes of length.
    const MAX_CUSTOM_DATA_BYTES: usize =
        1350 - std::mem::size_of::<AuthMethodKind>() - std::mem::size_of::<u16>();

    pub(crate) fn kind(&self) -> AuthMethodKind {
        match self {
            AuthMethod::UserPass { .. } => AuthMethodKind::UserPass,
            AuthMethod::Token { .. } => AuthMethodKind::Token,
            AuthMethod::VersionedToken { .. } => AuthMethodKind::VersionedToken,
            AuthMethod::CustomCallback { .. } => AuthMethodKind::CustomCallback,
        }
    }

    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        // We require at least 1 byte for auth type
        if buf.is_empty() {
            return Err(FromWireError::InsufficientData);
        };

        let kind = AuthMethodKind::try_from(buf.get_u8())
            .map_err(|_| FromWireError::InvalidEnumEncoding)?;

        match kind {
            AuthMethodKind::UserPass => {
                if buf.len() < 2 + 2 * Self::MAX_USER_PASS_LENGTH {
                    return Err(FromWireError::InsufficientData);
                }

                let user_len = buf.get_u8() as usize;
                let pass_len = buf.get_u8() as usize;

                if user_len > Self::MAX_USER_PASS_LENGTH || pass_len > Self::MAX_USER_PASS_LENGTH {
                    return Err(FromWireError::FieldTooLarge);
                }

                let user = String::from_utf8(buf[..user_len].to_vec())
                    .map_err(|_| FromWireError::InvalidStringEncoding)?;
                buf.advance(Self::MAX_USER_PASS_LENGTH);

                let password = String::from_utf8(buf[..pass_len].to_vec())
                    .map_err(|_| FromWireError::InvalidStringEncoding)?;
                buf.advance(Self::MAX_USER_PASS_LENGTH);

                Ok(AuthMethod::UserPass { user, password })
            }

            AuthMethodKind::Token => {
                if buf.len() < 2 {
                    return Err(FromWireError::InsufficientData);
                }

                let token_len = buf.get_u16() as usize;

                if token_len > Self::MAX_TOKEN_BYTES {
                    return Err(FromWireError::FieldTooLarge);
                }

                if buf.len() < token_len {
                    return Err(FromWireError::InsufficientData);
                }

                let token = String::from_utf8(buf[..token_len].to_vec())
                    .map_err(|_| FromWireError::InvalidStringEncoding)?;
                buf.advance(token_len);

                Ok(AuthMethod::Token { token })
            }

            AuthMethodKind::VersionedToken => {
                if buf.len() < 4 {
                    return Err(FromWireError::InsufficientData);
                }

                let major = buf.get_u8();
                let minor = buf.get_u8();
                let Some(version) = Version::try_new(major, minor) else {
                    return Err(FromWireError::InvalidProtocolVersion(major, minor));
                };

                let token_len = buf.get_u16() as usize;

                if token_len > Self::MAX_VERSIONED_TOKEN_BYTES {
                    return Err(FromWireError::FieldTooLarge);
                }

                if buf.len() < token_len {
                    return Err(FromWireError::InsufficientData);
                }

                let token = String::from_utf8(buf[..token_len].to_vec())
                    .map_err(|_| FromWireError::InvalidStringEncoding)?;
                buf.advance(token_len);

                Ok(AuthMethod::VersionedToken { version, token })
            }

            AuthMethodKind::CustomCallback => {
                if buf.len() < 2 {
                    return Err(FromWireError::InsufficientData);
                }

                let data_len = buf.get_u16() as usize;

                if data_len > Self::MAX_CUSTOM_DATA_BYTES {
                    return Err(FromWireError::FieldTooLarge);
                }

                if buf.len() < data_len {
                    return Err(FromWireError::InsufficientData);
                }

                let data = buf.copy_to_bytes(data_len);

                Ok(AuthMethod::CustomCallback { data })
            }
        }
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(1);

        buf.put_u8(self.kind().into());

        match self {
            AuthMethod::UserPass { user, password } => {
                debug_assert_le!(user.len(), Self::MAX_USER_PASS_LENGTH);
                debug_assert_le!(password.len(), Self::MAX_USER_PASS_LENGTH);

                // 2 length bytes, plus the data itself
                buf.reserve(2 + 2 * Self::MAX_USER_PASS_LENGTH);

                buf.put_u8(user.len() as u8);
                buf.put_u8(password.len() as u8);

                buf.put(user.as_bytes());
                buf.put_bytes(0, Self::MAX_USER_PASS_LENGTH - user.len());
                buf.put(password.as_bytes());
                buf.put_bytes(0, Self::MAX_USER_PASS_LENGTH - password.len());
            }

            AuthMethod::Token { token } => {
                debug_assert_le!(token.len(), Self::MAX_TOKEN_BYTES);

                // A u16 length + token
                buf.reserve(2 + token.len());

                buf.put_u16(token.len() as u16);
                buf.put(token.as_bytes());
            }

            AuthMethod::VersionedToken { version, token } => {
                debug_assert_le!(token.len(), Self::MAX_VERSIONED_TOKEN_BYTES);

                // 2 bytes of version + u16 length + token
                buf.reserve(2 + 2 + token.len());

                buf.put_u8(version.major());
                buf.put_u8(version.minor());
                buf.put_u16(token.len() as u16);
                buf.put(token.as_bytes());
            }

            AuthMethod::CustomCallback { data } => {
                debug_assert_le!(data.len(), Self::MAX_CUSTOM_DATA_BYTES);

                // A u16 length + data
                buf.reserve(2 + data.len());

                buf.put_u16(data.len() as u16);
                buf.put(&data[..]);
            }
        }
    }
}

/// Authentication Request (only sent from client to server)
///
/// See [`super::Frame::AuthSuccessWithConfigV4`] and
/// [`super::Frame::AuthFailure`] for the corresponding responses.
///
/// This is a variable sized request.
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   auth kind   | ... per AuthMethod data
/// +-+-+-+-+-+-+-+-+
///```
///
/// See [`AuthMethod`] for wire format of each variant.
#[derive(PartialEq, Debug)]
pub(crate) struct AuthRequest {
    pub(crate) auth_method: AuthMethod,
}

impl AuthRequest {
    pub(crate) fn try_from_wire(buf: &mut BorrowedBytesMut) -> FromWireResult<Self> {
        let auth_method = AuthMethod::try_from_wire(buf)?;

        Ok(Self { auth_method })
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        self.auth_method.append_to_wire(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::borrowed_bytesmut::ImmutableBytesMut;

    #[test]
    fn try_from_wire_too_short() {
        let mut buf = ImmutableBytesMut::from(&[0u8; 0][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            AuthRequest::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn try_from_wire_unknown_kind() {
        let mut buf = ImmutableBytesMut::from(&[111u8; 1][..]);
        let mut buf = buf.as_borrowed_bytesmut();
        assert!(matches!(
            AuthRequest::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InvalidEnumEncoding
        ));
    }

    mod user_pass {
        use super::*;

        #[test]
        fn try_from_too_short() {
            let buf = b"\x01\x32\x32uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuppppppppppppppppppppppppppppppppppppppppppppppppp";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InsufficientData
            ));
        }

        #[test]
        fn try_from_wire_user_too_long() {
            let buf = b"\x01\x33\x32uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuppppppppppppppppppppppppppppppppppppppppppppppppppp";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::FieldTooLarge
            ));
        }

        #[test]
        fn try_from_wire_pass_too_long() {
            let buf = b"\x01\x32\x33uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuupppppppppppppppppppppppppppppppppppppppppppppppppppp";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::FieldTooLarge
            ));
        }

        #[test]
        fn try_from_wire_user_invalid_utf8() {
            let buf = b"\x01\x02\x01\xc3\x28________________________________________________p_________________________________________________";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();

            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InvalidStringEncoding
            ));
        }

        #[test]
        fn try_from_wire_pass_invalid_utf8() {
            let buf = b"\x01\x01\x02u_________________________________________________\xc3\x28_________________________________________________";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InvalidStringEncoding
            ));
        }

        #[test]
        fn max_length_to_wire() {
            let am = AuthMethod::UserPass {
                user: "u".repeat(AuthMethod::MAX_USER_PASS_LENGTH),
                password: "p".repeat(AuthMethod::MAX_USER_PASS_LENGTH),
            };

            let mut buf = BytesMut::new();
            am.append_to_wire(&mut buf);

            assert_eq!(b"\x01\x32\x32uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuupppppppppppppppppppppppppppppppppppppppppppppppppp", &buf[..]);
        }

        #[test]
        fn max_length_from_wire() {
            let buf = b"\x01\x32\x32uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuupppppppppppppppppppppppppppppppppppppppppppppppppp";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            let am = AuthMethod::try_from_wire(&mut buf).unwrap();

            assert_eq!(
                am,
                AuthMethod::UserPass {
                    user: "u".repeat(AuthMethod::MAX_USER_PASS_LENGTH),
                    password: "p".repeat(AuthMethod::MAX_USER_PASS_LENGTH),
                }
            );
        }
    }

    mod token {
        use super::*;
        use test_case::test_case;

        #[test_case(&[0x2] ; "just kind")]
        #[test_case(&[0x2, 0x00]; "just one byte of length")]
        #[test_case(&[0x2, 0x02, 0x00, 0xff] ; "fewer bytes than length says")]
        fn try_from_wire_too_short(buf: &'static [u8]) {
            let mut buf = ImmutableBytesMut::from(buf);
            let mut buf = buf.as_borrowed_bytesmut();

            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InsufficientData
            ));
        }

        #[test]
        fn try_from_wire_too_long() {
            let mut buf = BytesMut::with_capacity(3 + AuthMethod::MAX_TOKEN_BYTES + 1);
            buf.extend_from_slice(b"\x02\x33\x00");
            buf.extend_from_slice(&[0x74; AuthMethod::MAX_TOKEN_BYTES + 1]);
            let mut buf = ImmutableBytesMut::from(buf.freeze());
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::FieldTooLarge
            ));
        }

        #[test]
        fn try_from_wire_pass_invalid_utf8() {
            let mut buf = ImmutableBytesMut::from(&b"\x02\x00\x02\xc3\x28"[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InvalidStringEncoding
            ));
        }

        #[test]
        fn max_length_to_wire() {
            let am = AuthMethod::Token {
                token: "t".repeat(AuthMethod::MAX_TOKEN_BYTES),
            };

            let mut buf = BytesMut::new();
            am.append_to_wire(&mut buf);

            assert_eq!(
                b"\x02\x05\x43ttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt",
                &buf[..]
            );
        }

        #[test]
        fn max_length_from_wire() {
            let buf = b"\x02\x05\x43ttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttt";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            let am = AuthMethod::try_from_wire(&mut buf).unwrap();

            assert_eq!(
                am,
                AuthMethod::Token {
                    token: "t".repeat(AuthMethod::MAX_TOKEN_BYTES),
                }
            );
        }
    }

    mod versioned_token {
        use super::*;
        use test_case::test_case;

        #[test_case(&[0x3] ; "just kind")]
        #[test_case(&[0x3, 0x01] ; "just one byte of version")]
        #[test_case(&[0x3, 0x01, 0x03] ; "no length")]
        #[test_case(&[0x3, 0x01, 0x03, 0x00] ; "just one byte of length")]
        #[test_case(&[0x3, 0x01, 0x03, 0x02, 0x00, 0xff] ; "fewer bytes than length says")]
        fn try_from_wire_too_short(buf: &'static [u8]) {
            let mut buf = ImmutableBytesMut::from(buf);
            let mut buf = buf.as_borrowed_bytesmut();

            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InsufficientData
            ));
        }

        #[test]
        fn try_from_wire_invalid_version() {
            // major=2, minor=0 is outside the supported Version range.
            let mut buf = ImmutableBytesMut::from(&b"\x03\x02\x00\x00\x05token"[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InvalidProtocolVersion(2, 0)
            ));
        }

        #[test]
        fn try_from_wire_too_long() {
            let mut buf = BytesMut::with_capacity(5 + AuthMethod::MAX_VERSIONED_TOKEN_BYTES + 1);
            // kind | major | minor | u16 len (big-endian) = MAX + 1
            let len = (AuthMethod::MAX_VERSIONED_TOKEN_BYTES + 1) as u16;
            buf.extend_from_slice(&[0x03, 0x01, 0x03]);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(&vec![0x74; AuthMethod::MAX_VERSIONED_TOKEN_BYTES + 1]);
            let mut buf = ImmutableBytesMut::from(buf.freeze());
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::FieldTooLarge
            ));
        }

        #[test]
        fn try_from_wire_invalid_utf8() {
            let mut buf = ImmutableBytesMut::from(&b"\x03\x01\x03\x00\x02\xc3\x28"[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InvalidStringEncoding
            ));
        }

        #[test]
        fn round_trip_to_wire() {
            let am = AuthMethod::VersionedToken {
                version: Version::MAXIMUM,
                token: "token".to_string(),
            };

            let mut buf = BytesMut::new();
            am.append_to_wire(&mut buf);

            assert_eq!(&b"\x03\x01\x03\x00\x05token"[..], &buf[..]);
        }

        #[test]
        fn round_trip_from_wire() {
            let mut buf = ImmutableBytesMut::from(&b"\x03\x01\x03\x00\x05token"[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            let am = AuthMethod::try_from_wire(&mut buf).unwrap();

            assert_eq!(
                am,
                AuthMethod::VersionedToken {
                    version: Version::MAXIMUM,
                    token: "token".to_string(),
                }
            );
        }

        #[test]
        fn max_length_round_trip() {
            let am = AuthMethod::VersionedToken {
                version: Version::MAXIMUM,
                token: "t".repeat(AuthMethod::MAX_VERSIONED_TOKEN_BYTES),
            };

            let mut buf = BytesMut::new();
            am.append_to_wire(&mut buf);

            let mut imm = ImmutableBytesMut::from(buf.freeze());
            let mut bb = imm.as_borrowed_bytesmut();
            let decoded = AuthMethod::try_from_wire(&mut bb).unwrap();

            assert_eq!(am, decoded);
        }
    }

    mod callback {
        use super::*;
        use test_case::test_case;

        #[test_case(&[0x17] ; "just kind")]
        #[test_case(&[0x17, 0x00]; "just one byte of length")]
        #[test_case(&[0x17, 0x02, 0x00, 0xff] ; "fewer bytes than length says")]
        fn try_from_wire_too_short(buf: &'static [u8]) {
            let mut buf = ImmutableBytesMut::from(buf);
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::InsufficientData
            ));
        }

        #[test]
        fn try_from_wire_too_long() {
            let mut buf = BytesMut::with_capacity(3 + AuthMethod::MAX_CUSTOM_DATA_BYTES + 1);
            buf.extend_from_slice(b"\x17\x05\x44");
            buf.extend_from_slice(&[0x64; AuthMethod::MAX_CUSTOM_DATA_BYTES + 1]);
            let mut buf = ImmutableBytesMut::from(buf.freeze());
            let mut buf = buf.as_borrowed_bytesmut();
            assert!(matches!(
                AuthRequest::try_from_wire(&mut buf).err().unwrap(),
                FromWireError::FieldTooLarge
            ));
        }

        #[test]
        fn max_length_to_wire() {
            let mut data = BytesMut::with_capacity(AuthMethod::MAX_CUSTOM_DATA_BYTES);
            data.resize(AuthMethod::MAX_CUSTOM_DATA_BYTES, 0x64);
            let data = data.freeze();
            let am = AuthMethod::CustomCallback { data };

            let mut buf = BytesMut::new();
            am.append_to_wire(&mut buf);

            assert_eq!(
                b"\x17\x05\x43ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                &buf[..]
            );
        }

        #[test]
        fn max_length_from_wire() {
            let buf = b"\x17\x05\x43ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
            let mut buf = ImmutableBytesMut::from(&buf[..]);
            let mut buf = buf.as_borrowed_bytesmut();
            let am = AuthMethod::try_from_wire(&mut buf).unwrap();

            let mut data = BytesMut::with_capacity(AuthMethod::MAX_CUSTOM_DATA_BYTES);
            data.resize(AuthMethod::MAX_CUSTOM_DATA_BYTES, 0x64);
            let data = data.freeze();
            assert_eq!(am, AuthMethod::CustomCallback { data });
        }
    }
}
