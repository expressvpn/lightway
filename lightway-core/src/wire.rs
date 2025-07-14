//! # The Lightway Wire Protocol
//!
//! # Basic Connection Lifecycle
//!
//! ## Authentication
//!
//! To authenticate, the client sends the server a
//! [`Frame::AuthRequest`]. The server will reply with either
//! [`Frame::AuthSuccessWithConfigV4`] or [`Frame::AuthFailure`].
//!
//! ## Communication
//!
//! Once authenticated, the client and the server communicate by
//! exchanging [`Frame::Data`] frames.
//!
//! ## Termination
//!
//! Either side may send a [`Frame::Goodbye`] to terminate the
//! connection.
//!
//! # Other Frames
//!
//! Some frames are sent outside the
//! authentication/communication/termination cycle described above.
//!
//! ## Client configuration push from server
//!
//! At any time between the client initiating authentication and
//! connection shutdown the server may send a [`Frame::ServerConfig`]
//! frame to the client.
//!
//! ## NoOp and Ping/Pong
//!
//! [`Frame::NoOp`] and [`Frame::Ping`] may be sent by either side at
//! any time.
//!
//! [`Frame::NoOp`] and [`Frame::Pong`] are ignored by the recipient.
//!
//! [`Frame::Ping`] will result in a [`Frame::Pong`] in response.

use crate::borrowed_bytesmut::BorrowedBytesMut;
use bytes::{Buf, BufMut, BytesMut};
use more_asserts::*;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use rand::Rng;

// A module for each frame type with a payload
mod auth_failure;
mod auth_request;
mod auth_success_with_config_ipv4;
mod data;
mod data_frag;
mod encoding_request;
mod encoding_response;
mod expresslane_config;
mod expresslane_data;
mod ping;
mod pong;
mod server_config;

pub use auth_request::AuthMethod;

pub(crate) use auth_failure::AuthFailure;
pub(crate) use auth_request::AuthRequest;
pub(crate) use auth_success_with_config_ipv4::AuthSuccessWithConfigV4;
pub(crate) use data::Data;
pub(crate) use data_frag::DataFrag;
pub(crate) use encoding_request::EncodingRequest;
pub(crate) use encoding_response::EncodingResponse;
pub(crate) use expresslane_config::ExpresslaneConfig;
pub(crate) use ping::Ping;
pub(crate) use pong::Pong;
pub(crate) use server_config::ServerConfig;

/// Errors which can occur during decoding.
#[derive(Debug, thiserror::Error)]
pub enum FromWireError {
    /// Input buffer does not contain enough bytes to complete
    /// decode. Usually you should wait for more bytes and then try
    /// again.
    #[error("Insufficient data")]
    InsufficientData,
    /// Invalid Magic Number
    #[error("Invalid magic number: {0:02x}{1:02x}")]
    InvalidMagicNumber(u8, u8),
    /// An unknown value was encountered in an enum-like field
    #[error("Invalid enum encoding")]
    InvalidEnumEncoding,
    /// An unknown value was encountered in an frame type field
    #[error("Invalid/Unknown frame type")]
    UnknownFrameType,
    /// A non UTF-8 string was encountered
    #[error("Invalid string encoding")]
    InvalidStringEncoding,
    /// A field which was larger than allowed was found
    #[error("Field too large")]
    FieldTooLarge,
    /// Wire contains an invalid protocol version
    #[error("Invalid protocol version {0}.{1}")]
    InvalidProtocolVersion(u8, u8),
    /// The toggle option is not a boolean
    #[error("Invalid toggle option: is not a boolean")]
    InvalidBool,
    /// Invalid express data path
    #[error("Invalid express data path")]
    InvalidExpressDataPath,
    /// Invalid express data
    #[error("Invalid express data")]
    InvalidExpressData,
}

/// The result of an attempted wire decode.
///
/// If there are insufficient bytes then decode routines should return
/// `Err(FromWireError::InsufficientData)`.
pub type FromWireResult<T> = std::result::Result<T, FromWireError>;

/// Session Identifier (opaque cookie)
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 8]);

impl SessionId {
    /// Initial/Unspecified session id
    pub const EMPTY: Self = Self([0_u8; 8]);

    /// Session rejected
    pub const REJECTED: Self = Self([0xff_u8; 8]);

    /// (tests only) create a SessionId from a byte array
    pub const fn from_const(value: [u8; 8]) -> Self {
        Self(value)
    }

    /// Is this `SessionId` one of the statically defined values
    pub fn is_reserved(&self) -> bool {
        self == &Self::EMPTY || self == &Self::REJECTED
    }

    fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl rand::distr::Distribution<SessionId> for rand::distr::StandardUniform {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> SessionId {
        loop {
            let candidate = SessionId(rng.random());
            if !candidate.is_reserved() {
                break candidate;
            }
        }
    }
}

impl std::fmt::Debug for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = u64::from_be_bytes(self.0);
        write!(f, "{n:016x?}")
    }
}

/// The header for each request.
///
/// It is strongly discouraged to interact with this header structure,
/// however, it is provided for specific use cases (such as a server
/// rejecting a session, where by definition we don't have a
/// connection object).
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   ASCII 'H'   |   ASCII 'e'   | major_version | minor_version |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   aggressive  | express data  |          RESERVED             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Session                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Session                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Header {
    /// The protocol version
    pub version: crate::Version,
    /// Request aggressive mode
    pub aggressive_mode: bool,
    /// Expresslane data
    pub expresslane_data: bool,
    /// Session identifier (opaque cookie)
    pub session: SessionId,
}

impl Header {
    /// Size on the wire (bytes)
    pub const WIRE_SIZE: usize = 16;

    /// Deserialize from wire format
    pub fn try_from_wire(buf: &mut BytesMut) -> FromWireResult<Self> {
        if buf.len() < Header::WIRE_SIZE {
            return Err(FromWireError::InsufficientData);
        }

        let he0 = buf.get_u8();
        let he1 = buf.get_u8();

        if he0 != b'H' || he1 != b'e' {
            return Err(FromWireError::InvalidMagicNumber(he0, he1));
        }

        let major_version = buf.get_u8();
        let minor_version = buf.get_u8();

        let aggressive_mode = buf.get_u8() != 0;
        let expresslane_data = buf.get_u8() != 0;
        buf.advance(2); // RESERVED

        let mut session = SessionId::EMPTY;
        buf.copy_to_slice(session.as_mut_slice());

        let version = crate::Version::try_new(major_version, minor_version).ok_or(
            FromWireError::InvalidProtocolVersion(major_version, minor_version),
        )?;

        Ok(Header {
            version,
            aggressive_mode,
            expresslane_data,
            session,
        })
    }

    /// Serialize to wire format
    pub fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(Header::WIRE_SIZE);

        buf.put_u8(b'H');
        buf.put_u8(b'e');
        buf.put_u8(self.version.major());
        buf.put_u8(self.version.minor());

        buf.put_u8(self.aggressive_mode as u8);
        buf.put_u8(self.expresslane_data as u8);
        buf.put_bytes(0, 2); // RESERVED

        buf.put(self.session.as_slice());

        debug_assert_ge!(buf.len(), Header::WIRE_SIZE);
    }
}

/// The encoding of the frame type. Each frame starts with a byte
/// indicating the type of frame.
// Needs repr(u8) in order to be able to convert to and from primitives
#[repr(u8)]
#[derive(Debug, PartialEq, TryFromPrimitive, IntoPrimitive)]
pub(crate) enum FrameKind {
    /// A No Op frame - it is dropped when received
    NoOp = 1,
    /// A ping request to the other side
    Ping = 2,
    /// A pong request in response to a ping
    Pong = 3,
    /// Authentication Request (client -> server only)
    AuthRequest = 4,
    /// Packets of data to / from the tunnel
    Data = 5,
    /// Authentication Success, contains IPV4 configuration (server -> client only)
    AuthSuccessWithConfigV4 = 6,
    /// Authentication Failure (server -> client only)
    AuthFailure = 7,
    // 8 is unused. lightway-core calls it `HE_MSGID_AUTH_RESPONSE_WITH_CONFIG`
    // 9 is unused. lightway-core calls it `HE_MSGID_EXTENSION`
    // 10 is unused. lightway-core calls it `HE_MSGID_SESSION_REQUEST`
    // 11 is unused. lightway-core calls it `HE_MSGID_SESSION_RESPONSE`
    /// Tell the other side you're hanging up
    Goodbye = 12,
    // 13 is deprecated and unused
    /// Server configuration data pushed to the client by the server
    ServerConfig = 14,
    /// Fragmented Data Packet
    DataFrag = 15,
    /// Encoded Data Packets of data to / from the tunnel
    EncodedData = 16,
    /// Encoded Fragmented Data Packet
    EncodedDataFrag = 17,
    /// Encoding Request
    EncodingRequest = 18,
    /// Encoding Response
    EncodingResponse = 19,
    /// Express Data
    ExpresslaneConfig = 20,
}

/// Encapsulates a single frame.
///
/// Wire Format:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   FrameKind   | Payload specific: variable number of bytes
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, PartialEq)]
pub(crate) enum Frame<'data> {
    /// A No Op frame - it is dropped when received
    NoOp,
    /// A ping request to the other side
    Ping(ping::Ping),
    /// A pong request in response to a ping
    Pong(pong::Pong),
    /// Authentication Request (client -> server only)
    AuthRequest(auth_request::AuthRequest),
    /// Packets of data to / from the tunnel
    Data(data::Data<'data>),
    /// Authentication Success, contains IPV4 configuration (server -> client only)
    AuthSuccessWithConfigV4(auth_success_with_config_ipv4::AuthSuccessWithConfigV4),
    /// Authentication Failure (server -> client only)
    AuthFailure(auth_failure::AuthFailure),
    /// Tell the other side you're hanging up
    Goodbye,
    /// Server configuration data pushed to the client by the server
    ServerConfig(server_config::ServerConfig),
    /// Fragmented Data Packet
    DataFrag(data_frag::DataFrag),
    /// Encoded packet of data to / from the tunnel
    EncodedData(data::Data<'data>),
    /// Encoded Fragmented Data Packet
    EncodedDataFrag(data_frag::DataFrag),
    /// Encoding Request
    EncodingRequest(encoding_request::EncodingRequest),
    /// Encoding Response
    EncodingResponse(encoding_response::EncodingResponse),
    /// Expresslane config
    ExpresslaneConfig(expresslane_config::ExpresslaneConfig),
}

impl Frame<'_> {
    pub(crate) fn kind(&self) -> FrameKind {
        match self {
            Self::NoOp => FrameKind::NoOp,
            Self::Ping(_) => FrameKind::Ping,
            Self::Pong(_) => FrameKind::Pong,
            Self::AuthRequest(_) => FrameKind::AuthRequest,
            Self::Data(_) => FrameKind::Data,
            Self::AuthSuccessWithConfigV4(_) => FrameKind::AuthSuccessWithConfigV4,
            Self::AuthFailure(_) => FrameKind::AuthFailure,
            Self::Goodbye => FrameKind::Goodbye,
            Self::ServerConfig(_) => FrameKind::ServerConfig,
            Self::DataFrag(_) => FrameKind::DataFrag,
            Self::EncodedData(_) => FrameKind::EncodedData,
            Self::EncodedDataFrag(_) => FrameKind::EncodedDataFrag,
            Self::EncodingRequest(_) => FrameKind::EncodingRequest,
            Self::EncodingResponse(_) => FrameKind::EncodingResponse,
            Self::ExpresslaneConfig(_) => FrameKind::ExpresslaneConfig,
        }
    }

    pub(crate) fn try_from_wire(buf: &mut BytesMut) -> FromWireResult<Self> {
        // The kind byte is required
        if buf.is_empty() {
            return Err(FromWireError::InsufficientData);
        }

        // There is a possibility that we end up with FromWireError::InsufficientData, while
        // parsing the buffer. In that case, we should not advance the incoming buffer.
        // So borrow the buf and parse safely. If any error occurred including FromWireError::InsufficientData,
        // return without advancing, so the next parse will start from the same buffer.
        let mut buf = BorrowedBytesMut::from(buf);

        let ty = FrameKind::try_from(buf.get_u8()).map_err(|_| FromWireError::UnknownFrameType)?;
        let frame = match ty {
            FrameKind::NoOp => Self::NoOp,
            FrameKind::Ping => Self::Ping(Ping::try_from_wire(&mut buf)?),
            FrameKind::Pong => Self::Pong(Pong::try_from_wire(&mut buf)?),
            FrameKind::AuthRequest => Self::AuthRequest(AuthRequest::try_from_wire(&mut buf)?),
            FrameKind::Data => Self::Data(Data::try_from_wire(&mut buf)?),
            FrameKind::AuthSuccessWithConfigV4 => {
                Self::AuthSuccessWithConfigV4(AuthSuccessWithConfigV4::try_from_wire(&mut buf)?)
            }
            FrameKind::AuthFailure => Self::AuthFailure(AuthFailure::try_from_wire(&mut buf)?),
            FrameKind::Goodbye => Self::Goodbye,
            FrameKind::ServerConfig => Self::ServerConfig(ServerConfig::try_from_wire(&mut buf)?),
            FrameKind::DataFrag => Self::DataFrag(DataFrag::try_from_wire(&mut buf)?),
            FrameKind::EncodedData => Self::EncodedData(Data::try_from_wire(&mut buf)?),
            FrameKind::EncodedDataFrag => Self::EncodedDataFrag(DataFrag::try_from_wire(&mut buf)?),
            FrameKind::EncodingRequest => {
                Self::EncodingRequest(EncodingRequest::try_from_wire(&mut buf)?)
            }
            FrameKind::EncodingResponse => {
                Self::EncodingResponse(EncodingResponse::try_from_wire(&mut buf)?)
            }
            FrameKind::ExpresslaneConfig => {
                Self::ExpresslaneConfig(ExpresslaneConfig::try_from_wire(&mut buf)?)
            }
        };

        buf.commit(); // We've successfully parsed a frame, move the
        // underlying buffer forward.

        Ok(frame)
    }

    pub(crate) fn append_to_wire(&self, buf: &mut BytesMut) {
        buf.reserve(1);

        buf.put_u8(self.kind().into());

        match self {
            Self::NoOp => {}
            Self::Ping(ping) => ping.append_to_wire(buf),
            Self::Pong(ping) => ping.append_to_wire(buf),
            Self::AuthRequest(auth) => auth.append_to_wire(buf),
            Self::Data(data) => data.append_to_wire(buf),
            Self::AuthSuccessWithConfigV4(cfg) => cfg.append_to_wire(buf),
            Self::AuthFailure(auth) => auth.append_to_wire(buf),
            Self::Goodbye => {}
            Self::ServerConfig(sc) => sc.append_to_wire(buf),
            Self::DataFrag(df) => df.append_to_wire(buf),
            Self::EncodedData(data) => data.append_to_wire(buf),
            Self::EncodedDataFrag(df) => df.append_to_wire(buf),
            Self::EncodingRequest(er) => er.append_to_wire(buf),
            Self::EncodingResponse(er) => er.append_to_wire(buf),
            Self::ExpresslaneConfig(conf) => conf.append_to_wire(buf),
        }
    }
}

#[cfg(test)]
mod session_id {
    use super::*;
    use test_case::test_case;

    #[test_case(SessionId::EMPTY => "0000000000000000")]
    #[test_case(SessionId::REJECTED => "ffffffffffffffff")]
    #[test_case(SessionId([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]) => "123456789abcdef0")]
    fn debug_format(s: SessionId) -> String {
        format!("{s:?}")
    }

    #[test_case(SessionId::EMPTY => true)]
    #[test_case(SessionId::REJECTED => true)]
    #[test_case(SessionId([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]) => false)]
    fn is_reserved(s: SessionId) -> bool {
        s.is_reserved()
    }

    #[test]
    fn gen_random() {
        let a: SessionId = rand::rng().random();
        let b: SessionId = rand::rng().random();
        assert_ne!(a, b, "Two genuinely random sessions IDs should not match");
    }
}

#[cfg(test)]
mod test_header {
    use super::*;
    use test_case::test_case;

    #[test]
    fn from_wire_ok() {
        let mut buf = BytesMut::from(
            &[
                0x48, 0x65, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
                0xde, 0xf0,
            ][..],
        );
        assert_eq!(buf.len(), Header::WIRE_SIZE);

        let h = Header::try_from_wire(&mut buf).expect("decode");
        assert!(buf.is_empty(), "should have consumed all bytes");

        assert_eq!(
            h,
            Header {
                version: crate::Version::try_new(1, 2).unwrap(),
                aggressive_mode: true,
                expresslane_data: false,
                session: SessionId([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]),
            },
        );
    }

    #[test]
    fn from_wire_too_short() {
        let mut buf = BytesMut::from(&[0u8; Header::WIRE_SIZE - 1][..]);
        assert!(matches!(
            Header::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test_case(b'H', b'_')]
    #[test_case(b'_', b'e')]
    fn from_wire_bad_header(a: u8, b: u8) {
        let mut buf = BytesMut::from(
            &[
                a, b, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde,
                0xf0,
            ][..],
        );

        assert!(matches!(
            Header::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InvalidMagicNumber(actual_a, actual_b) if a == actual_a && b == actual_b
        ));
    }

    #[test]
    fn into_wire() {
        let h = Header {
            version: crate::Version::try_new(1, 2).unwrap(),
            aggressive_mode: true,
            expresslane_data: false,
            session: SessionId([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]),
        };

        let mut buf = BytesMut::new();
        h.append_to_wire(&mut buf);
        assert_eq!(
            *buf,
            [
                0x48, 0x65, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
                0xde, 0xf0,
            ]
        )
    }
}

#[cfg(test)]
mod test_frame_kind {
    use super::*;
    use test_case::test_case;

    #[test_case(FrameKind::NoOp => 1)]
    #[test_case(FrameKind::Ping => 2)]
    #[test_case(FrameKind::Pong => 3)]
    #[test_case(FrameKind::AuthRequest => 4)]
    #[test_case(FrameKind::Data => 5)]
    #[test_case(FrameKind::AuthSuccessWithConfigV4 => 6)]
    #[test_case(FrameKind::AuthFailure => 7)]
    #[test_case(FrameKind::Goodbye => 12)]
    #[test_case(FrameKind::ServerConfig => 14)]
    #[test_case(FrameKind::DataFrag => 15)]
    #[test_case(FrameKind::EncodedData => 16)]
    #[test_case(FrameKind::EncodedDataFrag => 17)]
    #[test_case(FrameKind::EncodingRequest => 18)]
    #[test_case(FrameKind::EncodingResponse => 19)]
    fn into_primitive(ty: FrameKind) -> u8 {
        ty.into()
    }

    #[test_case( 1 => FrameKind::NoOp)]
    #[test_case( 2 => FrameKind::Ping)]
    #[test_case( 3 => FrameKind::Pong)]
    #[test_case( 4 => FrameKind::AuthRequest)]
    #[test_case( 5 => FrameKind::Data)]
    #[test_case( 6 => FrameKind::AuthSuccessWithConfigV4)]
    #[test_case( 7 => FrameKind::AuthFailure)]
    #[test_case( 8 => panics "TryFromPrimitiveError { number: 8 }")]
    #[test_case( 9 => panics "TryFromPrimitiveError { number: 9 }")]
    #[test_case(10 => panics "TryFromPrimitiveError { number: 10 }")]
    #[test_case(11 => panics "TryFromPrimitiveError { number: 11 }")]
    #[test_case(12 => FrameKind::Goodbye)]
    #[test_case(13 => panics "TryFromPrimitiveError { number: 13 }")]
    #[test_case(14 => FrameKind::ServerConfig)]
    #[test_case(15 => FrameKind::DataFrag)]
    #[test_case(16 => FrameKind::EncodedData)]
    #[test_case(17 => FrameKind::EncodedDataFrag)]
    #[test_case(18 => FrameKind::EncodingRequest)]
    #[test_case(19 => FrameKind::EncodingResponse)]
    #[test_case(20 => FrameKind::ExpresslaneConfig)]
    fn try_from_primitive(b: u8) -> FrameKind {
        FrameKind::try_from(b).unwrap()
    }

    #[test]
    fn try_from_primitive_out_of_range() {
        for b in 21..=255 {
            assert!(FrameKind::try_from(b).is_err())
        }
    }
}

#[cfg(test)]
mod test_frame {
    use super::*;
    use bytes::Bytes;
    use std::borrow::Cow;
    use test_case::test_case;

    #[test_case(Frame::NoOp => FrameKind::NoOp)]
    #[test_case(Frame::Ping(Ping{ id: 0, payload: Default::default() }) => FrameKind::Ping)]
    #[test_case(Frame::Pong(Pong{ id: 0 }) => FrameKind::Pong)]
    #[test_case(Frame::AuthRequest(AuthRequest{ auth_method: auth_request::AuthMethod::UserPass{ user: Default::default(), password: Default::default() }}) => FrameKind::AuthRequest)]
    #[test_case(Frame::Data(Data{ data: Cow::Owned(BytesMut::new()) }) => FrameKind::Data)]
    #[test_case(Frame::AuthSuccessWithConfigV4(AuthSuccessWithConfigV4{ local_ip: Default::default(), peer_ip: Default::default(), dns_ip: Default::default(), mtu: Default::default(), session: SessionId::EMPTY }) => FrameKind::AuthSuccessWithConfigV4)]
    #[test_case(Frame::AuthFailure(AuthFailure) => FrameKind::AuthFailure)]
    #[test_case(Frame::Goodbye => FrameKind::Goodbye)]
    #[test_case(Frame::ServerConfig(ServerConfig{ data: Default::default() }) => FrameKind::ServerConfig)]
    #[test_case(Frame::DataFrag(DataFrag{ id: 0, offset: 0, more_fragments: true, data: Default::default() }) => FrameKind::DataFrag)]
    #[test_case(Frame::EncodingRequest(EncodingRequest{ id: 513, enable: true }) => FrameKind::EncodingRequest)]
    #[test_case(Frame::EncodingResponse(EncodingResponse{ id: 513, enable: true }) => FrameKind::EncodingResponse)]
    fn frame_kind(f: Frame) -> FrameKind {
        f.kind()
    }

    #[test_case(Frame::NoOp => vec![0x01]; "noop")]
    #[test_case(Frame::Ping(Ping{ id: 0xf00b, payload: Default::default()}) => vec![0x2, 0xf0, 0x0b, 0x00, 0x00]; "ping")]
    #[test_case(Frame::Pong(Pong{ id: 0xabcd }) => vec![0x3, 0xab, 0xcd, 0x00, 0x00]; "pong")]
    #[test_case(Frame::AuthRequest(AuthRequest{ auth_method: auth_request::AuthMethod::UserPass{ user: "me".to_string(), password: "secret".to_string() }}) => b"\x04\x01\x02\x06me\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00secret\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(); "auth request userpass")]
    #[test_case(Frame::AuthRequest(AuthRequest{ auth_method: auth_request::AuthMethod::Token{ token: "token".to_string() }}) => b"\x04\x02\x00\x05token".to_vec(); "auth request token")]
    #[test_case(Frame::AuthRequest(AuthRequest{ auth_method: auth_request::AuthMethod::CustomCallback{ data: Bytes::from_static(&[1, 2, 3, 4]) }}) => vec![0x4, 23, 0x00, 0x04, 1, 2, 3, 4]; "auth request custom callback")]
    #[test_case(Frame::Data(Data{ data: Cow::Owned(BytesMut::from(&[0xfe, 0xbe, 0xaa][..]))}) => vec![0x5, 0, 3, 0xfe, 0xbe, 0xaa]; "data")]
    #[test_case(Frame::AuthSuccessWithConfigV4(AuthSuccessWithConfigV4{ local_ip: "1.1.1.1".to_string(), peer_ip: "2.2.2.2".to_string(), dns_ip: "3.3.3.3".to_string(), mtu: "1500".to_string(), session: SessionId([0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x2f, 0x66]) }) => b"\x061.1.1.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002.2.2.2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003.3.3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x001500\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x66".to_vec(); "auth success with config v4")]
    #[test_case(Frame::AuthFailure(AuthFailure) =>  b"\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(); "auth failure")]
    #[test_case(Frame::Goodbye => vec![0x0c]; "goodbye")]
    #[test_case(Frame::ServerConfig(ServerConfig{ data: Bytes::from_static(b"server config")}) => b"\x0e\x00\x0dserver config".to_vec(); "server config")]
    #[test_case(Frame::DataFrag(DataFrag{ id: 0x1234, offset: 0x5678, more_fragments: true, data: Bytes::from_static(b"fragmentary") }) => b"\x0f\x00\x0b\x12\x34\x2a\xcffragmentary".to_vec() ; "data frag")]
    #[test_case(Frame::EncodingRequest(EncodingRequest{ id: 513, enable: true}) => b"\x12\x00\x00\x00\x00\x00\x00\x02\x01\x01".to_vec(); "encoding request")]
    #[test_case(Frame::EncodingResponse(EncodingResponse{ id: 513, enable: true}) => b"\x13\x00\x00\x00\x00\x00\x00\x02\x01\x01".to_vec(); "encoding response")]
    fn into_wire(f: Frame) -> Vec<u8> {
        let mut buf = BytesMut::new();
        f.append_to_wire(&mut buf);
        buf.into()
    }

    #[test_case(&[0x01] => Frame::NoOp; "noop")]
    #[test_case(&[0x2, 0xf0, 0x0b, 0x00, 0x00] => Frame::Ping(Ping{ id: 0xf00b, payload: Default::default() }); "ping")]
    #[test_case(&[0x3, 0xab, 0xcd, 0x00, 0x00] => Frame::Pong(Pong{ id: 0xabcd }); "pong")]
    #[test_case(b"\x04\x01\x02\x06me\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00secret\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" => Frame::AuthRequest(AuthRequest{ auth_method: auth_request::AuthMethod::UserPass{ user: "me".to_string(), password: "secret".to_string() }}); "auth request user pass")]
    #[test_case(b"\x04\x02\x00\x05token" => Frame::AuthRequest(AuthRequest{ auth_method: auth_request::AuthMethod::Token{ token: "token".to_string() }}); "auth request token")]
    #[test_case(&[0x4, 23, 0x00, 0x04, 1, 2, 3, 4] => Frame::AuthRequest(AuthRequest{ auth_method: auth_request::AuthMethod::CustomCallback{ data: Bytes::from_static(&[1, 2, 3, 4]) }}); "auth request custom callback")]
    #[test_case(&[0x5, 0, 3, 0xfe, 0xbe, 0xaa] => Frame::Data(Data{ data: Cow::Owned(BytesMut::from(&[0xfe, 0xbe, 0xaa][..]))}); "data")]
    #[test_case(b"\x061.1.1.1\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x002.2.2.2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003.3.3.3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x001500\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x66" => Frame::AuthSuccessWithConfigV4(AuthSuccessWithConfigV4{ local_ip: "1.1.1.1".to_string(), peer_ip: "2.2.2.2".to_string(), dns_ip: "3.3.3.3".to_string(), mtu: "1500".to_string(), session: SessionId([0x00, 0x00, 0x00, 0x00, 0x00, 0x00,0x2f, 0x66]) }); "auth success with config v4")]
    #[test_case(b"\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" => Frame::AuthFailure(AuthFailure); "auth failure")]
    #[test_case(&[0x0c] => Frame::Goodbye; "goodbye")]
    #[test_case(b"\x0e\x00\x0dserver config" => Frame::ServerConfig(ServerConfig{ data: Bytes::from_static(b"server config")}); "server config")]
    #[test_case(b"\x0f\x00\x0b\x12\x34\x2a\xcffragmentary"=> Frame::DataFrag(DataFrag{ id: 0x1234, offset: 0x5678, more_fragments: true, data: Bytes::from_static(b"fragmentary") }) ; "data frag")]
    #[test_case(&[0x10, 0, 3, 0xfe, 0xbe, 0xaa] => Frame::EncodedData(Data{ data: Cow::Owned(BytesMut::from(&[0xfe, 0xbe, 0xaa][..]))}); "encoded data")]
    #[test_case(b"\x11\x00\x0b\x12\x34\x2a\xcffragmentary"=> Frame::EncodedDataFrag(DataFrag{ id: 0x1234, offset: 0x5678, more_fragments: true, data: Bytes::from_static(b"fragmentary") }) ; "encoded data frag")]
    #[test_case(b"\x12\x00\x00\x00\x00\x00\x00\x02\x01\x01"=> Frame::EncodingRequest(EncodingRequest{id: 513, enable: true}) ; "encoding request")]
    #[test_case(b"\x13\x00\x00\x00\x00\x00\x00\x02\x02\x00"=> Frame::EncodingResponse(EncodingResponse{id: 514, enable: false}) ; "encoding response")]
    fn try_from_wire(buf: &'static [u8]) -> Frame<'static> {
        let mut buf = BytesMut::from(buf);
        let r = Frame::try_from_wire(&mut buf).unwrap();
        assert!(buf.is_empty(), "Should consume entire frame");
        r
    }

    #[test]
    fn from_wire_too_short() {
        let mut buf = BytesMut::from(&[0u8; 0][..]);
        assert!(matches!(
            Frame::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::InsufficientData
        ));
    }

    #[test]
    fn from_wire_unknown_frame_kind() {
        let mut buf = BytesMut::from(&[127u8; 1][..]);
        assert!(matches!(
            Frame::try_from_wire(&mut buf).err().unwrap(),
            FromWireError::UnknownFrameType
        ));
    }

    #[test]
    fn partial_decode() {
        let mut buf = BytesMut::with_capacity(5);

        // Initial partial frame
        buf.extend_from_slice(&[0x2, 0xf0, 0x0b]);

        // Try (and fail) to consume it
        let r = Frame::try_from_wire(&mut buf);
        assert!(matches!(r, Err(FromWireError::InsufficientData)));

        assert_eq!(
            &buf[..],
            &[0x2, 0xf0, 0x0b],
            "buf should still have all the data"
        );

        // Add the rest of the partial frame
        buf.extend_from_slice(&[0x00, 0x00]);
        // Add another frame
        buf.extend_from_slice(&[0x1]);
        // Consume the now complete frame
        let r = Frame::try_from_wire(&mut buf).unwrap();
        assert_eq!(
            r,
            Frame::Ping(Ping {
                id: 0xf00b,
                payload: Default::default(),
            })
        );

        // Consume the second frame
        let r = Frame::try_from_wire(&mut buf);
        assert!(matches!(r, Ok(Frame::NoOp)));

        assert!(buf.is_empty(), "Should have consumed everything");
    }
}
