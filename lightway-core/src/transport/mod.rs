//! The transport under a [`crate::Connection`].
//!
//! A transport owns the secure session and the framing between
//! Lightway frames and the outside path. The connection owns the
//! Lightway state machine and never touches the secure session or the
//! socket.

pub(crate) mod tls;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;

use crate::tls::{IOCallbackResult, Poll, ProtocolVersion};
use crate::{OutsideIOSendCallbackArg, SessionId};

/// Result of a transport operation that can need more outside I/O.
pub type PollResult<T> = Result<Poll<T>, TransportError>;

/// An error from the transport. The transport decides whether the
/// connection survives it.
#[derive(Debug, thiserror::Error)]
#[error("{error}")]
pub struct TransportError {
    fatal: bool,
    error: Box<dyn std::error::Error + Send + Sync>,
}

impl TransportError {
    /// Wrap an error. Set `fatal` when the error ends the connection.
    pub fn new(fatal: bool, error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self {
            fatal,
            error: error.into(),
        }
    }

    /// Whether this error ends the connection.
    pub fn is_fatal(&self) -> bool {
        self.fatal
    }
}

/// What a transport can and cannot do. The connection adapts its
/// framing, queueing and error handling to these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCaps {
    /// Datagram framing: one Lightway frame travels per packet, and
    /// packets are independent. A packet can be lost or reordered,
    /// and nothing retransmits it.
    pub lossy: bool,
    /// Control frames are delivered in order and never lost, even when
    /// `lossy` is set. When the outside path blocks, the connection
    /// queues the frames that nothing above retransmits (control and
    /// inner UDP), and does not drop them.
    pub reliable_control: bool,
    /// Every packet starts with a [`crate::Header`] that carries the
    /// session id. Expresslane needs it: the header marks an
    /// expresslane record and carries the session id that its
    /// decryption uses.
    pub wire_header: bool,
}

pub(crate) use tls::TlsTransport;

/// The transport under a connection.
///
/// Every method is synchronous. A method that needs the outside path
/// reports `Pending*` and the caller retries after the next outside
/// packet or tick.
pub trait Transport: Send {
    /// Capabilities of this transport. The connection reads them once,
    /// when it is built.
    fn caps(&self) -> TransportCaps;

    /// Largest number of frame bytes one packet can carry. The
    /// connection reads this only on a `lossy` transport. It stays
    /// constant for the life of the transport.
    fn max_frame_payload(&self) -> usize;

    /// Drive the handshake. `Ready` once the secure link is up.
    fn handshake(&mut self) -> PollResult<()>;

    /// Hand one received outside payload to the transport.
    fn feed(&mut self, buf: &[u8]);

    /// The connection calls this after it processes the current packet.
    /// A lossy transport drops what the session did not consume, because
    /// a record never spans packets.
    fn packet_done(&mut self);

    /// Read decrypted frame bytes into `into`.
    fn read(&mut self, into: &mut BytesMut) -> PollResult<usize>;

    /// Encrypt and send frame bytes. `buf` holds exactly one Lightway
    /// frame. Advances `buf` by the bytes consumed. After a blocked
    /// write, the connection retries with the same buffer.
    fn write(&mut self, buf: &mut BytesMut) -> PollResult<usize>;

    /// Close the secure session.
    fn shutdown(&mut self) -> PollResult<bool>;

    /// Start a key update.
    fn key_update(&mut self) -> PollResult<()>;

    /// Whether a key update is in flight.
    fn key_update_pending(&mut self) -> bool;

    /// Interval until the transport needs a tick, `None` when it
    /// needs no ticks. The connection asks only while the link comes
    /// up or a key update is pending.
    fn tick_interval(&mut self) -> Option<Duration>;

    /// The connection calls this on each tick, except while the client
    /// authenticates. Retransmit here if necessary, and return true
    /// when the peer is lost.
    fn has_timed_out(&mut self) -> Poll<bool>;

    /// Negotiated secure protocol version.
    fn protocol_version(&mut self) -> ProtocolVersion;

    /// Negotiated cipher, once the link is up.
    fn current_cipher(&mut self) -> Option<String>;

    /// Negotiated key exchange group, once the link is up.
    fn current_curve(&mut self) -> Option<String>;

    /// Session id to stamp on outgoing packets.
    fn set_session_id(&mut self, id: SessionId);

    /// The connection calls this when it reaches
    /// [`crate::State::Online`], after auth.
    fn online(&mut self);

    /// Mark outgoing packets as PMTUD probes, which the path must not
    /// fragment.
    fn pmtud_probe(&mut self, on: bool);

    /// Replace the outside path.
    fn set_outside_io(&mut self, io: OutsideIOSendCallbackArg);

    /// Peer address of the outside path.
    fn peer_addr(&self) -> SocketAddr;

    /// Change the peer address. Return the previous address.
    fn set_peer_addr(&mut self, addr: SocketAddr) -> SocketAddr;

    /// Send an expresslane record, which the connection already
    /// encrypted, beside the secure session. The connection calls this
    /// only on a `wire_header` transport.
    fn send_expresslane(&mut self, buf: &[u8]) -> IOCallbackResult<usize>;

    /// Open a batch: sends coalesce until [`Transport::batch_end`].
    #[cfg(target_os = "linux")]
    fn batch_begin(&mut self);

    /// Close the open batch. Flush it if `send`, else drop it.
    #[cfg(target_os = "linux")]
    fn batch_end(&mut self, send: bool) -> IOCallbackResult<usize>;
}
