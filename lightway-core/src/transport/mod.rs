//! The transport under a [`crate::Connection`].
//!
//! A transport owns the secure session. It turns Lightway frames into
//! records and records back into frames. It never touches the outside
//! IO: the connection takes the records and sends them.

pub(crate) mod tls;

use std::time::Duration;

use bytes::BytesMut;

use crate::tls::{Poll, ProtocolVersion};

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

/// How a transport delivers records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// In order, and never lost. When the outside path blocks, the
    /// connection queues the frames that nothing above retransmits
    /// (control and inner UDP).
    Stream,
    /// One Lightway frame travels per packet, and packets are
    /// independent. A packet can be lost or reordered, and nothing
    /// retransmits it.
    Datagram {
        /// Every packet starts with a [`crate::Header`] that carries the
        /// session id. Expresslane needs it: the header marks an
        /// expresslane record and carries the session id that its
        /// decryption uses.
        wire_header: bool,
    },
}

/// What a transport can and cannot do. The connection adapts its
/// framing, queueing and error handling to these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportCaps {
    /// How the transport delivers records.
    pub delivery: Delivery,
}

impl TransportCaps {
    /// Whether a record can be lost: [`Delivery::Datagram`].
    pub fn is_lossy(&self) -> bool {
        matches!(self.delivery, Delivery::Datagram { .. })
    }

    /// Whether every packet starts with a [`crate::Header`].
    pub fn has_wire_header(&self) -> bool {
        matches!(self.delivery, Delivery::Datagram { wire_header: true })
    }
}

pub(crate) use tls::TlsTransport;

/// The transport under a connection.
///
/// Every method is synchronous. A method that needs the outside path
/// reports `Pending*` and the caller retries after the next outside
/// packet or tick. After each call, the connection takes every record
/// with [`Transport::poll_transmit`].
pub trait Transport: Send {
    /// Capabilities of this transport. The connection reads them once,
    /// when it is built.
    fn caps(&self) -> TransportCaps;

    /// Largest number of frame bytes one packet can carry. The
    /// connection reads this only on a datagram transport. It stays
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

    /// Encrypt frame bytes into records. `buf` holds exactly one
    /// Lightway frame. Advances `buf` by the bytes consumed. After a
    /// blocked write, the connection retries with the same buffer.
    fn write(&mut self, buf: &mut BytesMut) -> PollResult<usize>;

    /// Take the next record to send, if any.
    fn poll_transmit(&mut self) -> Option<BytesMut>;

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

    /// The connection calls this when it reaches
    /// [`crate::State::Online`], after auth.
    fn online(&mut self);
}
