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
pub type PollResult<T> = Result<Poll<T>, crate::tls::Error>;

pub(crate) use tls::TlsTransport;

/// The transport under a connection.
///
/// Every method is synchronous. A method that needs the outside path
/// reports `Pending*` and the caller retries after the next outside
/// packet or tick. After each call, the connection takes every record
/// with [`Transport::poll_transmit`].
pub trait Transport: Send {
    /// Drive the handshake. `Ready` once the secure link is up.
    fn handshake(&mut self) -> PollResult<()>;

    /// Hand one received outside payload to the transport.
    fn feed(&mut self, buf: &[u8]);

    /// Drop received bytes the transport did not consume.
    fn discard_pending(&mut self);

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
