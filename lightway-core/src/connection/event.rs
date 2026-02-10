use crate::connection::ExpresslaneState;
use crate::{SessionId, State};

/// A lightway event
#[derive(Debug)]
pub enum Event {
    /// The connection state has changed
    StateChanged(State),
    /// A reply was received after a [`crate::Connection::keepalive()`]
    KeepaliveReply,
    /// A pending session id change (following a call to
    /// [`crate::Connection::rotate_session_id`]) has been
    /// acknowledged and applied to the connection.
    ///
    /// Server connections only
    SessionIdRotationAcknowledged {
        /// The original [`SessionId`]
        old: SessionId,
        /// The new [`SessionId`]
        new: SessionId,
    },
    /// A key rollover was started for a TLS or DTLS 1.3 connection.
    ///
    /// Server connections only
    TlsKeysUpdateStart,
    /// A key rollover was completed for a TLS or DTLS 1.3 connection.
    ///
    /// Server connections only
    TlsKeysUpdateCompleted,
    /// The first packet from the server has been received
    ///
    /// Client connections only
    FirstPacketReceived,
    /// The inside packet codec encoding state has changed
    ///
    /// Fired when the server agrees to enable or disable the inside packet codec
    /// after the client requests it, or when the server enables/disables it.
    EncodingStateChanged {
        /// Whether encoding is now enabled
        enabled: bool,
    },
    /// Expresslane state changed
    ExpresslaneStateChanged(ExpresslaneState),
}
