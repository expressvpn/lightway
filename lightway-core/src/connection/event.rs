use crate::connection::ExpresslaneState;
use crate::{PmtudStatus, SessionId, State};

/// A lightway event
#[derive(Debug)]
pub enum Event {
    /// The connection state has changed
    StateChanged(State),
    /// A reply was received after a [`crate::Connection::keepalive()`]
    KeepaliveReply,
    /// A new session id has been generated and will be used in
    /// outgoing packets. The old session id is still active until
    /// the peer acknowledges the new one.
    ///
    /// Server connections only
    SessionIdRotationStarted {
        /// The current [`SessionId`]
        old: SessionId,
        /// The new [`SessionId`]
        new: SessionId,
    },
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
    /// Path MTU discovery state or estimate changed.
    ///
    /// Fired on every DPLPMTUD state transition and whenever the PLPMTU
    /// estimate changes within a state (each confirmed search probe).
    /// [`PmtudStatus::max_packet_size`] is the largest inside packet the
    /// connection now sends unfragmented; `None` means no estimate is
    /// available and the connection sizes packets by its configured
    /// outside MTU instead.
    ///
    /// Only client datagram connections built with a PMTUD timer
    /// ([`crate::ClientConnectionBuilder::with_pmtud_timer`]) emit this
    /// event; servers and stream connections never do.
    ///
    /// The event is a notification of a change, delivered synchronously
    /// from the call that drove the state machine. A consumer that
    /// receives events through an asynchronous bridge which does not
    /// preserve their order (for example one that spawns a task per
    /// event) should read [`crate::Connection::pmtud_status`] for the
    /// current snapshot rather than apply the event's payload.
    PmtudStateChanged(PmtudStatus),
}
