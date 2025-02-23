mod connection_map;

use dashmap::DashMap;
use delegate::delegate;
use parking_lot::Mutex;
use std::{
    net::SocketAddr,
    sync::{
        Arc, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
use thiserror::Error;
use time::Duration;
use tokio_stream::StreamExt;
use tracing::{info, instrument, warn};

use crate::connection_manager::connection_map::InsertError;
use crate::{
    connection::{Connection, ConnectionState},
    metrics,
};
use connection_map::ConnectionMap;
use lightway_app_utils::{EventStream, EventStreamCallback};
use lightway_core::{
    ConnectionActivity, ConnectionBuilderError, ConnectionError, ContextError, Event,
    OutsideIOSendCallbackArg, OutsidePacket, ServerContext, SessionId, State, Version,
};

/// How often to check for connections to expire aged connections
const CONNECTION_AGE_EXPIRATION_INTERVAL: Duration = Duration::minutes(1);

/// How often to check for connections to expire connections where authentication has expired
const CONNECTION_AUTH_EXPIRATION_INTERVAL: Duration = Duration::hours(6);

/// How long a connection can be idle for
const CONNECTION_MAX_IDLE_AGE: Duration = Duration::days(1);

/// How long a connection can take to become Online
/// If connection is not online by this time, it will be closed to save resources
const CONNECTION_STALE_AGE: std::time::Duration = std::time::Duration::from_secs(60);

impl connection_map::Value for Connection {
    fn socket_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    fn session_id(&self) -> SessionId {
        self.session_id()
    }
}

#[derive(Debug, Error)]
pub(crate) enum ConnectionManagerError {
    /// Client session id and connection session id mismatch
    #[error("Client session id and connection session id mismatch")]
    SessionIdMismatch,

    /// No active session for client
    #[error("No active session for client")]
    NoActiveSession,

    /// Connection map error occurred
    #[error("Connection Map Error: {0}")]
    ConnectionMap(#[from] InsertError),

    /// LW Connection Builder error occurred
    #[error("ConnectionBuilder Error: {0}")]
    LwConnectionBuilder(#[from] ConnectionBuilderError),

    /// LW Connection error occurred
    #[error("Connection Error: {0}")]
    LwConnection(#[from] ConnectionError),

    /// LW Context Builder error occurred
    #[error("Context Error: {0}")]
    LwContextError(#[from] ContextError),
}

async fn evict_idle_connections(manager: Weak<ConnectionManager>) {
    let mut ticker = tokio::time::interval(CONNECTION_AGE_EXPIRATION_INTERVAL.unsigned_abs());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticker = tokio_stream::wrappers::IntervalStream::new(ticker);

    while ticker.next().await.is_some() {
        let Some(manager) = manager.upgrade() else {
            info!("Connection Manager has gone away, stopping");
            return;
        };
        manager.evict_idle_connections();
    }
}

async fn evict_expired_connections(manager: Weak<ConnectionManager>) {
    let mut ticker = tokio::time::interval(CONNECTION_AUTH_EXPIRATION_INTERVAL.unsigned_abs());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticker = tokio_stream::wrappers::IntervalStream::new(ticker);

    while ticker.next().await.is_some() {
        let Some(manager) = manager.upgrade() else {
            info!("Connection Manager has gone away, stopping");
            return;
        };
        manager.evict_expired_connections();
    }
}

pub(crate) struct ConnectionManager {
    ctx: ServerContext<ConnectionState>,
    connections: Mutex<ConnectionMap<Connection>>,
    pending_session_id_rotations: DashMap<SessionId, Arc<Connection>>,
    /// Total number of sessions there have ever been
    total_sessions: AtomicUsize,
}

#[instrument(level = "trace", skip_all)]
async fn handle_state_change(state: State, conn: &Weak<Connection>) {
    let Some(conn) = conn.upgrade() else {
        info!("Connection has gone away, stopping");
        return;
    };

    info!(session = ?conn.session_id(), ?state, "State changed for {:?}", conn.peer_addr(),);

    match state {
        State::Connecting => {}
        State::LinkUp => {
            metrics::connection_link_up(&conn);
        }
        State::Authenticating => {}
        State::Online => {
            metrics::connection_online(&conn);
        }
        State::Disconnecting => {}
        State::Disconnected => {}
    }
}

#[instrument(level = "trace", skip_all)]
fn handle_finalize_session_rotation(conn: &Weak<Connection>, old: SessionId, new: SessionId) {
    let Some(conn) = conn.upgrade() else {
        info!("Connection has gone away, stopping");
        return;
    };

    conn.finalize_session_id_rotation(old, new);
}

#[instrument(level = "trace", skip_all)]
fn handle_tls_keys_update_start(conn: &Weak<Connection>) {
    metrics::connection_key_update_start();

    // For UDP connections begin a session ID rotation
    let Some(conn) = conn.upgrade() else {
        info!("Connection has gone away, stopping");
        return;
    };

    if conn.connection_type().is_datagram() {
        conn.begin_session_id_rotation();
    }
}

#[instrument(level = "trace", skip_all)]
fn handle_tls_keys_update_complete() {
    metrics::connection_key_update_complete();
}

#[instrument(level = "trace", skip_all)]
async fn handle_events(mut stream: EventStream, conn: Weak<Connection>) {
    while let Some(event) = stream.next().await {
        match event {
            Event::StateChanged(state) => handle_state_change(state, &conn).await,
            Event::KeepaliveReply => {}
            Event::SessionIdRotationAcknowledged { old, new } => {
                handle_finalize_session_rotation(&conn, old, new);
            }
            Event::TlsKeysUpdateStart => handle_tls_keys_update_start(&conn),
            Event::TlsKeysUpdateCompleted => handle_tls_keys_update_complete(),
            Event::FirstPacketReceived => {
                unreachable!("client only event received");
            }
        }
    }
}

#[instrument(level = "trace", skip_all)]
async fn handle_stale(conn: Weak<Connection>) {
    tokio::time::sleep(CONNECTION_STALE_AGE).await;
    if let Some(conn) = conn.upgrade() {
        if !matches!(conn.state(), State::Online) {
            metrics::connection_stale_closed();
            let _ = conn.disconnect();
        }
    };
}

fn new_connection(
    manager: Arc<ConnectionManager>,
    ctx: &ServerContext<ConnectionState>,
    protocol_version: Version,
    local_addr: SocketAddr,
    outside_io: OutsideIOSendCallbackArg,
) -> Result<Arc<Connection>, ConnectionManagerError> {
    metrics::connection_created(&protocol_version);

    let (event_cb, event_stream) = EventStreamCallback::new();

    manager.total_sessions.fetch_add(1, Ordering::Relaxed);
    let conn = Connection::new(
        ctx,
        manager,
        protocol_version,
        local_addr,
        outside_io,
        event_cb,
    )
    .inspect_err(|err| {
        metrics::connection_create_failed(&protocol_version);
        warn!(?err, "Failed to create new connection");
    })?;

    tokio::spawn(handle_events(event_stream, Arc::downgrade(&conn)));
    tokio::spawn(handle_stale(Arc::downgrade(&conn)));

    Ok(conn)
}

impl ConnectionManager {
    pub(crate) fn new(ctx: ServerContext<ConnectionState>) -> Arc<Self> {
        let conn_manager = Arc::new(Self {
            ctx,
            connections: Mutex::new(Default::default()),
            pending_session_id_rotations: Default::default(),
            total_sessions: Default::default(),
        });

        tokio::spawn(evict_idle_connections(Arc::downgrade(&conn_manager)));
        tokio::spawn(evict_expired_connections(Arc::downgrade(&conn_manager)));

        conn_manager
    }

    delegate! {
        to self.ctx {
            pub(crate) fn is_supported_version(&self, v: Version) -> bool;
            pub(crate) fn parse_raw_outside_packet<'pkt>(&self, buf: OutsidePacket<'pkt>) -> Result<OutsidePacket<'pkt>, ContextError>;
        }
    }

    pub(crate) fn total_sessions(&self) -> usize {
        self.total_sessions.load(Ordering::Relaxed)
    }

    pub(crate) fn pending_session_id_rotations_count(&self) -> usize {
        self.pending_session_id_rotations.len()
    }

    pub(crate) fn create_streaming_connection(
        self: &Arc<Self>,
        protocol_version: Version,
        socket_addr: SocketAddr,
        outside_io: OutsideIOSendCallbackArg,
    ) -> Result<Arc<Connection>, ConnectionManagerError> {
        let conn = new_connection(
            self.clone(),
            &self.ctx,
            protocol_version,
            socket_addr,
            outside_io,
        )?;
        // TODO: what if addr was already present?
        self.connections.lock().insert(&conn)?;
        Ok(conn)
    }

    /// Lookup the [`Connection`] associated with `addr` or
    /// `session_id`
    ///
    /// If a connection is found then it will be returned.
    ///
    /// If no connection is found and `session_id` is
    /// `SessionID::EMPTY` then a new connection is created and
    /// returned.
    ///
    /// If the `session_id` is not `SessionID::EMPTY` (i.e. the client
    /// thinks there is a session but we didn't find one) then `None`
    /// is returned and the packet should be rejected.
    ///
    /// The second member of the returned tuple indicates that the
    /// caller should call [`Connection::set_peer_addr`] after
    /// successfully calling [`Connection::outside_data_received`] (or
    /// a variant). This will commit to the new client address, after
    /// the client is observed to have floated and we have successfully done .
    pub(crate) fn find_or_create_datagram_connection_with<F>(
        self: &Arc<Self>,
        addr: SocketAddr,
        protocol_version: Version,
        session_id: SessionId,
        local_addr: SocketAddr,
        create_io: F,
    ) -> Result<(Arc<Connection>, bool), ConnectionManagerError>
    where
        F: FnOnce() -> OutsideIOSendCallbackArg,
    {
        match self.connections.lock().lookup(addr, session_id) {
            connection_map::Entry::Occupied(c) => {
                if session_id == SessionId::EMPTY || c.session_id() == session_id {
                    let update_peer_address = addr != c.peer_addr();
                    Ok((c.clone(), update_peer_address))
                } else {
                    // If the session id of the client does not match
                    // the session id of our connection then reject.
                    Err(ConnectionManagerError::SessionIdMismatch)
                }
            }
            connection_map::Entry::Vacant(e) if session_id == SessionId::EMPTY => {
                info!(?addr, %protocol_version, "New Client");
                let outside_io = create_io();
                let c = new_connection(
                    self.clone(),
                    &self.ctx,
                    protocol_version,
                    local_addr,
                    outside_io,
                )?;
                e.insert(&c)?;
                Ok((c, false))
            }
            connection_map::Entry::Vacant(_e) => {
                // Maybe this is a pending session rotation
                if let Some(c) = self.pending_session_id_rotations.get(&session_id) {
                    let update_peer_address = addr != c.peer_addr();

                    return Ok((c.clone(), update_peer_address));
                }

                // Client thinks we should have a session, but we don't, reject.
                Err(ConnectionManagerError::NoActiveSession)
            }
        }
    }

    pub(crate) fn find_datagram_connection_with(
        self: &Arc<Self>,
        addr: SocketAddr,
    ) -> Option<Arc<Connection>> {
        self.connections.lock().find_by(addr)
    }

    pub(crate) fn set_peer_addr(&self, conn: &Arc<Connection>, new_addr: SocketAddr) {
        let old_addr = conn.set_peer_addr(new_addr);
        self.connections
            .lock()
            .update_socketaddr_for_connection(old_addr, new_addr);
    }

    pub(crate) fn remove_connection(&self, conn: &Connection) {
        self.connections.lock().remove(conn)
    }

    pub(crate) fn begin_session_id_rotation(
        &self,
        conn: &Arc<Connection>,
        new_session_id: SessionId,
    ) {
        self.pending_session_id_rotations
            .insert(new_session_id, conn.clone());

        metrics::udp_session_rotation_begin();
    }

    pub(crate) fn finalize_session_id_rotation(
        &self,
        _conn: &Arc<Connection>,
        old: SessionId,
        new: SessionId,
    ) {
        self.pending_session_id_rotations.remove(&new);
        self.connections
            .lock()
            .update_session_id_for_connection(old, new);

        metrics::udp_session_rotation_finalized();
    }

    pub(crate) fn online_connection_activity(&self) -> Vec<ConnectionActivity> {
        self.connections
            .lock()
            .iter_connections()
            .filter_map(|c| match c.state() {
                State::Online => Some(c.activity()),
                _ => None,
            })
            .collect()
    }

    #[instrument(level = "trace", skip_all)]
    fn evict_idle_connections(&self) {
        tracing::trace!("Aging connections");

        for conn in self.connections.lock().iter_connections() {
            let age = conn.activity().last_outside_data_received.elapsed();
            if age > CONNECTION_MAX_IDLE_AGE {
                tracing::info!(session = ?conn.session_id(), age = ?age, "Disconnecting idle connection");
                metrics::connection_aged_out();
                // `iter_connections` holds the connection map lock, disconnect asynchronously
                let conn = conn.clone();
                tokio::spawn(async move {
                    let _ = conn.disconnect();
                });
            } else {
                tracing::trace!(session = ?conn.session_id(), age = ?age, "Keeping active connection");
            }
        }
    }

    #[instrument(level = "trace", skip_all)]
    fn evict_expired_connections(&self) {
        tracing::trace!("Expiring connections");

        for conn in self.connections.lock().iter_connections() {
            let Ok(expired) = conn.authentication_expired() else {
                continue;
            };

            if expired {
                tracing::info!(session = ?conn.session_id(), "Disconnecting expired connection");
                metrics::connection_expired();
                // `iter_connections` holds the connection map lock, disconnect asynchronously
                let conn = conn.clone();
                tokio::spawn(async move {
                    let _ = conn.disconnect();
                });
            }
        }
    }

    pub(crate) fn close_all_connections(&self) {
        let connections = self.connections.lock().remove_connections();
        for conn in connections {
            let _ = conn.lw_disconnect();
        }
    }
}
