use bytes::BytesMut;
use delegate::delegate;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, Weak},
};
use tracing::{trace, warn};

use crate::{
    connection_manager::{ConnectionManager, ConnectionManagerError},
    metrics,
};
use lightway_app_utils::{ConnectionTicker, ConnectionTickerState, EventStreamCallback, Tickable};
use lightway_core::{
    ConnectionActivity, ConnectionError, ConnectionResult, ConnectionType,
    OutsideIOSendCallbackArg, OutsidePacket, PacketEncoderType, ProtocolVersion, ServerContext,
    SessionId, State, Version,
};

pub struct ConnectionState {
    // Handler for tick callbacks.
    ticker: ConnectionTicker,
    // The local IP which the client has connected to
    pub local_addr: SocketAddr,
    // Addr of connected client
    pub peer_addr: SocketAddr,
    // The backend IP (from IP pool) associated with this connection
    pub internal_ip: Option<Ipv4Addr>,
    // The connection
    pub(crate) conn: std::cell::OnceCell<Weak<Connection>>,
}

impl ConnectionTickerState for ConnectionState {
    fn connection_ticker(&self) -> &ConnectionTicker {
        &self.ticker
    }
}

pub(crate) struct Connection {
    manager: Arc<ConnectionManager>,
    lw_conn: Mutex<lightway_core::Connection<ConnectionState>>,
    pub(crate) connection_started: std::time::Instant,
}

impl Tickable for Connection {
    fn tick(&self) -> ConnectionResult<()> {
        Connection::tick(self)
    }
}

impl Connection {
    pub fn new(
        ctx: &ServerContext<ConnectionState>,
        manager: Arc<ConnectionManager>,
        protocol_version: Version,
        local_addr: SocketAddr,
        outside_io: OutsideIOSendCallbackArg,
        event_cb: EventStreamCallback,
    ) -> Result<Arc<Self>, ConnectionManagerError> {
        tracing::debug!(?local_addr, "New connection");
        let connection_started = std::time::Instant::now();

        let (ticker, ticker_task) = ConnectionTicker::new();
        let state = ConnectionState {
            ticker,
            local_addr,
            peer_addr: outside_io.peer_addr(),
            internal_ip: None,
            conn: std::cell::OnceCell::new(),
        };

        let lw_conn = Mutex::new(
            ctx.start_accept(protocol_version, outside_io)?
                .with_event_cb(Box::new(event_cb))
                .accept(state)?,
        );

        let conn = Arc::new(Self {
            manager,
            lw_conn,
            connection_started,
        });

        conn.lw_conn
            .lock()
            .unwrap()
            .app_state_mut()
            .conn
            .set(Arc::downgrade(&conn))
            .unwrap();

        ticker_task.spawn(Arc::downgrade(&conn));
        metrics::connection_created(&protocol_version);

        Ok(conn)
    }

    delegate! {
        to self.lw_conn.lock().unwrap() {
            pub fn tls_protocol_version(&self) -> ProtocolVersion;
            pub fn connection_type(&self) -> ConnectionType;
            pub fn session_id(&self) -> SessionId;
            pub fn peer_addr(&self) -> SocketAddr;
            pub fn set_peer_addr(&self, addr: SocketAddr) -> SocketAddr;
            pub fn current_cipher(&self) -> Option<String>;
            pub fn current_curve(&self) -> Option<String>;
            pub fn state(&self) -> State;
            pub fn activity(&self) -> ConnectionActivity;
            pub fn tick(&self) -> ConnectionResult<()>;
            pub fn authentication_expired(&self) -> ConnectionResult<bool>;

            pub fn outside_data_received(&self, buf: OutsidePacket) -> ConnectionResult<usize>;
            pub fn inside_data_received(&self, pkt: &mut BytesMut) -> ConnectionResult<()>;

            pub fn get_inside_packet_encoder(&self) -> Option<PacketEncoderType>;
        }
    }

    /// Handle an outside data error. On a fatal error will disconnect
    /// and return [`std::ops::ControlFlow::Break`], the caller should
    /// stop processing further traffic for this connection (closing
    /// the underlying stream if needed). Otherwise returns
    /// [`std::ops::ControlFlow::Continue`] and the caller continue to
    /// process future data.
    pub fn handle_outside_data_error(&self, err: &ConnectionError) -> std::ops::ControlFlow<()> {
        let fatal = err.is_fatal(self.connection_type());

        match err {
            ConnectionError::Goodbye => {
                metrics::connection_client_closed();
            }
            ConnectionError::Disconnected => {
                metrics::connection_data_after_disconnect();
            }
            ConnectionError::WolfSSL(_) => {
                metrics::connection_tls_error(fatal);
            }
            _ => {
                metrics::connection_unknown_error(fatal);
            }
        }

        if fatal {
            let _ = self.disconnect();
            std::ops::ControlFlow::Break(())
        } else {
            std::ops::ControlFlow::Continue(())
        }
    }

    pub fn begin_session_id_rotation(self: &Arc<Self>) {
        let mut conn = self.lw_conn.lock().unwrap();

        // A rotation is already in flight, nothing to be done this time.
        if conn.pending_session_id().is_some() {
            return;
        }

        let new_session = match conn.rotate_session_id() {
            Ok(s) => s,
            Err(err) => {
                warn!(?err, "Failed to start session id rotation");
                return;
            }
        };

        self.manager.begin_session_id_rotation(self, new_session);
    }

    pub fn finalize_session_id_rotation(self: &Arc<Self>, old: SessionId, new: SessionId) {
        self.manager.finalize_session_id_rotation(self, old, new)
    }

    pub fn flush_ingress_pkt_accumulator(self: &Arc<Self>) -> ConnectionResult<()> {
        let mut conn = self.lw_conn.lock().unwrap();

        if conn.state() != State::Online {
            return Ok(());
        }

        conn.flush_pkts_to_outside()
    }

    pub fn get_internal_ip(self: &Arc<Self>) -> Option<Ipv4Addr> {
        self.lw_conn.lock().unwrap().app_state().internal_ip
    }

    // Use this only during shutdown, after clearing all connections from
    // connection_manager
    pub fn lw_disconnect(self: Arc<Self>) -> ConnectionResult<()> {
        self.lw_conn.lock().unwrap().disconnect()
    }

    // This api should be idempotent since it can be called from multiple places
    // when there is failures
    pub fn disconnect(&self) -> ConnectionResult<()> {
        self.manager.remove_connection(self);
        self.lw_conn.lock().unwrap().disconnect()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        trace!("Dropping Connection!");
        metrics::connection_closed();
    }
}
