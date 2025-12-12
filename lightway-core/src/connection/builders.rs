use std::{num::NonZeroU16, sync::Arc};

use bytes::{Bytes, BytesMut};
use rand::Rng;
use thiserror::Error;

#[cfg(feature = "debug")]
use wolfssl::Tls13SecretCallbacksArg;

use crate::{
    AuthMethod, BuilderPredicates, ClientContext, Connection, ConnectionType, MAX_OUTSIDE_MTU,
    MIN_OUTSIDE_MTU, OutsideIOSendCallbackArg, PacketDecoderType, PacketEncoderType, ServerContext,
    ServerIpPoolArg, Version,
    connection::{EventCallbackArg, dplpmtud, fragment_map::FragmentMap, key_update},
    context::ServerAuthArg,
    max_dtls_outside_mtu,
    plugin::PluginFactoryError,
    wire::SessionId,
};

use super::{ConnectionError, ConnectionMode, NewConnectionArgs, PluginList};

/// An error while building a [`Connection`] via [`ClientConnectionBuilder`]
/// or [`ServerConnectionBuilder`].
#[derive(Debug, Error)]
pub enum ConnectionBuilderError {
    /// No auth method was provided for client connection.
    #[error("An Auth method is required")]
    AuthRequired,
    /// Protocol version
    #[error("Connection uses unsupported protocol version {0}")]
    UnsupportedProtocolVersion(Version),
    /// Invalid Outside MTU
    #[error("Unsupported Outside MTU: {0}")]
    UnsupportedOutsideMtu(usize),
    /// Failed to create a new Session
    #[error("WolfSSL Error: {0}")]
    FailedNew(#[from] wolfssl::NewSessionError),
    /// Plugin factory error occurred
    #[error("PluginFactory Error: {0}")]
    PluginFactory(#[from] PluginFactoryError),
    /// Failed to connect the stream
    #[error("Connection Error: {0}")]
    FailedConnect(#[from] ConnectionError),
}

type ConnectionBuilderResult<T> = Result<T, ConnectionBuilderError>;

/// Builder for a client  [`Connection`].
pub struct ClientConnectionBuilder<AppState> {
    connection_type: ConnectionType,
    ctx: ClientContext<AppState>,
    outside_mtu: usize,
    pmtud_base_mtu: Option<u16>,
    auth_method: Option<AuthMethod>,
    session_config: wolfssl::SessionConfig<super::WolfSSLIOAdapter>,
    event_cb: Option<EventCallbackArg>,
    max_fragment_map_entries: NonZeroU16,
    pmtud_timer: Option<dplpmtud::TimerArg<AppState>>,
    outside_plugins: Arc<PluginList>,
    inside_pkt_codec: Option<(PacketEncoderType, PacketDecoderType)>,
}

impl<AppState: Send + 'static> ClientConnectionBuilder<AppState> {
    /// Create a new client connection builder
    pub(crate) fn new(
        ctx: ClientContext<AppState>,
        outside_io: OutsideIOSendCallbackArg,
        outside_mtu: usize,
    ) -> ConnectionBuilderResult<Self> {
        if !(MIN_OUTSIDE_MTU..=MAX_OUTSIDE_MTU).contains(&outside_mtu) {
            return Err(ConnectionBuilderError::UnsupportedOutsideMtu(outside_mtu));
        }

        let connection_type = ctx.connection_type;
        let outside_plugins = ctx.outside_plugins.build()?;
        let outside_plugins = Arc::new(outside_plugins);

        let io = super::WolfSSLIOAdapter {
            connection_type,
            protocol_version: if ctx.expresslane {
                Version::MAXIMUM
            } else {
                Version::try_new(1, 2).unwrap()
            },
            aggressive_send: connection_type.is_datagram(),
            outside_mtu,
            recv_buf: BytesMut::new(),
            send_buf: super::IOAdapterSendBuffer::new(outside_mtu),
            io: outside_io,
            session_id: SessionId::EMPTY,
            outside_plugins: outside_plugins.clone(),
        };
        let session_config =
            wolfssl::SessionConfig::new(io).when(connection_type.is_datagram(), |s| {
                s.with_dtls_mtu(max_dtls_outside_mtu(outside_mtu) as u16)
                    .with_dtls_nonblocking(true)
            });

        Ok(Self {
            connection_type,
            ctx,
            outside_mtu,
            session_config,
            auth_method: None,
            event_cb: None,
            max_fragment_map_entries: FragmentMap::DEFAULT_MAX_ENTRIES,
            pmtud_timer: None,
            pmtud_base_mtu: None,
            outside_plugins,
            inside_pkt_codec: None,
        })
    }

    /// Setup authentication using the given method
    pub fn with_auth(self, auth_method: AuthMethod) -> Self {
        Self {
            auth_method: Some(auth_method),
            ..self
        }
    }

    /// Setup authentication using a username and password
    pub fn with_auth_user_password(self, user: &str, password: &str) -> Self {
        let auth_method = AuthMethod::UserPass {
            user: user.to_string(),
            password: password.to_string(),
        };

        self.with_auth(auth_method)
    }

    /// Setup authentication using a token
    pub fn with_auth_token(self, token: &str) -> Self {
        let auth_method = AuthMethod::Token {
            token: token.to_string(),
        };

        self.with_auth(auth_method)
    }

    /// Setup authentication using the callback method
    pub fn with_auth_cb_data(self, data: Bytes) -> Self {
        let auth_method = AuthMethod::CustomCallback { data };

        self.with_auth(auth_method)
    }

    /// Sets the callback to notify events
    pub fn with_event_cb(self, event_cb: EventCallbackArg) -> Self {
        Self {
            event_cb: Some(event_cb),
            ..self
        }
    }

    /// Enables TLS1.3 key logging
    #[cfg(feature = "debug")]
    pub fn with_key_logger(self, keylog: Tls13SecretCallbacksArg) -> Self {
        Self {
            session_config: self.session_config.with_key_logger(keylog),
            ..self
        }
    }

    /// Enable server domain name validation
    pub fn with_server_domain_name_validation(self, server_dn: String) -> Self {
        Self {
            session_config: self.session_config.with_checked_domain_name(&server_dn),
            ..self
        }
    }

    /// Enable Post Quantum Crypto
    #[cfg(feature = "postquantum")]
    pub fn with_pq_crypto(self) -> Self {
        #[cfg(not(feature = "kyber_only"))]
        let curve = wolfssl::CurveGroup::P521MLKEM1024;
        #[cfg(feature = "kyber_only")]
        let curve = wolfssl::CurveGroup::P521KyberLevel5;

        Self {
            session_config: self.session_config.with_keyshare_group(curve),
            ..self
        }
    }

    /// Sets SNI header of the session
    pub fn with_sni_header(self, server_hostname: &str) -> Self {
        Self {
            session_config: self.session_config.with_sni(server_hostname),
            ..self
        }
    }

    /// Sets the maximum number of in-progress fragmented packets to support.
    pub fn with_fragment_map_entries(self, max_fragment_map_entries: NonZeroU16) -> Self {
        Self {
            max_fragment_map_entries,
            ..self
        }
    }

    /// Sets the timer to use for PMTU discovery ([`ConnectionType::Datagram`] only)
    pub fn with_pmtud_timer(self, timer: dplpmtud::TimerArg<AppState>) -> Self {
        Self {
            pmtud_timer: Some(timer),
            ..self
        }
    }

    /// Sets the Inside Packet Codec which should be used for Lightway connection.
    /// See [`PacketEncoderType`] and [`PacketDecoderType`].
    pub fn with_inside_pkt_codec(
        self,
        inside_pkt_codec: Option<(PacketEncoderType, PacketDecoderType)>,
    ) -> Self {
        Self {
            inside_pkt_codec,
            ..self
        }
    }

    /// Sets the base mtu to use for PMTU discovery ([`ConnectionType::Datagram`] only)
    pub fn with_pmtud_base_mtu(self, mtu: u16) -> Self {
        Self {
            pmtud_base_mtu: Some(mtu),
            ..self
        }
    }

    /// Finalize the builder to create a [`Connection`] and begin the connection process.
    pub fn connect(self, app_state: AppState) -> ConnectionBuilderResult<Connection<AppState>> {
        let auth_method = self
            .auth_method
            .ok_or(ConnectionBuilderError::AuthRequired)?;

        let session = self.ctx.wolfssl.new_session(self.session_config)?;

        tracing::info!("New Connection");

        let protocol_version = if self.ctx.expresslane {
            Version::MAXIMUM
        } else {
            Version::try_new(1, 2).unwrap()
        };

        Ok(Connection::new(NewConnectionArgs {
            app_state,
            connection_type: self.connection_type,
            protocol_version,
            outside_mtu: self.outside_mtu,
            session,
            session_id: SessionId::EMPTY,
            mode: ConnectionMode::Client {
                auth_method,
                ip_config_cb: self.ctx.ip_config,
            },
            rng: self.ctx.rng.clone(),
            inside_io: self.ctx.inside_io,
            schedule_tick_cb: self.ctx.schedule_tick_cb,
            event_cb: self.event_cb,
            inside_plugins: self.ctx.inside_plugins.build()?,
            outside_plugins: self.outside_plugins,
            max_fragment_map_entries: self.max_fragment_map_entries,
            pmtud_timer: self.pmtud_timer,
            pmtud_base_mtu: self.pmtud_base_mtu,
            inside_pkt_codec: self.inside_pkt_codec,
            expresslane: self.ctx.expresslane,
            expresslane_cb: self.ctx.expresslane_cb.clone(),
        })?)
    }
}

impl<AppState> BuilderPredicates for ClientConnectionBuilder<AppState> {
    type Error = ConnectionBuilderError;
}

/// Builder for a server  [`Connection`].
pub struct ServerConnectionBuilder<'a, AppState> {
    connection_type: ConnectionType,
    protocol_version: Version,
    ctx: &'a ServerContext<AppState>,
    auth: ServerAuthArg<AppState>,
    ip_pool: ServerIpPoolArg<AppState>,
    session_config: wolfssl::SessionConfig<super::WolfSSLIOAdapter>,
    session_id: SessionId,
    event_cb: Option<EventCallbackArg>,
    max_fragment_map_entries: NonZeroU16,
    outside_plugins: Arc<PluginList>,
    inside_pkt_codec: Option<(PacketEncoderType, PacketDecoderType)>,
}

impl<'a, AppState: Send + 'static> ServerConnectionBuilder<'a, AppState> {
    /// Create a new server connection builder
    pub(crate) fn new(
        ctx: &'a ServerContext<AppState>,
        protocol_version: Version,
        outside_io: OutsideIOSendCallbackArg,
    ) -> ConnectionBuilderResult<Self> {
        let connection_type = ctx.connection_type;
        let auth = ctx.auth.clone();
        let ip_pool = ctx.ip_pool.clone();

        let session_id = ctx.rng.lock().unwrap().random();

        let outside_mtu = MAX_OUTSIDE_MTU;
        let outside_plugins = ctx.outside_plugins.build()?;
        let outside_plugins = Arc::new(outside_plugins);

        let io = super::WolfSSLIOAdapter {
            connection_type,
            protocol_version,
            aggressive_send: false,
            outside_mtu,
            recv_buf: BytesMut::new(),
            send_buf: super::IOAdapterSendBuffer::new(outside_mtu),
            io: outside_io,
            session_id,
            outside_plugins: outside_plugins.clone(),
        };
        let session_config =
            wolfssl::SessionConfig::new(io).when(connection_type.is_datagram(), |s| {
                s.with_dtls_mtu(max_dtls_outside_mtu(outside_mtu) as u16)
                    .with_dtls_nonblocking(true)
                    .with_dtls13_allow_ch_frag(true)
            });

        Ok(Self {
            connection_type,
            protocol_version,
            ctx,
            session_config,
            session_id,
            auth,
            ip_pool,
            event_cb: None,
            max_fragment_map_entries: FragmentMap::DEFAULT_MAX_ENTRIES,
            outside_plugins,
            inside_pkt_codec: None,
        })
    }

    /// Sets the callback to notify events
    pub fn with_event_cb(self, event_cb: EventCallbackArg) -> Self {
        Self {
            event_cb: Some(event_cb),
            ..self
        }
    }

    /// Sets the maximum number of in-progress fragmented packets to support.
    pub fn with_fragment_map_entries(self, max_fragment_map_entries: NonZeroU16) -> Self {
        Self {
            max_fragment_map_entries,
            ..self
        }
    }

    /// Sets the Inside Packet Codec which should be used for Lightway connection.
    /// See [`PacketEncoderType`] and [`PacketDecoderType`].
    pub fn with_inside_pkt_codec(
        self,
        inside_pkt_codec: Option<(PacketEncoderType, PacketDecoderType)>,
    ) -> Self {
        Self {
            inside_pkt_codec,
            ..self
        }
    }

    /// Finalize the builder to accept [`Connection`] and begin the connection process.
    pub fn accept(self, app_state: AppState) -> ConnectionBuilderResult<Connection<AppState>> {
        if !self.ctx.is_supported_version(self.protocol_version) {
            return Err(ConnectionBuilderError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }

        let session = self.ctx.wolfssl.new_session(self.session_config)?;

        Ok(Connection::new(NewConnectionArgs {
            app_state,
            connection_type: self.connection_type,
            protocol_version: self.protocol_version,
            session,
            session_id: self.session_id,
            mode: ConnectionMode::Server {
                auth: self.auth,
                auth_handle: None,
                ip_pool: self.ip_pool,
                key_update: key_update::State::new(self.ctx.key_update_interval),
                pending_session_id: None,
            },
            rng: self.ctx.rng.clone(),
            outside_mtu: MAX_OUTSIDE_MTU,
            inside_io: Some(self.ctx.inside_io.clone()),
            schedule_tick_cb: self.ctx.schedule_tick_cb,
            event_cb: self.event_cb,
            inside_plugins: self.ctx.inside_plugins.build()?,
            outside_plugins: self.outside_plugins,
            max_fragment_map_entries: self.max_fragment_map_entries,
            pmtud_timer: None,
            pmtud_base_mtu: None,
            inside_pkt_codec: self.inside_pkt_codec,
            expresslane: self.ctx.expresslane,
            expresslane_cb: self.ctx.expresslane_cb.clone(),
        })?)
    }
}

impl<AppState> BuilderPredicates for ServerConnectionBuilder<'_, AppState> {
    type Error = ConnectionBuilderError;
}
