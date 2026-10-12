use std::{num::NonZeroU16, sync::Arc};

use bytes::Bytes;
use rand::distr::{Distribution, StandardUniform};
use thiserror::Error;

use crate::{
    AuthMethod, BuilderPredicates, ClientContext, ClientTransportArgs, Connection, KeyShare,
    MAX_OUTSIDE_MTU, MIN_OUTSIDE_MTU, OutsideIOSendCallbackArg, PacketDecoderType,
    PacketEncoderType, ServerContext, ServerIpPoolArg, ServerTransportBuilder, TransportArgs,
    TransportError, Version,
    connection::{EventCallbackArg, dplpmtud, fragment_map::FragmentMap, key_update},
    context::ServerAuthArg,
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
    /// Failed to build the transport
    #[error("Transport Error: {0}")]
    Transport(#[from] TransportError),
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
    ctx: ClientContext<AppState>,
    outside_io: OutsideIOSendCallbackArg,
    outside_mtu: usize,
    pmtud_base_mtu: Option<u16>,
    auth_method: Option<AuthMethod>,
    client: ClientTransportArgs,
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

        let outside_plugins = ctx.outside_plugins.build()?;
        let outside_plugins = Arc::new(outside_plugins);

        Ok(Self {
            ctx,
            outside_io,
            outside_mtu,
            auth_method: None,
            client: ClientTransportArgs::default(),
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

    /// Setup authentication using a token. The client's maximum
    /// supported lightway protocol [`Version`] is sent alongside the
    /// token via [`AuthMethod::VersionedToken`] so the server can
    /// determine the client's version even on transports without a
    /// wire header (e.g. TCP).
    pub fn with_auth_token(self, token: &str) -> Self {
        self.with_auth_versioned_token(token, Version::MAXIMUM)
    }

    /// Setup authentication using a token plus an explicit lightway
    /// protocol [`Version`]. Prefer [`Self::with_auth_token`] which
    /// auto-fills the client's maximum supported version.
    pub fn with_auth_versioned_token(self, token: &str, version: Version) -> Self {
        let auth_method = AuthMethod::VersionedToken {
            version,
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

    /// Enable server domain name validation
    pub fn with_server_domain_name_validation(mut self, server_dn: &str) -> Self {
        self.client.domain_name = Some(server_dn.to_string());
        self
    }

    /// Offer `keyshare` in the first ClientHello. On BoringSSL the group
    /// must also be enabled with
    /// [`crate::TlsClientFactoryBuilder::enable_pq_crypto`].
    pub fn with_pq_crypto(mut self, keyshare: KeyShare) -> Self {
        self.client.key_share = Some(crate::tls::KeyShareOffer::Group(keyshare.as_curve_group()));
        self
    }

    /// Send the first ClientHello without a key share.
    pub fn with_no_key_shares(mut self) -> Self {
        self.client.key_share = Some(crate::tls::KeyShareOffer::Empty);
        self
    }

    /// Sets SNI header of the session
    pub fn with_sni_header(mut self, server_hostname: &str) -> Self {
        self.client.sni = Some(server_hostname.to_string());
        self
    }

    /// Sets the maximum number of in-progress fragmented packets to support.
    pub fn with_fragment_map_entries(self, max_fragment_map_entries: NonZeroU16) -> Self {
        Self {
            max_fragment_map_entries,
            ..self
        }
    }

    /// Sets the timer to use for PMTU discovery (lossy transports only)
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

    /// Sets the base mtu to use for PMTU discovery (lossy transports only)
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

        let protocol_version = Version::MAXIMUM;

        let transport = self.ctx.transport.connect(
            TransportArgs {
                outside_io: self.outside_io,
                outside_mtu: self.outside_mtu,
                protocol_version,
                session_id: SessionId::EMPTY,
                outside_plugins: self.outside_plugins.clone(),
            },
            self.client,
        )?;

        tracing::info!("New Connection");

        Ok(Connection::new(NewConnectionArgs {
            app_state,
            protocol_version,
            outside_mtu: self.outside_mtu,
            transport,
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
            expresslane_metrics: self.ctx.expresslane_metrics.clone(),
            expresslane_keys_rotation_interval: self.ctx.expresslane_keys_rotation_interval,
        })?)
    }
}

impl<AppState> BuilderPredicates for ClientConnectionBuilder<AppState> {
    type Error = ConnectionBuilderError;
}

/// Builder for a server  [`Connection`].
pub struct ServerConnectionBuilder<'a, AppState> {
    protocol_version: Version,
    ctx: &'a ServerContext<AppState>,
    auth: ServerAuthArg<AppState>,
    ip_pool: ServerIpPoolArg<AppState>,
    outside_io: OutsideIOSendCallbackArg,
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
        let auth = ctx.auth.clone();
        let ip_pool = ctx.ip_pool.clone();

        let session_id = StandardUniform.sample(&mut *ctx.rng.lock().unwrap());

        let outside_plugins = ctx.outside_plugins.build()?;
        let outside_plugins = Arc::new(outside_plugins);

        Ok(Self {
            protocol_version,
            ctx,
            outside_io,
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
    pub fn accept(
        self,
        app_state: AppState,
        transport: ServerTransportBuilder<'_>,
    ) -> ConnectionBuilderResult<Connection<AppState>> {
        if !self.ctx.is_supported_version(self.protocol_version) {
            return Err(ConnectionBuilderError::UnsupportedProtocolVersion(
                self.protocol_version,
            ));
        }

        let transport = transport(TransportArgs {
            outside_io: self.outside_io,
            outside_mtu: MAX_OUTSIDE_MTU,
            protocol_version: self.protocol_version,
            session_id: self.session_id,
            outside_plugins: self.outside_plugins.clone(),
        })?;

        Ok(Connection::new(NewConnectionArgs {
            app_state,
            protocol_version: self.protocol_version,
            transport,
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
            expresslane_metrics: self.ctx.expresslane_metrics.clone(),
            expresslane_keys_rotation_interval: self.ctx.expresslane_keys_rotation_interval,
        })?)
    }
}

impl<AppState> BuilderPredicates for ServerConnectionBuilder<'_, AppState> {
    type Error = ConnectionBuilderError;
}
