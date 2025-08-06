pub mod ip_pool;
mod server_auth;

use rand::SeedableRng;
use std::sync::{Arc, Mutex};
use thiserror::Error;

use crate::{
    BuilderPredicates, Cipher, ClientConnectionBuilder, ConnectionBuilderError,
    InsideIOSendCallbackArg, OutsideIOSendCallbackArg, OutsidePacket, PluginResult,
    RootCertificate, Secret, ServerConnectionBuilder, ServerIpPoolArg, Version,
    context::ip_pool::ClientIpConfigArg,
    packet::OutsidePacketError,
    plugin::{PluginFactoryError, PluginFactoryList, PluginList},
    version::VersionRangeInclusive,
    wire,
};
pub use server_auth::{ServerAuth, ServerAuthArg, ServerAuthHandle, ServerAuthResult};

/// An error while building a [`ClientContext`] via [`ClientContextBuilder`]
/// or a [`ServerContext`] via [`ServerContextBuilder`].
#[derive(Debug, Error)]
pub enum ContextBuilderError {
    /// Inside MTU is not in MIN_INSIDE_MTU..=MAX_INSIDE_MTU
    #[error("Inside MTU {0} unsupported")]
    InvalidInsideMtu(usize),

    /// Failed to create a new ContextBuilder
    #[error("WolfSSL Error: {0}")]
    FailedNew(#[from] wolfssl::NewContextBuilderError),

    /// A WolfSSL error occurred
    #[error("WolfSSL Error: {0}")]
    WolfSSL(#[from] wolfssl::Error),

    /// Plugin factory error occurred
    #[error("PluginFactory Error: {0}")]
    PluginFactory(#[from] PluginFactoryError),

    /// Attempt to set an invalid parameter
    #[error("Invalid Parameter: {0}")]
    InvalidParameter(String),
}

type ContextBuilderResult<T> = Result<T, ContextBuilderError>;

/// The type of connection used by a Lightway context
#[derive(Debug, Clone, Copy)]
pub enum ConnectionType {
    /// Stream mode (i.e. TCP)
    Stream,
    /// Datagram mode (i.e. UDP)
    Datagram,
}

impl ConnectionType {
    /// Returns true if this is `ConnectionType::Stream`
    pub fn is_stream(&self) -> bool {
        matches!(self, Self::Stream)
    }

    /// Returns true if this is `ConnectionType::Datagram`
    pub fn is_datagram(&self) -> bool {
        matches!(self, Self::Datagram)
    }
}

#[cfg(test)]
mod test_connection_type {
    use super::ConnectionType;
    use test_case::test_case;

    #[test_case(ConnectionType::Stream => true; "stream")]
    #[test_case(ConnectionType::Datagram => false; "datagram")]
    fn is_stream(ct: ConnectionType) -> bool {
        ct.is_stream()
    }

    #[test_case(ConnectionType::Stream => false; "stream")]
    #[test_case(ConnectionType::Datagram => true; "datagram")]
    fn is_datagram(ct: ConnectionType) -> bool {
        ct.is_datagram()
    }
}

/// Tick type
pub enum TickType {
    /// Ticks for connection management
    ConnectionTick,
    /// Ticks for inside packet codec
    PktCodecTick(u64),
}

/// Type of the application provided method to schedule a call to
/// [`crate::Connection::tick`] after an interval. When this method is
/// called by lightway the application should arrange to call
/// [`crate::Connection::tick`] after `d` has elapsed. There is no
/// requirement to cancel any other pending callback.
///
/// Take care if calling [`crate::Connection`] methods from within the
/// callback to avoid deadlock with any application lock you have
/// wrapped the connection in.
pub type ScheduleTickCb<AppState> =
    fn(d: std::time::Duration, state: &mut AppState, tick_type: TickType);

/// The core Lightway Client-side context.
pub struct ClientContext<AppState> {
    pub(crate) wolfssl: wolfssl::Context,
    pub(crate) connection_type: ConnectionType,
    pub(crate) inside_io: Option<InsideIOSendCallbackArg<AppState>>,
    pub(crate) schedule_tick_cb: ScheduleTickCb<AppState>,
    pub(crate) ip_config: ClientIpConfigArg<AppState>,
    pub(crate) inside_plugins: Arc<PluginFactoryList>,
    pub(crate) outside_plugins: Arc<PluginFactoryList>,
}

impl<AppState: Send + 'static> ClientContext<AppState> {
    /// Start connecting to a server, creating a
    /// [`ClientConnectionBuilder`].
    pub fn start_connect(
        self,
        outside_io: OutsideIOSendCallbackArg,
        outside_mtu: usize,
    ) -> Result<ClientConnectionBuilder<AppState>, ContextError> {
        Ok(ClientConnectionBuilder::new(self, outside_io, outside_mtu)?)
    }
}

/// Builder for a client side instance of [`ClientContext`].
pub struct ClientContextBuilder<AppState> {
    wolfssl: wolfssl::ContextBuilder,
    connection_type: ConnectionType,
    inside_io: Option<InsideIOSendCallbackArg<AppState>>,
    schedule_tick_cb: ScheduleTickCb<AppState>,
    ip_config: ClientIpConfigArg<AppState>,
    inside_plugins: Arc<PluginFactoryList>,
    outside_plugins: Arc<PluginFactoryList>,
}

impl<AppState> ClientContextBuilder<AppState> {
    /// Create a new builder
    pub fn new(
        connection_type: ConnectionType,
        root_ca: RootCertificate,
        inside_io: Option<InsideIOSendCallbackArg<AppState>>,
        ip_config: ClientIpConfigArg<AppState>,
        schedule_tick_cb: ScheduleTickCb<AppState>,
    ) -> ContextBuilderResult<Self> {
        let protocol = match connection_type {
            ConnectionType::Stream => wolfssl::Method::TlsClientV1_3,
            ConnectionType::Datagram => wolfssl::Method::DtlsClientV1_3,
        };

        let wolfssl = wolfssl::ContextBuilder::new(protocol)?
            .with_root_certificate(root_ca)?
            .with_cipher_list(Cipher::default().as_cipher_list(connection_type))?;

        Ok(Self {
            wolfssl,
            connection_type,
            inside_io,
            schedule_tick_cb,
            ip_config,
            inside_plugins: Arc::new(PluginFactoryList::default()),
            outside_plugins: Arc::new(PluginFactoryList::default()),
        })
    }

    /// Sets the inside plugins list which should be used for Lightway connection.
    /// See [`PluginFactoryList`].
    pub fn with_inside_plugins(self, inside_plugins: PluginFactoryList) -> Self {
        Self {
            inside_plugins: Arc::new(inside_plugins),
            ..self
        }
    }

    /// Sets the outside plugins list which should be used for Lightway connection.
    /// See [`PluginFactoryList`].
    pub fn with_outside_plugins(self, outside_plugins: PluginFactoryList) -> Self {
        Self {
            outside_plugins: Arc::new(outside_plugins),
            ..self
        }
    }

    /// Sets the cipher which should be used for Lightway connection.
    /// See [`Cipher`].
    pub fn with_cipher(self, cipher: Cipher) -> ContextBuilderResult<Self> {
        let wolfssl = self
            .wolfssl
            .with_cipher_list(cipher.as_cipher_list(self.connection_type))?;
        Ok(Self { wolfssl, ..self })
    }

    /// Finalize the builder, creating a [`ClientContext`].
    pub fn build(self) -> ClientContext<AppState> {
        let wolfssl = self.wolfssl.build();
        ClientContext {
            wolfssl,
            connection_type: self.connection_type,
            inside_io: self.inside_io,
            schedule_tick_cb: self.schedule_tick_cb,
            ip_config: self.ip_config,
            inside_plugins: self.inside_plugins,
            outside_plugins: self.outside_plugins,
        }
    }
}

impl<AppState> BuilderPredicates for ClientContextBuilder<AppState> {
    type Error = ContextBuilderError;
}

/// An error while accessing a [`ClientContext`] or a [`ServerContext`]
#[derive(Debug, Error)]
pub enum ContextError {
    /// Plugin return error or drop
    #[error("Plugin error: {0}")]
    PluginError(#[from] PluginResult),

    /// Plugin factory error occurred
    #[error("PluginFactory Error: {0}")]
    PluginFactory(#[from] PluginFactoryError),

    /// Connection builder error occurred
    #[error("ConnectionBuilderError Error: {0}")]
    ConnectionBuilder(#[from] ConnectionBuilderError),

    /// A wire protocol error occurred
    #[error("Wire protocol Error: {0}")]
    WireError(#[from] wire::FromWireError),

    /// Packet parsing error occurred
    #[error("Packet Error: {0}")]
    PacketError(#[from] OutsidePacketError),
}

/// The core Lightway Server-side context.
pub struct ServerContext<AppState = ()> {
    pub(crate) wolfssl: wolfssl::Context,
    pub(crate) connection_type: ConnectionType,
    pub(crate) schedule_tick_cb: ScheduleTickCb<AppState>,
    pub(crate) inside_io: InsideIOSendCallbackArg<AppState>,
    pub(crate) auth: ServerAuthArg<AppState>,
    pub(crate) ip_pool: ServerIpPoolArg<AppState>,
    pub(crate) supported_protocol_versions: VersionRangeInclusive,
    pub(crate) key_update_interval: std::time::Duration,
    pub(crate) rng: Arc<Mutex<dyn rand_core::CryptoRng + Send>>,
    pub(crate) inside_plugins: PluginFactoryList,
    pub(crate) outside_plugins: PluginFactoryList,
    pub(crate) outside_plugins_instance: PluginList,
}

impl<AppState: Send + 'static> ServerContext<AppState> {
    /// Predicate returning whether `v` is a supported `Version`
    pub fn is_supported_version(&self, v: Version) -> bool {
        self.supported_protocol_versions.contains(v)
    }

    /// Predicate returning whether `v` is the latest  `Version`
    pub fn is_latest_version(&self, v: Version) -> bool {
        self.supported_protocol_versions.maximum() == v
    }

    /// Parse raw `OutsidePacket::Wire` to `TcpFrame` or `UdpFrame`
    ///
    /// Usage:
    /// Normally application does not need to parse the `OutsidePacket::Wire` frame
    /// and can call `Connection::outside_data_received` directly.
    /// But in case, application need to retrieve `Header` from `UdpFrame`, it can
    /// call this function to run the plugin chain and then parse the header.
    pub fn parse_raw_outside_packet<'pkt>(
        &self,
        pkt: OutsidePacket<'pkt>,
    ) -> Result<OutsidePacket<'pkt>, ContextError> {
        Ok(pkt.apply_ingress_chain(&self.outside_plugins_instance)?)
    }

    /// Start accepting a server connection, creating a
    /// [`ServerConnectionBuilder`].
    pub fn start_accept(
        &self,
        protocol_version: Version,
        outside_io: OutsideIOSendCallbackArg,
    ) -> Result<ServerConnectionBuilder<'_, AppState>, ContextError> {
        Ok(ServerConnectionBuilder::new(
            self,
            protocol_version,
            outside_io,
        )?)
    }
}

/// Builder for a server side instance of [`ServerContext`].
pub struct ServerContextBuilder<AppState> {
    wolfssl: wolfssl::ContextBuilder,
    connection_type: ConnectionType,
    schedule_tick_cb: ScheduleTickCb<AppState>,
    inside_io: InsideIOSendCallbackArg<AppState>,
    auth: ServerAuthArg<AppState>,
    ip_pool: ServerIpPoolArg<AppState>,
    supported_protocol_versions: VersionRangeInclusive,
    key_update_interval: std::time::Duration,
    inside_plugins: PluginFactoryList,
    outside_plugins: PluginFactoryList,
}

/// server curves when PQC is not enabled, in decreasing order of preference.
const SERVER_CURVE_BASE_GROUPS: &[wolfssl::CurveGroup] = &[
    wolfssl::CurveGroup::EccSecp256R1,
    wolfssl::CurveGroup::EccX25519,
];

/// server curves when PQC is enabled, in decreasing order of preference.
#[cfg(feature = "postquantum")]
const SERVER_CURVE_PQC_GROUPS: &[wolfssl::CurveGroup] = &[
    #[cfg(not(feature = "kyber_only"))]
    wolfssl::CurveGroup::P521MLKEM1024,
    wolfssl::CurveGroup::P521KyberLevel5,
    #[cfg(not(feature = "kyber_only"))]
    wolfssl::CurveGroup::P256MLKEM512,
    wolfssl::CurveGroup::P256KyberLevel1,
    wolfssl::CurveGroup::EccSecp256R1,
    wolfssl::CurveGroup::EccX25519,
];

impl<AppState> ServerContextBuilder<AppState> {
    /// Create a new builder
    pub fn new(
        connection_type: ConnectionType,
        server_cert: Secret,
        server_key: Secret,
        auth: ServerAuthArg<AppState>,
        ip_pool: ServerIpPoolArg<AppState>,
        inside_io: InsideIOSendCallbackArg<AppState>,
        schedule_tick_cb: ScheduleTickCb<AppState>,
    ) -> ContextBuilderResult<Self> {
        let protocol = match connection_type {
            ConnectionType::Stream => wolfssl::Method::TlsServerV1_3,
            // `wolfssl::Method::DtlsServer` supports both DTLS 1.2 and 1.3
            ConnectionType::Datagram => wolfssl::Method::DtlsServer,
        };

        let cipher_list = match connection_type {
            ConnectionType::Stream => "TLS13-AES256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256",
            ConnectionType::Datagram => {
                "TLS13-CHACHA20-POLY1305-SHA256:ECDHE-RSA-CHACHA20-POLY1305:TLS13-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
            }
        };

        let wolfssl = wolfssl::ContextBuilder::new(protocol)?
            .with_private_key(server_key)?
            .with_certificate(server_cert)?
            .with_groups(SERVER_CURVE_BASE_GROUPS)?
            .with_cipher_list(cipher_list)?;

        Ok(Self {
            wolfssl,
            connection_type,
            auth,
            ip_pool,
            inside_io,
            schedule_tick_cb,
            supported_protocol_versions: VersionRangeInclusive::all(),
            key_update_interval: std::time::Duration::ZERO,
            inside_plugins: PluginFactoryList::default(),
            outside_plugins: PluginFactoryList::default(),
        })
    }

    /// Sets the inside plugins list which should be used for Lightway connection.
    /// See [`PluginFactoryList`].
    pub fn with_inside_plugins(self, list: PluginFactoryList) -> Self {
        Self {
            inside_plugins: list,
            ..self
        }
    }

    /// Sets the outside plugins list which should be used for Lightway connection.
    /// See [`PluginFactoryList`].
    pub fn with_outside_plugins(self, list: PluginFactoryList) -> Self {
        Self {
            outside_plugins: list,
            ..self
        }
    }

    /// Sets the minimum protocol version to be supported by this
    /// server context
    pub fn with_minimum_protocol_version(self, v: Version) -> ContextBuilderResult<Self> {
        Ok(Self {
            supported_protocol_versions: self
                .supported_protocol_versions
                .set_minimum(v)
                .map_err(ContextBuilderError::InvalidParameter)?,
            ..self
        })
    }

    /// Sets the maximum protocol version to be supported by this
    /// server context
    pub fn with_maximum_protocol_version(self, v: Version) -> ContextBuilderResult<Self> {
        Ok(Self {
            supported_protocol_versions: self
                .supported_protocol_versions
                .set_maximum(v)
                .map_err(ContextBuilderError::InvalidParameter)?,
            ..self
        })
    }

    /// Sets the key update interval for DTLS/TLS 1.3 connections
    pub fn with_key_update_interval(self, key_update_interval: std::time::Duration) -> Self {
        Self {
            key_update_interval,
            ..self
        }
    }

    /// Enable Post Quantum Crypto
    #[cfg(feature = "postquantum")]
    pub fn with_pq_crypto(self) -> ContextBuilderResult<Self> {
        Ok(Self {
            wolfssl: self.wolfssl.with_groups(SERVER_CURVE_PQC_GROUPS)?,
            ..self
        })
    }

    /// Finalize the builder, creating a [`ServerContext`].
    pub fn build(self) -> ContextBuilderResult<ServerContext<AppState>> {
        debug_assert!(self.supported_protocol_versions.valid());
        let outside_plugins_instance = self.outside_plugins.build()?;

        let wolfssl = self.wolfssl.build();
        Ok(ServerContext {
            wolfssl,
            connection_type: self.connection_type,
            auth: self.auth,
            ip_pool: self.ip_pool,
            inside_io: self.inside_io,
            key_update_interval: self.key_update_interval,
            rng: Arc::new(Mutex::new(rand::rngs::StdRng::from_os_rng())),
            schedule_tick_cb: self.schedule_tick_cb,
            supported_protocol_versions: self.supported_protocol_versions,
            inside_plugins: self.inside_plugins,
            outside_plugins: self.outside_plugins,
            outside_plugins_instance,
        })
    }
}

impl<AppState> BuilderPredicates for ServerContextBuilder<AppState> {
    type Error = ContextBuilderError;
}
