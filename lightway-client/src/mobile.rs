use crate::LightwayError;
pub(crate) mod lightway;
pub(crate) mod tracing_utils;

use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tracing::{info, warn};

#[derive(Debug, uniffi::Enum, PartialEq, Eq)]
/// Current state of Expresslane
pub enum ExpresslaneState {
    /// Expresslane not enabled in the config
    Disabled,
    /// Expresslane enabled in the config, but handshake not completed or peer has disabled Expresslane, so inactive
    Inactive,
    /// Expresslane enabled and being used in the current connection
    Active,
    /// Expresslane enabled, but connection is degraded and back to normal D/TLS for data packets
    Degraded,
}

impl TryFrom<lightway_core::ExpresslaneState> for ExpresslaneState {
    type Error = ();

    fn try_from(state: lightway_core::ExpresslaneState) -> Result<Self, Self::Error> {
        match state {
            lightway_core::ExpresslaneState::Disabled => Ok(ExpresslaneState::Disabled),
            lightway_core::ExpresslaneState::Inactive => Ok(ExpresslaneState::Inactive),
            lightway_core::ExpresslaneState::Active => Ok(ExpresslaneState::Active),
            lightway_core::ExpresslaneState::Degraded => Ok(ExpresslaneState::Degraded),
            lightway_core::ExpresslaneState::WaitingForClient => Err(()),
        }
    }
}

#[uniffi::export(with_foreign)]
#[cfg_attr(test, mockall::automock)]
pub trait RustEventHandlers: Send + Sync {
    /// Handles VPN connection status changes from the native Lightway client.
    /// State values: 2=Connecting, 6=LinkUp, 5=Authenticating, 7=Online, 4=Disconnecting, 1=Disconnected (from lightway-core)
    ///
    /// `Online` state is advertised when we have selected the best connection in parallel connect
    fn handle_status_change(&self, state: u8);

    /// Handles Expresslane state change. This will be called whenever there's a new update on
    /// the Expresslane state change, see `ExpresslaneState` enum for details.
    fn handle_expresslane_state_change(&self, state: ExpresslaneState);

    /// Called when the first packet is received from the server.
    ///
    /// It returns time in milliseconds from the connection start until the first packet is received
    fn received_first_packet(&self, time_in_ms: u64);

    /// Notify the mobile app that an outside socket has been created and pass the FD (by reference, not owned)
    fn created_outside_fd(&self, fd: i32);

    /// Notify the mobile app that connection has floated and do not need a reconnect after outside
    /// IO has been changed, which could happen when the device is online again or the device is
    /// using a different network interface (Cellular <-> WiFi). (iOS-only)
    fn connection_has_floated(&self);

    /// Handles inside pkt codec status changes from the native Lightway client. When the server
    /// agrees to enable or disable the inside packet codec (after the client requests), this
    /// handler will be called with the resulting state.
    fn handle_inside_pkt_codec_status_change(&self, enabled: bool);
}

#[uniffi::export]
fn get_lightway_client_hash() -> String {
    env!("GIT_HASH").to_string()
}

/// Get the version for WolfSSL
#[uniffi::export]
fn get_wolfssl_version() -> String {
    lightway_core::wolfssl::get_wolfssl_version_string().to_string()
}

/// Sets up a global default logging bridge between Rust and the mobile app, while
/// installing a panic hook for proper crash reporting.
/// Invoking this multiple times replaces the previously registered logger so that the latest callback is used.
/// A `LoggingBridgeError` error is returned if another global subscriber was installed externally.
#[uniffi::export]
fn initialize_rust_logging_bridge(
    logger_callback: Arc<dyn tracing_utils::RustLogger>,
) -> Result<(), LightwayError> {
    std::panic::set_hook(Box::new(tracing_panic::panic_hook));
    tracing_utils::set_global_default_subscriber(logger_callback).map_err(|e| e.into())
}

#[derive(Debug, uniffi::Enum)]
/// Current network state of the device
/// For Android, all the 3 enums (Online/InterfaceChanged/RouteUpdated) have the same behaviour
pub enum DeviceNetworkState {
    /// Device transitioned from offline to online
    /// Socket recreation is required on iOS due to potential interface changes after we have gone online
    /// for UDP connections.
    Online,
    /// Network interface changed has changed (e.g. WiFi -> Cellular)
    InterfaceChanged,
    /// Network updated, but the interface remains unchanged
    RouteUpdated,
    /// No usable route
    Offline,
}

#[derive(Debug, uniffi::Record)]
/// User settings from the mobile app
pub struct LightwayUserSettings {
    /// Enable continuous/NAT keep-alive
    pub enable_heart_beat: bool,
    /// SNI header for TLS connections
    pub sni_header: String,
    /// Defer timeout in milliseconds
    defer_timeout: i64,
    /// Enable Expresslane for UDP connections
    pub enable_expresslane: bool,
}

impl LightwayUserSettings {
    const DEFAULT_PREFERRED_CONNECTION_WAIT_INTERVAL_IN_MILLISECS: u64 = 2000;
    pub fn get_defer_timeout_duration(&self) -> Duration {
        let defer_timeout = self.defer_timeout;
        let defer_interval = u64::try_from(defer_timeout).unwrap_or_else(|_| {
            warn!("Defer timeout value {defer_timeout} is invalid. Using default value.");
            Self::DEFAULT_PREFERRED_CONNECTION_WAIT_INTERVAL_IN_MILLISECS
        });
        info!("Using defer timeout value: {defer_timeout} ms");
        Duration::from_millis(defer_interval)
    }
}

#[derive(uniffi::Object)]
struct RustVpnConnection {
    /// Timestamp when this connection object was created
    created_at: u64,
    /// To indicate the index of the connection in the list of connections
    connected_index: Arc<OnceLock<usize>>,
    /// Default guard of tracing subscriber to override the global default subscriber
    _default_guard: Option<tracing_core::dispatcher::DefaultGuard>,
}

#[uniffi::export]
impl RustVpnConnection {
    #[uniffi::constructor]
    fn new(logger_callback: Option<Arc<dyn crate::mobile::tracing_utils::RustLogger>>) -> Self {
        let default_guard =
            logger_callback.map(crate::mobile::tracing_utils::set_default_guard_subscriber);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_secs();

        info!(created_at, "initializing RustVpnConnection");

        Self {
            created_at,
            connected_index: Arc::new(OnceLock::new()),
            _default_guard: default_guard,
        }
    }

    /// Establishes parallel connections to multiple Lightway endpoints.
    ///
    /// This function coordinates the connection setup to multiple endpoints in parallel
    /// using Tokio's asynchronous runtime. It prepares the necessary configurations,
    /// processes incoming parameters, and handles the management receiver that interacts
    /// with asynchronous tasks. Critical errors during the process are mapped to
    /// `LightwayError` for proper error handling.
    fn parallel_connect(
        &self,
        endpoints: Vec<crate::endpoint::RustEndpointConfig>,
        event_handler: Arc<dyn RustEventHandlers>,
        raw_tun_fd: i32,
        user_settings: LightwayUserSettings,
    ) -> Result<crate::ClientResult, LightwayError> {
        info!("start parallel Lightway connections");

        info!("Received {} endpoints", endpoints.len());
        if endpoints.is_empty() {
            return Err(LightwayError::EmptyEndpointsError);
        }

        for endpoint in &endpoints {
            info!(
                "Endpoint {}:{} with {}",
                endpoint.server_ip,
                endpoint.port,
                if endpoint.use_tcp {
                    "lightway_tcp"
                } else {
                    "lightway_udp"
                },
            );
        }

        let mut builder = tokio::runtime::Builder::new_current_thread();
        builder
            .enable_all()
            .build()
            .unwrap()
            .block_on(lightway::async_lightway_start(
                endpoints,
                raw_tun_fd,
                event_handler,
                user_settings,
                self.connected_index.clone(),
            ))
            .map_err(|e| {
                if let Some(lightway_core::ConnectionError::Unauthorized) =
                    e.downcast_ref::<lightway_core::ConnectionError>()
                {
                    LightwayError::Unauthorized
                } else {
                    e.into()
                }
            })
    }

    fn stop_connection(&self) -> Result<(), LightwayError> {
        info!("stopping connection");
        Ok(())
    }

    // UniFFI doesn't support returning usize to Swift, so we return Option<u8>
    fn get_connection_index(&self) -> Result<Option<u8>, LightwayError> {
        info!("getting connection index");
        Ok(self.connected_index.get().map(|&i| i as u8))
    }

    fn notify_network_changed(&self, state: DeviceNetworkState) -> Result<(), LightwayError> {
        info!("device had a network change: {:?}", state);
        Ok(())
    }
}

impl Drop for RustVpnConnection {
    fn drop(&mut self) {
        info!(created_at = self.created_at, "dropping RustVpnConnection");
    }
}
