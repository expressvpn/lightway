use crate::error::LightwayError;
pub(crate) mod tracing_utils;

use std::sync::{Arc, OnceLock};
use tracing::info;

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
    logger_callback: Arc<dyn tracing_utils::Logger>,
) -> Result<(), LightwayError> {
    std::panic::set_hook(Box::new(tracing_panic::panic_hook));
    tracing_utils::set_global_default_subscriber(logger_callback).map_err(|e| e.into())
}

#[derive(uniffi::Object)]
struct VpnConnection {
    /// Timestamp when this connection object was created
    created_at: u64,
    /// To indicate the index of the connection in the list of connections
    connected_index: Arc<OnceLock<usize>>,
    /// Default guard of tracing subscriber to override the global default subscriber
    _default_guard: Option<tracing_core::dispatcher::DefaultGuard>,
}

#[uniffi::export]
impl VpnConnection {
    #[uniffi::constructor]
    fn new(logger_callback: Option<Arc<dyn crate::mobile::tracing_utils::Logger>>) -> Self {
        let default_guard =
            logger_callback.map(crate::mobile::tracing_utils::set_default_guard_subscriber);
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("System time before UNIX epoch")
            .as_secs();

        info!(created_at, "initializing VpnConnection");

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
        endpoints: Vec<crate::config::MobileConnectionConfig>,
        event_handler: Arc<dyn crate::event_handlers::EventHandlers>,
        raw_tun_fd: i32,
        mobile_config: crate::config::MobileConfig,
    ) -> Result<crate::ClientResult, LightwayError> {
        info!("start parallel Lightway connections");
        let mut config = crate::config::Config::default();
        config.apply_mobile_config(mobile_config);

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
        config.apply_mobile_connect_configs(endpoints);
        let servers = config.take_servers()?;
        let config =
            config.into_client_config(raw_tun_fd, event_handler, self.connected_index.clone());

        let mut builder = tokio::runtime::Builder::new_current_thread();
        builder
            .enable_all()
            .build()
            .unwrap()
            .block_on(crate::client(config, servers))
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

    fn notify_network_changed(
        &self,
        state: crate::state::DeviceNetworkState,
    ) -> Result<(), LightwayError> {
        info!("device had a network change: {:?}", state);
        Ok(())
    }
}

impl Drop for VpnConnection {
    fn drop(&mut self) {
        info!(created_at = self.created_at, "dropping VpnConnection");
    }
}
