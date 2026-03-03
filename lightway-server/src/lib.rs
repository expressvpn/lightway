mod connection;
mod connection_manager;
mod io;
mod ip_manager;
pub mod metrics;
mod statistics;
mod wolfssl;

// re-export so server app does not need to depend on lightway-core
#[cfg(feature = "debug")]
pub use lightway_core::enable_tls_debug;
pub use lightway_core::{ConnectionType, ServerAuth, ServerAuthHandle, ServerAuthResult, Version};

use ipnet::Ipv4Net;
use lightway_app_utils::{PacketCodecFactoryType, TunConfig};
use lightway_core::{AuthMethod, ConnectionError, ConnectionResult};
#[cfg(feature = "io-uring")]
use std::time::Duration;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use connection::Connection;

pub use crate::connection::ConnectionState;
pub use crate::io::inside::{InsideIO, InsideIORecv};

pub use wolfssl::{
    PluginFactoryError, PluginFactoryList, ServerConnectionMode, ServerTransport,
    WolfsslServerTransport, server,
};

pub(crate) fn debug_fmt_plugin_list(
    list: &PluginFactoryList,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{} plugins", list.len())
}

pub(crate) fn debug_pkt_codec_fac(
    codec_fac: &Option<PacketCodecFactoryType>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    match codec_fac {
        Some(codec_fac) => write!(f, "{}", codec_fac.get_codec_name()),
        None => write!(f, "No Codec"),
    }
}

#[derive(Debug)]
pub struct AuthState<'a> {
    pub local_addr: &'a SocketAddr,
    pub peer_addr: &'a SocketAddr,
    pub internal_ip: &'a Option<Ipv4Addr>,
}

pub(crate) struct AuthAdapter<SA: for<'a> ServerAuth<AuthState<'a>>>(pub(crate) SA);

impl<SA: for<'a> ServerAuth<AuthState<'a>>> ServerAuth<connection::ConnectionState>
    for AuthAdapter<SA>
{
    fn authorize(
        &self,
        method: &AuthMethod,
        app_state: &mut connection::ConnectionState,
    ) -> ServerAuthResult {
        let mut auth_state = AuthState {
            local_addr: &app_state.local_addr,
            peer_addr: &app_state.peer_addr,
            internal_ip: &app_state.internal_ip,
        };
        let authorized = self.0.authorize(method, &mut auth_state);
        if matches!(authorized, ServerAuthResult::Denied) {
            metrics::connection_rejected_access_denied();
        }
        authorized
    }
}

#[derive(educe::Educe)]
#[educe(Debug)]
pub struct ServerConfig<SA: for<'a> ServerAuth<AuthState<'a>>> {
    /// Authentication manager
    #[educe(Debug(ignore))]
    pub auth: SA,

    /// Server certificate
    pub server_cert: PathBuf,

    /// Server key
    pub server_key: PathBuf,

    /// Tun device name to use
    #[educe(Debug(ignore))]
    pub tun_config: TunConfig,

    /// IP pool to assign clients
    pub ip_pool: Ipv4Net,

    /// The IP assigned to the Tun device. If this is within `ip_pool`
    /// then it will be reserved.
    pub tun_ip: Option<Ipv4Addr>,

    /// A map of connection IP to a subnet of `ip_pool` to use
    /// exclusively for that particular incoming IP.
    pub ip_map: HashMap<IpAddr, Ipv4Net>,

    /// Server IP to send in network_config message
    pub lightway_server_ip: Ipv4Addr,

    /// Client IP to send in network_config message
    pub lightway_client_ip: Ipv4Addr,

    /// DNS IP to send in network_config message
    pub lightway_dns_ip: Ipv4Addr,

    /// Boolean flag to select actual client ip assigned or above static ip
    /// in network_config message
    pub use_dynamic_client_ip: bool,

    /// Address to listen to
    pub bind_address: SocketAddr,

    /// Alternate Inside IO to use.
    /// When this is supplied, tun_config will not be used for creating tun interface.
    #[educe(Debug(ignore))]
    pub inside_io: Option<Arc<dyn InsideIO>>,

    #[cfg(feature = "io-uring")]
    /// Enable IO-uring interface for Tunnel
    pub enable_tun_iouring: bool,

    #[cfg(feature = "io-uring")]
    /// IO-uring submission queue count
    pub iouring_entry_count: usize,

    #[cfg(feature = "io-uring")]
    /// IO-uring sqpoll idle time.
    pub iouring_sqpoll_idle_time: Duration,

    /// Enable Expresslane for Udp connections
    pub enable_expresslane: bool,

    /// Inside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub inside_plugins: PluginFactoryList,

    /// Outside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub outside_plugins: PluginFactoryList,

    /// Inside packet codec to use
    #[educe(Debug(method(debug_pkt_codec_fac)))]
    pub inside_pkt_codec: Option<PacketCodecFactoryType>,

    /// Disable IP pool randomization (debug only)
    #[cfg(feature = "debug")]
    pub randomize_ippool: bool,

    /// Transport-specific configuration
    pub transport: ServerTransport,
}

pub(crate) fn handle_inside_io_error(conn: Arc<Connection>, result: ConnectionResult<()>) {
    match result {
        Ok(()) => {}
        Err(ConnectionError::InvalidState | ConnectionError::Disconnected) => {
            // Skip forwarding packet when offline
            metrics::tun_rejected_packet_invalid_state();
        }
        Err(ConnectionError::InvalidInsidePacket(_)) => {
            // Skip processing invalid packet
            metrics::tun_rejected_packet_invalid_inside_packet();
        }
        Err(err) => {
            let fatal = err.is_fatal(conn.connection_type());
            metrics::tun_rejected_packet_invalid_other(fatal);
            if fatal {
                tracing::info!(session = ?conn.session_id(), ?err, "Inside IO error, disconnecting");
                let _ = conn.disconnect();
            }
        }
    }
}
