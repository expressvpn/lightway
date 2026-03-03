mod debug;
#[cfg(desktop)]
pub mod dns_manager;
pub mod io;
pub mod keepalive;
pub mod platform;
#[cfg(desktop)]
pub mod route_manager;
mod wolfssl;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub use io::inside::{InsideIO, InsideIORecv};
use lightway_app_utils::args::Cipher;
use lightway_app_utils::{
    ConnectionTicker, ConnectionTickerState, PacketCodecFactoryType, TunConfig,
};
use lightway_core::{ClientIpConfig, InsideIpConfig};

use tokio::sync::{mpsc, oneshot};
pub use wolfssl::{
    AuthMethod, ClientConnection, ClientConnectionMode, MAX_INSIDE_MTU, MAX_OUTSIDE_MTU,
    PluginFactoryError, PluginFactoryList, RootCertificate, Version, WolfsslClientTransport,
    client, connect, encoding_request_task, handle_decoded_pkt_send, handle_encoded_pkt_send,
    inside_io_task, outside_io_task,
};
#[cfg(feature = "debug")]
pub use wolfssl::{enable_tls_debug, set_logging_callback};

pub use lightway_core::EventCallback;

#[cfg(desktop)]
use crate::dns_manager::DnsConfigMode;
#[cfg(desktop)]
use crate::route_manager::RouteMode;

#[derive(Debug)]
pub enum ClientResult {
    UserDisconnect,
    NetworkChange,
}

pub struct ClientIpConfigCb;

impl<ExtAppState: Send + Sync> ClientIpConfig<ConnectionState<ExtAppState>> for ClientIpConfigCb {
    fn ip_config(&self, state: &mut ConnectionState<ExtAppState>, ip_config: InsideIpConfig) {
        tracing::debug!("Got IP from server: {ip_config:?}");
        state.ip_config = Some(ip_config);
    }
}

pub struct ConnectionState<ExtAppState: Send + Sync = ()> {
    /// Handler for tick callbacks.
    pub ticker: ConnectionTicker,
    /// InsideIpConfig received from server
    pub ip_config: Option<InsideIpConfig>,
    /// Other extended state
    pub extended: ExtAppState,
}

impl<ExtAppState: Send + Sync> ConnectionTickerState for ConnectionState<ExtAppState> {
    fn connection_ticker(&self) -> &ConnectionTicker {
        &self.ticker
    }
}

#[derive(educe::Educe)]
#[educe(Debug)]
pub struct ClientConfig<'cert, ExtAppState: Send + Sync> {
    /// Auth parameters to use for connection
    #[educe(Debug(ignore))]
    pub auth: AuthMethod,

    /// CA certificate
    #[educe(Debug(ignore))]
    pub root_ca_cert: RootCertificate<'cert>,

    /// Outside (wire) MTU
    pub outside_mtu: usize,

    /// Alternate Inside IO to use
    /// When this is supplied, tun_config will not be used for creating tun interface
    #[educe(Debug(ignore))]
    pub inside_io: Option<Arc<dyn InsideIO<ExtAppState>>>,

    /// Tun device to use
    pub tun_config: TunConfig,

    /// Local IP to use in Tun device
    pub tun_local_ip: Ipv4Addr,

    /// Peer IP to use in Tun device
    pub tun_peer_ip: Ipv4Addr,

    /// DNS IP to use in Tun device
    pub tun_dns_ip: Ipv4Addr,

    /// Interval between keepalives
    pub keepalive_interval: Duration,

    /// Keepalive timeout
    pub keepalive_timeout: Duration,

    /// Enable Expresslane for Udp connections
    pub enable_expresslane: bool,

    /// Inside packet codec's config
    pub inside_pkt_codec_config: Option<ClientInsidePacketCodecConfig>,

    /// Specifies if the program responds to INT/TERM signals
    #[educe(Debug(ignore))]
    pub stop_signal: oneshot::Receiver<()>,

    /// Signal for notifying a network change event
    /// network change being defined as a change in
    /// wifi networks or a change of network interfaces
    #[educe(Debug(ignore))]
    pub network_change_signal: Option<mpsc::Receiver<()>>,

    /// Route Mode
    #[cfg(desktop)]
    pub route_mode: RouteMode,

    /// DNS configuration mode
    #[cfg(desktop)]
    pub dns_config_mode: DnsConfigMode,

    /// Signal for Lightway to notify the index of the best connection when it is selected
    #[educe(Debug(ignore))]
    pub best_connection_selected_signal: Option<oneshot::Sender<usize>>,

    /// Transport-specific configuration
    pub transport: ClientTransport,
}

#[derive(educe::Educe)]
#[educe(Debug)]
pub struct ClientConnectionConfig<EventHandler: 'static + Send + EventCallback> {
    /// Connection mode
    pub mode: ClientConnectionMode,

    /// Cipher to use for encryption
    pub cipher: Cipher,

    /// Server domain name to validate
    pub server_dn: Option<String>,

    /// Server IP address and port
    pub server: SocketAddr,

    /// Inside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub inside_plugins: PluginFactoryList,

    /// Outside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub outside_plugins: PluginFactoryList,

    /// Inside packet codec to use
    #[educe(Debug(method(debug_pkt_codec_fac)))]
    pub inside_pkt_codec: Option<PacketCodecFactoryType>,

    /// Allow injection of a custom handler for event callback
    #[educe(Debug(ignore))]
    pub event_handler: Option<EventHandler>,
}

#[derive(educe::Educe)]
#[educe(Debug)]
pub struct ClientInsidePacketCodecConfig {
    /// Enables inside packet encoding when connection is established.
    pub enable_encoding_at_connect: bool,

    /// Signal for send inside packet encoding request to the server.
    #[educe(Debug(ignore))]
    pub encoding_request_signal: tokio::sync::mpsc::Receiver<bool>,
}

/// Transport-specific configuration for a client connection.
#[derive(educe::Educe)]
#[educe(Debug)]
pub enum ClientTransport {
    Wolfssl(WolfsslClientTransport),
}

fn debug_fmt_plugin_list(
    list: &PluginFactoryList,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{} plugins", list.len())
}

fn debug_pkt_codec_fac(
    codec_fac: &Option<PacketCodecFactoryType>,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    match codec_fac {
        Some(codec_fac) => write!(f, "{}", codec_fac.get_codec_name()),
        None => write!(f, "No Codec"),
    }
}
