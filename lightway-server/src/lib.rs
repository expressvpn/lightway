mod connection;
mod connection_manager;
mod io;
mod ip_manager;
pub mod metrics;
pub mod network_setup;
mod statistics;

use bytesize::ByteSize;
use connection::Connection;
// re-export so server app does not need to depend on lightway-core
#[cfg(feature = "debug")]
pub use lightway_core::enable_tls_debug;
pub use lightway_core::{
    ConnectionType, PluginFactoryError, PluginFactoryList, ServerAuth, ServerAuthHandle,
    ServerAuthResult, Version,
};

use anyhow::{Context, Result, anyhow};
use ipnet::Ipv4Net;
use lightway_app_utils::{PacketCodecFactoryType, TunConfig, connection_ticker_cb};
use lightway_core::{
    AuthMethod, BuilderPredicates, ConnectionError, ConnectionResult, IOCallbackResult,
    InsideIpConfig, Secret, ServerContextBuilder, ipv4_update_destination,
};
use pnet_packet::ipv4::Ipv4Packet;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};
use tracing::{info, warn};

pub use crate::connection::ConnectionState;
pub use crate::io::inside::{InsideIO, InsideIORecv};

use crate::{ip_manager::IpManager, network_setup::{NetworkSetup, NetworkSetupMode}};

use connection_manager::ConnectionManager;
use io::outside::Server;

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

#[derive(Debug)]
pub struct AuthState<'a> {
    pub local_addr: &'a SocketAddr,
    pub peer_addr: &'a SocketAddr,
    pub internal_ip: &'a Option<Ipv4Addr>,
}

struct AuthAdapter<SA: for<'a> ServerAuth<AuthState<'a>>>(SA);

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

/// Connection mode
///
/// Application can also attach server socket for library to use directly,
/// instead of library creating socket and binding.
/// If socket is sent from application, it must be already binded to proper address
pub enum ServerConnectionMode {
    Stream(Option<TcpListener>),
    Datagram(Option<UdpSocket>),
}

impl std::fmt::Debug for ServerConnectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(_) => f.debug_tuple("Stream").finish(),
            Self::Datagram(_) => f.debug_tuple("Datagram").finish(),
        }
    }
}

impl From<&ServerConnectionMode> for ConnectionType {
    fn from(value: &ServerConnectionMode) -> Self {
        match value {
            ServerConnectionMode::Stream(_) => ConnectionType::Stream,
            ServerConnectionMode::Datagram(_) => ConnectionType::Datagram,
        }
    }
}

#[derive(educe::Educe)]
#[educe(Debug)]
pub struct ServerConfig<SA: for<'a> ServerAuth<AuthState<'a>>> {
    /// Connection mode
    pub mode: ServerConnectionMode,

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

    /// Alternate Inside IO to use
    /// When this is supplied, tun_config
    /// will not be used for creating tun interface
    #[educe(Debug(ignore))]
    pub inside_io: Option<Arc<dyn InsideIO>>,

    /// IP pool to assign clients
    pub ip_pool: Ipv4Net,

    /// The IP assigned to the Tun device. If this is within `ip_pool`
    /// then it will be reserved.
    pub tun_ip: Option<Ipv4Addr>,

    /// A map of connection IP to a subnet of `ip_pool` to use
    /// exclusively for that particular incoming IP.
    pub ip_map: HashMap<IpAddr, Ipv4Net>,

    /// Server IP to send in network setup message
    pub lightway_server_ip: Ipv4Addr,

    /// Client IP to send in network setup message
    pub lightway_client_ip: Ipv4Addr,

    /// DNS IP to send in network setup message
    pub lightway_dns_ip: Ipv4Addr,

    /// Boolean flag to select actual client ip assigned or above static ip
    /// in network setup message
    pub use_dynamic_client_ip: bool,

    /// Enable Post Quantum Crypto
    pub enable_pqc: bool,

    #[cfg(feature = "io-uring")]
    /// Enable IO-uring interface for Tunnel
    pub enable_tun_iouring: bool,

    #[cfg(feature = "io-uring")]
    /// IO-uring submission queue count
    pub iouring_entry_count: usize,

    #[cfg(feature = "io-uring")]
    /// IO-uring sqpoll idle time.
    pub iouring_sqpoll_idle_time: Duration,

    /// The key update interval for DTLS/TLS 1.3 connections
    pub key_update_interval: Duration,

    /// Inside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub inside_plugins: PluginFactoryList,

    /// Outside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub outside_plugins: PluginFactoryList,

    /// Inside packet codec to use
    #[educe(Debug(method(debug_pkt_codec_fac)))]
    pub inside_pkt_codec: Option<PacketCodecFactoryType>,

    /// Address to listen to
    pub bind_address: SocketAddr,

    /// Enable PROXY protocol support (TCP only)
    pub proxy_protocol: bool,

    /// UDP Buffer size for the server
    pub udp_buffer_size: ByteSize,

    /// Whether to enable network setup
    pub network_setup: NetworkSetupMode,

    /// Disable IP pool randomization
    /// Should be used for debugging only
    #[cfg(feature = "debug")]
    pub randomize_ippool: bool,
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

pub async fn server<SA: for<'a> ServerAuth<AuthState<'a>> + Sync + Send + 'static>(
    mut config: ServerConfig<SA>,
) -> Result<()> {
    let server_key = Secret::PemFile(&config.server_key);
    let server_cert = Secret::PemFile(&config.server_cert);

    info!("Server starting with config:\n{:#?}", &config);

    if let Some(tun_ip) = config.tun_ip {
        info!("Server started with inside ip: {}", tun_ip);
    }

    let mut network_setup = NetworkSetup::new(
        config.network_setup,
        config.ip_pool,
        config
            .tun_config
            .tun_name
            .clone()
            .ok_or_else(|| anyhow!("Tun device name is required for network setup"))?,
    )
    .map_err(|e| anyhow!("Failed to initialize network setup: {}", e))?;

    let inside_ip_config = InsideIpConfig {
        client_ip: config.lightway_client_ip,
        server_ip: config.lightway_server_ip,
        dns_ip: config.lightway_dns_ip,
    };

    let reserved_ips = [config.lightway_client_ip, config.lightway_server_ip]
        .into_iter()
        .chain(config.tun_ip)
        .chain(std::iter::once(config.lightway_dns_ip));
    #[cfg(feature = "debug")]
    let randomize_ippool = config.randomize_ippool;
    #[cfg(not(feature = "debug"))]
    let randomize_ippool = true;

    let ip_manager = IpManager::new(
        config.ip_pool,
        config.ip_map,
        reserved_ips,
        inside_ip_config,
        config.use_dynamic_client_ip,
        randomize_ippool,
    );
    let ip_manager = Arc::new(ip_manager);

    let connection_type = config.mode;
    let auth = Arc::new(AuthAdapter(config.auth));

    let inside_io: Arc<dyn InsideIO> = match config.inside_io.take() {
        Some(io) => io,
        None => {
            use io::inside::Tun;
            #[cfg(not(feature = "io-uring"))]
            let tun = Tun::new(&config.tun_config).await;
            #[cfg(feature = "io-uring")]
            let tun = if config.enable_tun_iouring {
                Tun::new_with_iouring(
                    &config.tun_config,
                    config.iouring_entry_count,
                    config.iouring_sqpoll_idle_time,
                )
                .await
            } else {
                Tun::new(&config.tun_config).await
            };

            let tun = tun.context("Tun creation")?;

            Arc::new(tun)
        }
    };

    let ctx = ServerContextBuilder::new(
        (&connection_type).into(),
        server_cert,
        server_key,
        auth,
        ip_manager.clone(),
        inside_io.clone().into_io_send_callback(),
    )?
    .with_schedule_tick_cb(connection_ticker_cb)
    .with_key_update_interval(config.key_update_interval)
    .try_when(config.enable_pqc, |b| b.with_pq_crypto())?
    .with_inside_plugins(config.inside_plugins)
    .with_outside_plugins(config.outside_plugins)
    .build()?;

    let conn_manager = ConnectionManager::new(ctx, config.inside_pkt_codec);

    tokio::spawn(statistics::run(conn_manager.clone(), ip_manager.clone()));

    let mut server: Box<dyn Server> = match connection_type {
        ServerConnectionMode::Datagram(may_be_sock) => Box::new(
            io::outside::UdpServer::new(
                conn_manager.clone(),
                config.bind_address,
                config.udp_buffer_size,
                may_be_sock,
            )
            .await?,
        ),
        ServerConnectionMode::Stream(may_be_sock) => Box::new(
            io::outside::TcpServer::new(
                conn_manager.clone(),
                config.bind_address,
                config.proxy_protocol,
                may_be_sock,
            )
            .await?,
        ),
    };

    let inside_io_loop: JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        loop {
            let mut buf = match inside_io.recv_buf().await {
                IOCallbackResult::Ok(buf) => buf,
                IOCallbackResult::WouldBlock => continue, // Spuriously failed to read, keep waiting
                IOCallbackResult::Err(err) => {
                    break Err(anyhow!(err).context("InsideIO recv buf error"));
                }
            };

            // Find connection based on client ip (dest ip) and forward packet
            let packet = Ipv4Packet::new(buf.as_ref());
            let Some(packet) = packet else {
                eprintln!("Invalid inside packet size (less than Ipv4 header)!");
                continue;
            };
            let conn = ip_manager.find_connection(packet.get_destination());

            // Update destination IP address to client's ip
            ipv4_update_destination(buf.as_mut(), config.lightway_client_ip);

            if let Some(conn) = conn {
                let result = conn.inside_data_received(&mut buf);
                handle_inside_io_error(conn, result);
            } else {
                metrics::tun_rejected_packet_no_connection();
            }
        }
    });

    network_setup.start().await.context("Network setup")?;

    let (ctrlc_tx, ctrlc_rx) = tokio::sync::oneshot::channel();
    let mut ctrlc_tx = Some(ctrlc_tx);
    ctrlc::set_handler(move || {
        if let Some(Err(err)) = ctrlc_tx.take().map(|tx| tx.send(())) {
            warn!("Failed to send Ctrl-C signal: {err:?}");
        }
    })?;

    tokio::select! {
        err = server.run() => err.context("Outside IO loop exited"),
        io = inside_io_loop =>  io.map_err(|e| anyhow!(e).context("Inside IO loop panicked"))?.context("Inside IO loop exited"),
        _ = ctrlc_rx => {
            info!("Sigterm or Sigint received");
            conn_manager.close_all_connections();
            Ok(())
        }
    }
}
