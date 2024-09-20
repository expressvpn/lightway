mod connection;
mod connection_manager;
mod io;
mod ip_manager;
mod metrics;
mod statistics;

// re-export so server app does not need to depend on lightway-core
#[cfg(feature = "debug")]
pub use lightway_core::enable_tls_debug;
pub use lightway_core::{
    PluginFactoryError, PluginFactoryList, ServerAuth, ServerAuthHandle, ServerAuthResult, Version,
};

use anyhow::{anyhow, Context, Result};
use ipnet::Ipv4Net;
use lightway_app_utils::{connection_ticker_cb, TunConfig};
use lightway_core::{
    ipv4_update_destination, AuthMethod, BuilderPredicates, ConnectionError, ConnectionType,
    IOCallbackResult, InsideIpConfig, Secret, ServerContextBuilder,
};
use pnet::packet::ipv4::Ipv4Packet;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::io::inside::InsideIO;
use crate::ip_manager::IpManager;

use connection_manager::ConnectionManager;
use io::outside::Server;

fn debug_fmt_plugin_list(
    list: &PluginFactoryList,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{} plugins", list.len())
}

pub struct AuthState<'a> {
    pub local_addr: &'a SocketAddr,
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
            local_addr: &mut app_state.local_addr,
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
    /// Connection mode
    pub connection_type: ConnectionType,

    /// Authentication manager
    #[educe(Debug(ignore))]
    pub auth: SA,

    /// Server certificate
    pub server_cert: PathBuf,

    /// Server key
    pub server_key: PathBuf,

    /// Tun device name to use
    pub tun_config: TunConfig,

    /// IP pool to assign clients
    pub ip_pool: Ipv4Net,

    /// A map of connection IP to a subnet of `ip_pool` to use
    /// exclusively for that particular incoming IP.
    pub ip_map: HashMap<IpAddr, Ipv4Net>,

    /// The IP assigned to the Tun device. If this is within `ip_pool`
    /// then it will be reserved.
    pub tun_ip: Option<Ipv4Addr>,

    /// Server IP to send in network_config message
    pub lightway_server_ip: Ipv4Addr,

    /// Client IP to send in network_config message
    pub lightway_client_ip: Ipv4Addr,

    /// DNS IP to send in network_config message
    pub lightway_dns_ip: Ipv4Addr,

    /// Enable Post Quantum Crypto
    pub enable_pqc: bool,

    /// Enable IO-uring interface for Tunnel
    pub enable_tun_iouring: bool,

    /// IO-uring submission queue count
    pub iouring_entry_count: usize,

    /// The key update interval for DTLS/TLS 1.3 connections
    pub key_update_interval: Duration,

    /// Inside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub inside_plugins: PluginFactoryList,

    /// Outside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub outside_plugins: PluginFactoryList,

    /// Address to listen to
    pub bind_address: SocketAddr,
}

pub async fn server<SA: for<'a> ServerAuth<AuthState<'a>> + Sync + Send + 'static>(
    config: ServerConfig<SA>,
) -> Result<()> {
    let server_key = Secret::PemFile(&config.server_key);
    let server_cert = Secret::PemFile(&config.server_cert);

    info!("Server starting with config:\n{:#?}", &config);

    if let Some(tun_ip) = config.tun_ip {
        info!("Server started with inside ip: {}", tun_ip);
    }

    let inside_ip_config = InsideIpConfig {
        client_ip: config.lightway_client_ip,
        server_ip: config.lightway_server_ip,
        dns_ip: config.lightway_dns_ip,
    };

    let reserved_ips = [config.lightway_client_ip, config.lightway_server_ip]
        .into_iter()
        .chain(config.tun_ip)
        .chain(std::iter::once(config.lightway_dns_ip));
    let ip_manager = IpManager::new(
        config.ip_pool,
        config.ip_map,
        reserved_ips,
        inside_ip_config,
    );
    let ip_manager = Arc::new(ip_manager);

    let connection_type = config.connection_type;
    let auth = Arc::new(AuthAdapter(config.auth));

    let iouring = if config.enable_tun_iouring {
        Some(config.iouring_entry_count)
    } else {
        None
    };
    let inside_io = Arc::new(io::inside::Tun::new(config.tun_config, iouring).await?);

    let ctx = ServerContextBuilder::new(
        connection_type,
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

    let conn_manager = ConnectionManager::new(ctx);

    tokio::spawn(statistics::run(conn_manager.clone(), ip_manager.clone()));

    let mut server: Box<dyn Server> = match connection_type {
        ConnectionType::Datagram => {
            Box::new(io::outside::UdpServer::new(conn_manager.clone(), config.bind_address).await?)
        }
        ConnectionType::Stream => {
            Box::new(io::outside::TcpServer::new(conn_manager.clone(), config.bind_address).await?)
        }
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
                match conn.inside_data_received(&mut buf) {
                    Ok(()) => {}
                    Err(ConnectionError::InvalidState) => {
                        // Skip forwarding packet when offline
                        metrics::tun_rejected_packet_invalid_state();
                    }
                    Err(ConnectionError::InvalidInsidePacket(_)) => {
                        // Skip processing invalid packet
                        metrics::tun_rejected_packet_invalid_inside_packet();
                    }
                    Err(err) => {
                        metrics::tun_rejected_packet_invalid_other();
                        // TODO: fatal vs non-fatal;
                        break Err(anyhow!(err).context("Inside data handling error"));
                    }
                }
            } else {
                metrics::tun_rejected_packet_no_connection();
            }
        }
    });

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
