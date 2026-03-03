use anyhow::{Context, Result, anyhow};
use bytesize::ByteSize;
use lightway_app_utils::connection_ticker_cb;
use lightway_core::{
    BuilderPredicates, ConnectionType, IOCallbackResult, InsideIpConfig, Secret, ServerAuth,
    ServerContextBuilder, ipv4_update_destination,
};
use pnet_packet::ipv4::Ipv4Packet;
use std::{sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, UdpSocket},
    task::JoinHandle,
};
use tracing::{info, warn};

pub use lightway_core::{PluginFactoryError, PluginFactoryList};

use crate::connection_manager::ConnectionManager;
use crate::io;
use crate::io::inside::InsideIO;
use crate::io::outside::Server;
use crate::ip_manager::IpManager;
use crate::metrics;
use crate::statistics;

use super::{AuthAdapter, AuthState, ServerConfig, handle_inside_io_error};

/// WolfSSL/DTLS-specific server transport configuration.
#[derive(educe::Educe)]
#[educe(Debug)]
pub struct WolfsslServerTransport {
    /// Connection mode
    pub mode: ServerConnectionMode,

    /// UDP Buffer size for the server
    pub udp_buffer_size: ByteSize,

    /// Enable Post Quantum Crypto
    pub enable_pqc: bool,

    /// The key update interval for DTLS/TLS 1.3 connections
    pub key_update_interval: Duration,

    /// Enable PROXY protocol support (TCP only)
    pub proxy_protocol: bool,
}

/// Transport-specific configuration for a server.
#[derive(educe::Educe)]
#[educe(Debug)]
pub enum ServerTransport {
    Wolfssl(WolfsslServerTransport),
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

pub async fn server<SA: for<'a> ServerAuth<AuthState<'a>> + Sync + Send + 'static>(
    config: ServerConfig<SA>,
) -> Result<()> {
    let server_key = Secret::PemFile(&config.server_key);
    let server_cert = Secret::PemFile(&config.server_cert);

    info!("Server starting with config:\n{:#?}", &config);

    #[allow(clippy::infallible_destructuring_match)]
    let wolfssl = match config.transport {
        ServerTransport::Wolfssl(w) => w,
    };

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

    let connection_type = wolfssl.mode;
    let auth = Arc::new(AuthAdapter(config.auth));

    let inside_io: Arc<dyn InsideIO> = match config.inside_io {
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
        connection_ticker_cb,
    )?
    .with_key_update_interval(wolfssl.key_update_interval)
    .when(config.enable_expresslane, |b| b.with_expresslane())
    .try_when(wolfssl.enable_pqc, |b| b.with_pq_crypto())?
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
                wolfssl.udp_buffer_size,
                may_be_sock,
            )
            .await?,
        ),
        ServerConnectionMode::Stream(may_be_sock) => Box::new(
            io::outside::TcpServer::new(
                conn_manager.clone(),
                config.bind_address,
                wolfssl.proxy_protocol,
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
