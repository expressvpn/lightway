mod connection;
mod connection_manager;
mod io;
mod ip_manager;
mod metrics;
mod statistics;

use bytesize::ByteSize;
// re-export so server app does not need to depend on lightway-core
#[cfg(feature = "debug")]
pub use lightway_core::enable_tls_debug;
pub use lightway_core::{
    ConnectionType, PluginFactoryError, PluginFactoryList, ServerAuth, ServerAuthHandle,
    ServerAuthResult, Version,
};

use anyhow::{anyhow, Context, Result};
use ipnet::Ipv4Net;
use lightway_app_utils::{connection_ticker_cb, TunConfig};
use lightway_core::{AuthMethod, BuilderPredicates, InsideIpConfig, Secret, ServerContextBuilder};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::{info, warn};

use crate::ip_manager::IpManager;

use connection_manager::ConnectionManager;

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

    /// IO-uring submission queue count
    pub iouring_entry_count: usize,

    /// IO-uring sqpoll idle time.
    pub iouring_sqpoll_idle_time: Duration,

    /// Number of concurrent TUN device read requests to issue to
    /// IO-uring. Setting this too large may negatively impact
    /// performance.
    pub iouring_tun_rx_count: u32,

    /// Configure TUN in blocking mode.
    pub iouring_tun_blocking: bool,

    /// Number of concurrent UDP socket recvmsg requests to issue to
    /// IO-uring.
    pub iouring_udp_rx_count: u32,

    /// Maximum number of concurrent UDP + TUN sendmsg/write requests
    /// to issue to IO-uring.
    pub iouring_tx_count: u32,

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

    /// Enable PROXY protocol support (TCP only)
    pub proxy_protocol: bool,

    /// UDP Buffer size for the server
    pub udp_buffer_size: ByteSize,

    /// TCP Buffer size for the server
    pub tcp_buffer_size: ByteSize,
}

impl<SA: for<'a> ServerAuth<AuthState<'a>> + Sync + Send + 'static> ServerConfig<SA> {
    fn validate(&self) -> Result<()> {
        let mut required_uring_slots =
            self.iouring_tun_rx_count as usize + self.iouring_tx_count as usize + 1; // cancellation request

        required_uring_slots += match self.connection_type {
            // this should be 2 * max connections, but max connections
            // is unknown, assume at least 1.
            ConnectionType::Stream => 2,
            ConnectionType::Datagram => self.iouring_udp_rx_count as usize,
        };

        if self.iouring_entry_count < required_uring_slots {
            return Err(anyhow!(
                "iouring_entry_count too small {} < {}",
                self.iouring_entry_count,
                required_uring_slots
            ));
        }

        Ok(())
    }
}

pub async fn server<SA: for<'a> ServerAuth<AuthState<'a>> + Sync + Send + 'static>(
    config: ServerConfig<SA>,
) -> Result<()> {
    config.validate()?;

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

    let tx_queue = Arc::new(Mutex::new(io::TxQueue::new(config.iouring_tx_count)));

    let tun = io::inside::Tun::new(
        config.iouring_tun_rx_count,
        config.iouring_tun_blocking,
        config.tun_config,
        config.lightway_client_ip,
        ip_manager.clone(),
        tx_queue.clone(),
    )?;

    let ctx = ServerContextBuilder::new(
        connection_type,
        server_cert,
        server_key,
        auth,
        ip_manager.clone(),
        tun.inside_io_sender(),
    )?
    .with_schedule_tick_cb(connection_ticker_cb)
    .with_key_update_interval(config.key_update_interval)
    .try_when(config.enable_pqc, |b| b.with_pq_crypto())?
    .with_inside_plugins(config.inside_plugins)
    .with_outside_plugins(config.outside_plugins)
    .build()?;

    let conn_manager = ConnectionManager::new(ctx);

    tokio::spawn(statistics::run(conn_manager.clone(), ip_manager.clone()));

    let server = match connection_type {
        ConnectionType::Datagram => io::OutsideIoSource::Udp(
            io::outside::UdpServer::new(
                config.iouring_udp_rx_count,
                conn_manager.clone(),
                tx_queue.clone(),
                config.bind_address,
                config.udp_buffer_size,
            )
            .await?,
        ),
        ConnectionType::Stream => io::OutsideIoSource::Tcp(
            io::outside::TcpServer::new(
                conn_manager.clone(),
                tx_queue.clone(),
                config.bind_address,
                config.proxy_protocol,
                config.tcp_buffer_size,
            )
            .await?,
        ),
    };

    // On exit dropping _io_handle will cause EPIPE to be delivered to
    // io_cancel. This causes the corresponding read request on the
    // ring to complete and signal the loop should exit.
    let (_io_handle, io_cancel) = tokio::net::unix::pipe::pipe()?;
    let io_cancel = io_cancel.into_blocking_fd()?;
    let io_task = tokio::task::spawn_blocking(move || {
        let io_loop = io::Loop::new(
            config.iouring_entry_count,
            config.iouring_sqpoll_idle_time,
            tx_queue,
            server,
            tun,
        )?;
        io_loop.run(io_cancel)
    });

    let (ctrlc_tx, ctrlc_rx) = tokio::sync::oneshot::channel();
    let mut ctrlc_tx = Some(ctrlc_tx);
    ctrlc::set_handler(move || {
        if let Some(Err(err)) = ctrlc_tx.take().map(|tx| tx.send(())) {
            warn!("Failed to send Ctrl-C signal: {err:?}");
        }
    })?;

    tokio::select! {
        r = io_task => r?.context("IO task exited"),
        _ = ctrlc_rx => {
            info!("Sigterm or Sigint received");
            conn_manager.close_all_connections();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_case::test_case;

    struct Auth;

    impl ServerAuth<AuthState<'_>> for Auth {}

    #[test_case(ConnectionType::Stream, 0, 0, 0, 0 => panics "iouring_entry_count too small")]
    #[test_case(ConnectionType::Stream, 3, 0, 0, 0 => ())]
    #[test_case(ConnectionType::Stream, 20, 5, 0, 13 => panics "iouring_entry_count too small")]
    #[test_case(ConnectionType::Stream, 21, 5, 0, 13 => ())]
    #[test_case(ConnectionType::Stream, 22, 5, 0, 13 => ())]
    #[test_case(ConnectionType::Stream, 7, 1, 10_000, 3 => ())] // udp rx count irrelevant for stream
    #[test_case(ConnectionType::Datagram, 0, 0, 0, 0 => panics "iouring_entry_count too small")]
    #[test_case(ConnectionType::Datagram, 1, 0, 0, 0 => ())]
    #[test_case(ConnectionType::Datagram, 25, 5, 7, 13 => panics "iouring_entry_count too small")]
    #[test_case(ConnectionType::Datagram, 26, 5, 7, 13 => ())]
    #[test_case(ConnectionType::Datagram, 27, 5, 7, 13 => ())]
    fn validate_iouring_entry_count(
        connection_type: ConnectionType,
        iouring_entry_count: usize,
        iouring_tun_rx_count: u32,
        iouring_udp_rx_count: u32,
        iouring_tx_count: u32,
    ) {
        let config = ServerConfig {
            connection_type,
            auth: Auth,
            server_cert: "".into(),
            server_key: "".into(),
            tun_config: Default::default(),
            ip_pool: "10.0.0.0/8".parse().unwrap(),
            ip_map: Default::default(),
            tun_ip: None,
            lightway_server_ip: "1.1.1.1".parse().unwrap(),
            lightway_client_ip: "2.2.2.2".parse().unwrap(),
            lightway_dns_ip: "3.3.3.3".parse().unwrap(),
            enable_pqc: false,
            iouring_entry_count,
            iouring_sqpoll_idle_time: Default::default(),
            iouring_tun_rx_count,
            iouring_tun_blocking: false,
            iouring_udp_rx_count,
            iouring_tx_count,
            key_update_interval: Default::default(),
            inside_plugins: Default::default(),
            outside_plugins: Default::default(),
            bind_address: "0.0.0.0:0".parse().unwrap(),
            proxy_protocol: false,
            udp_buffer_size: Default::default(),
            tcp_buffer_size: Default::default(),
        };
        config.validate().unwrap();
    }
}
