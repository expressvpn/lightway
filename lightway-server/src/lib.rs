mod connection;
mod connection_manager;
mod io;
mod ip_manager;
pub mod metrics;
mod statistics;

#[cfg(target_os = "linux")]
use bytes::Buf;
use bytesize::ByteSize;
use connection::Connection;
// re-export so server app does not need to depend on lightway-core
pub use crate::connection_manager::DEFAULT_CONNECTION_AGE_EXPIRATION_INTERVAL;
pub use crate::statistics::DEFAULT_STATISTICS_REPORTING_INTERVAL;
#[cfg(feature = "debug")]
pub use lightway_core::enable_tls_debug;
pub use lightway_core::{
    ConnectionType, DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL, Event, ExpresslaneCbType,
    ExpresslaneMetricsType, PluginFactoryError, PluginFactoryList, ServerAuth, ServerAuthHandle,
    ServerAuthResult, SessionId, Version,
};

/// Callback type for receiving per-connection events with session ID.
/// Implement this to handle events like session rotation and disconnection.
pub type ServerEventCbType = Arc<dyn Fn(SessionId, &Event) + Send + Sync>;

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
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
use tracing::info;

pub use crate::connection::ConnectionState;
pub use crate::io::inside::{InsideIO, InsideIORecv};

use crate::ip_manager::IpManager;

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

    /// Server IP to send in network_config message
    pub lightway_server_ip: Ipv4Addr,

    /// Client IP to send in network_config message
    pub lightway_client_ip: Ipv4Addr,

    /// DNS IP to send in network_config message
    pub lightway_dns_ip: Ipv4Addr,

    /// Boolean flag to select actual client ip assigned or above static ip
    /// in network_config message
    pub use_dynamic_client_ip: bool,

    /// Enable Expresslane for Udp connections
    pub enable_expresslane: bool,

    /// Interval between Expresslane key rotations
    pub expresslane_keys_rotation_interval: Duration,

    /// Callback for expresslane key updates
    #[educe(Debug(ignore))]
    pub expresslane_cb: Option<ExpresslaneCbType<ConnectionState>>,

    /// External metrics provider for expresslane packet stats,
    /// supplied when packet processing happens outside the lightway runtime.
    #[educe(Debug(ignore))]
    pub expresslane_metrics: Option<ExpresslaneMetricsType>,

    /// Optional callback to receive per-connection events with session ID.
    /// Called for every event (state changes, session rotation, etc.).
    #[educe(Debug(ignore))]
    pub event_cb: Option<ServerEventCbType>,

    /// Enable Post Quantum Crypto
    pub enable_pqc: bool,

    /// Enable TUN offload (GRO/GSO) for batch packet processing
    #[cfg(target_os = "linux")]
    pub enable_tun_offload: bool,

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

    /// How often to check for connections to expire aged connections
    pub connection_age_expiration_interval: Duration,

    /// Interval between session statistics reports
    pub statistics_reporting_interval: Duration,

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

async fn inside_io_loop_default(
    inside_io: Arc<dyn InsideIO>,
    ip_manager: Arc<IpManager<Arc<Connection>>>,
    lightway_client_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    let mtu = inside_io.mtu();
    let mut buf = BytesMut::with_capacity(mtu);
    loop {
        buf.clear();
        buf.resize(mtu, 0);
        match inside_io.recv_buf(&mut buf).await {
            IOCallbackResult::Ok(_n) => {}
            IOCallbackResult::WouldBlock => continue,
            IOCallbackResult::Err(err) => {
                break Err(anyhow!(err).context("InsideIO recv buf error"));
            }
        };

        let packet = Ipv4Packet::new(buf.as_ref());
        let Some(packet) = packet else {
            eprintln!("Invalid inside packet size (less than Ipv4 header)!");
            continue;
        };
        let conn = ip_manager.find_connection(packet.get_destination());

        ipv4_update_destination(buf.as_mut(), lightway_client_ip);

        if let Some(conn) = conn {
            let result = conn.inside_data_received(&mut buf);
            handle_inside_io_error(conn, result);
        } else {
            metrics::tun_rejected_packet_no_connection();
        }
    }
}

#[cfg(target_os = "linux")]
async fn inside_io_loop_gso(
    inside_io: Arc<dyn InsideIO>,
    ip_manager: Arc<IpManager<Arc<Connection>>>,
    lightway_client_ip: Ipv4Addr,
) -> anyhow::Result<()> {
    use lightway_core::gso::{
        VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, VIRTIO_NET_HDR_LEN, VirtioNetHdr,
        gso_none_checksum,
    };

    // Receive buffer reused across iterations. Allocate once and
    // recv directly into it (no per-packet `BytesMut::from(&...)`
    // copy + alloc).
    //
    // Mental model: `BytesMut` is a (ptr, len, cap) *window* into a
    // backing slab. `cap` is the distance from `ptr` to the end of
    // the slab — NOT the slab size. Every `advance(N)` below slides
    // `ptr += N` and shrinks `cap -= N`; the slab itself doesn't
    // change. Without intervention, the window crawls toward the
    // end of the slab and `cap` decays.
    //
    // `pkt.reserve(initial_cap)` below is the "slide back" call: if
    // the window can already hold `initial_cap` more bytes after
    // `len`, it's a free no-op; otherwise BytesMut compacts the
    // window back to the start of the slab (with `len = 0` after
    // `clear()`, this is just a pointer reset — no memcpy).
    let initial_cap = VIRTIO_NET_HDR_LEN + 65535;
    let mut pkt = bytes::BytesMut::zeroed(initial_cap);

    loop {
        // Reset the window to start of slab (cheap; no-op while still
        // at slab start, pointer-only reset after `advance()` has
        // drifted us).
        pkt.reserve(initial_cap);

        // Expose the full slab to `recv_gso` as `&mut [u8]`.
        // SAFETY: every byte of the slab was zero-initialized at
        // construction; subsequent iters only ever shrunk `len` or
        // overwrote bytes. We never hand out uninitialized memory.
        #[allow(unsafe_code)]
        unsafe {
            pkt.set_len(pkt.capacity());
        }

        let len = match inside_io.recv_gso(pkt.as_mut()).await {
            IOCallbackResult::Ok(n) => n,
            IOCallbackResult::WouldBlock => continue,
            IOCallbackResult::Err(err) => {
                break Err(anyhow!(err).context("InsideIO recv gso error"));
            }
        };

        // SAFETY: `recv_gso` wrote `len` bytes; `len ≤ pkt.capacity()`.
        #[allow(unsafe_code)]
        unsafe {
            pkt.set_len(len);
        }

        if len <= VIRTIO_NET_HDR_LEN {
            tracing::warn!("TUN read too short ({len} <= {VIRTIO_NET_HDR_LEN})");
            pkt.clear();
            continue;
        }

        let hdr = match VirtioNetHdr::from_bytes(&pkt[..VIRTIO_NET_HDR_LEN]) {
            Ok(hdr) => *hdr,
            Err(err) => {
                tracing::warn!("Failed to decode virtio header: {err}");
                pkt.clear();
                continue;
            }
        };
        // Strip the virtio header — `pkt` is now the IP payload.
        pkt.advance(VIRTIO_NET_HDR_LEN);

        if hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            gso_none_checksum(pkt.as_mut(), hdr.csum_start, hdr.csum_offset);
        }

        let packet = Ipv4Packet::new(pkt.as_ref());
        let Some(packet) = packet else {
            pkt.clear();
            continue;
        };
        let conn = ip_manager.find_connection(packet.get_destination());

        ipv4_update_destination(pkt.as_mut(), lightway_client_ip);

        if let Some(conn) = conn {
            let result = if hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE {
                conn.inside_data_received(&mut pkt)
            } else {
                conn.inside_data_received_gso(&mut pkt, &hdr)
            };
            handle_inside_io_error(conn, result);
        } else {
            metrics::tun_rejected_packet_no_connection();
        }

        pkt.clear();
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
            #[cfg(target_os = "linux")]
            if config.enable_tun_offload {
                config.tun_config.offload = true;
            }
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
    .with_key_update_interval(config.key_update_interval)
    .when(config.enable_expresslane, |b| {
        b.with_expresslane(config.expresslane_keys_rotation_interval)
    })
    .when(config.expresslane_cb.is_some(), |b| {
        b.with_expresslane_cb(config.expresslane_cb.clone().unwrap())
    })
    .when(config.expresslane_metrics.is_some(), |b| {
        b.with_expresslane_metrics(config.expresslane_metrics.clone().unwrap())
    })
    .try_when(config.enable_pqc, |b| b.with_pq_crypto())?
    .with_inside_plugins(config.inside_plugins)
    .with_outside_plugins(config.outside_plugins)
    .build()?;

    let conn_manager = ConnectionManager::new(
        ctx,
        config.inside_pkt_codec,
        config.event_cb,
        config.connection_age_expiration_interval,
    );

    tokio::spawn(statistics::run(
        conn_manager.clone(),
        ip_manager.clone(),
        config.statistics_reporting_interval,
    ));

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

    let inside_io_loop: JoinHandle<anyhow::Result<()>> = {
        #[cfg(target_os = "linux")]
        if config.enable_tun_offload {
            tokio::spawn(inside_io_loop_gso(
                inside_io,
                ip_manager.clone(),
                config.lightway_client_ip,
            ))
        } else {
            tokio::spawn(inside_io_loop_default(
                inside_io,
                ip_manager.clone(),
                config.lightway_client_ip,
            ))
        }
        #[cfg(not(target_os = "linux"))]
        tokio::spawn(inside_io_loop_default(
            inside_io,
            ip_manager.clone(),
            config.lightway_client_ip,
        ))
    };

    let (ctrlc_tx, ctrlc_rx) = tokio::sync::oneshot::channel();

    #[cfg(unix)]
    {
        tokio::spawn(async move {
            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("Failed to register SIGINT handler");
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
            let _ = ctrlc_tx.send(());
        });
    }

    #[cfg(windows)]
    {
        let mut ctrlc_tx = Some(ctrlc_tx);
        ctrlc::set_handler(move || {
            if let Some(Err(err)) = ctrlc_tx.take().map(|tx| tx.send(())) {
                tracing::warn!("Failed to send Ctrl-C signal: {err:?}");
            }
        })?;
    }

    tokio::select! {
        err = server.run() => err.context("Outside IO loop exited"),
        io = inside_io_loop => io.map_err(|e| anyhow!(e).context("Inside IO loop panicked"))?.context("Inside IO loop exited"),
        _ = ctrlc_rx => {
            info!("Sigterm or Sigint received");
            conn_manager.shutdown();
            Ok(())
        }
    }
}
