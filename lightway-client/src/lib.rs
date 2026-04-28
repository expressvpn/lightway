mod debug;
#[cfg(desktop)]
pub mod dns_manager;
pub(crate) mod endpoint;
pub mod io;
pub mod keepalive;
pub mod platform;
#[cfg(desktop)]
pub mod route_manager;

#[cfg(feature = "mobile")]
pub mod mobile;

#[cfg(feature = "mobile")]
uniffi::setup_scaffolding!();

use anyhow::{Context, Result, anyhow};
use bytes::BytesMut;
use bytesize::ByteSize;
use futures::{FutureExt, stream::FuturesUnordered};
pub use io::inside::{InsideIO, InsideIORecv};
use keepalive::Keepalive;
#[cfg(feature = "postquantum")]
use lightway_app_utils::args::KeyShare;
use lightway_app_utils::{
    ConnectionTicker, ConnectionTickerState, DplpmtudTimer, EventStream, EventStreamCallback,
    PacketCodecFactoryType, TunConfig, args::Cipher, connection_ticker_cb,
};
use lightway_core::{
    BuilderPredicates, ClientContextBuilder, ClientIpConfig, Connection, ConnectionError,
    ConnectionType, Event, EventCallback, IOCallbackResult, InsideIOSendCallbackArg,
    InsideIpConfig, OutsidePacket, State, ipv4_update_destination, ipv4_update_source,
};
use tokio::sync::mpsc::UnboundedReceiver;

#[cfg(feature = "debug")]
use crate::debug::WiresharkKeyLogger;
#[cfg(desktop)]
use crate::dns_manager::{DnsConfigMode, DnsManager, DnsManagerError, DnsSetup};
use crate::keepalive::Config as KeepaliveConfig;
#[cfg(desktop)]
use crate::route_manager::{RouteManager, RouteMode};
#[cfg(feature = "debug")]
use lightway_app_utils::wolfssl_tracing_callback;
#[cfg(batch_receive)]
use lightway_core::MAX_IO_BATCH_SIZE;
pub use lightway_core::{
    AuthMethod, MAX_INSIDE_MTU, MAX_OUTSIDE_MTU, PluginFactoryError, PluginFactoryList,
    RootCertificate, Version,
};
#[cfg(feature = "debug")]
// re-export so client app does not need to depend on lightway-core
pub use lightway_core::{enable_tls_debug, set_logging_callback};
use pnet_packet::ipv4::Ipv4Packet;
#[cfg(desktop)]
use std::net::IpAddr;
#[cfg(feature = "debug")]
use std::path::PathBuf;
use std::time::Instant;
use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_stream::{StreamExt, StreamMap};
use tracing::info;

/// Connection type
/// Applications can also attach socket for library to use directly,
/// if there is any customisations needed
pub enum ClientConnectionMode {
    Stream(Option<TcpStream>),
    Datagram(Option<UdpSocket>),
}

impl std::fmt::Debug for ClientConnectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(_) => f.debug_tuple("Stream").finish(),
            Self::Datagram(_) => f.debug_tuple("Datagram").finish(),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(feature = "mobile", derive(uniffi::Enum))]
pub enum ClientResult {
    UserDisconnect,
    NetworkChange,

    #[cfg(feature = "mobile")]
    ServerGoodbye,
}

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "mobile", derive(uniffi::Error), uniffi(flat_error))]
pub enum LightwayError {
    #[error("Connection Error: `{0}`")]
    ConnectionError(#[from] anyhow::Error),
    #[error("Received empty endpoints")]
    EmptyEndpointsError,
    #[error("User is not authorized / authentication failed")]
    Unauthorized,

    // These Endpoint Error is iOS only
    #[cfg(feature = "mobile")]
    #[error("Endpoint Error: `{0}`")]
    EndpointError(#[from] crate::endpoint::EndpointError),
    #[cfg(feature = "mobile")]
    #[error("Logging bridge initialization error: `{0}`")]
    LoggingBridgeError(#[from] crate::mobile::tracing_utils::LoggingBridgeError),
}

/// Details about an established outside connection.
/// Emitted after the best connection is selected so callers can attach
/// to the live socket without reopening it.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionInfo {
    /// The underlying socket, tagged with its transport type.
    pub socket: io::outside::OutsideSocket,
    /// Remote peer address the connection is established to.
    pub peer_addr: std::net::SocketAddr,
}

/// Information about the selected best connection, sent via `best_connection_selected_signal`.
#[derive(Debug)]
pub struct BestConnectionInfo {
    /// Index of the best connection in the original server list
    pub index: usize,
    /// Details about the established outside connection (socket type + peer).
    pub connection: ConnectionInfo,
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

    /// Key share group for post-quantum key exchange
    #[cfg(feature = "postquantum")]
    pub keyshare: KeyShare,

    /// Interval between keepalives
    pub keepalive_interval: Duration,

    /// Keepalive timeout
    pub keepalive_timeout: Duration,

    /// Time it takes to trigger a tracer packet
    /// when we haven't received an outside packet
    pub tracer_packet_timeout: Duration,

    /// Enables keepalives to be sent constantly instead
    /// of only during network change events
    pub continuous_keepalive: bool,

    /// How long to wait before selecting the preferred connection
    pub preferred_connection_wait_interval: Duration,

    /// Socket send buffer size
    pub sndbuf: ByteSize,
    /// Socket receive buffer size
    pub rcvbuf: ByteSize,

    /// Enable batch receive (`recvmsg_x` on macOS, `recvmmsg` on Linux/Android)
    #[cfg(batch_receive)]
    pub enable_batch_receive: bool,

    /// Route Mode
    #[cfg(desktop)]
    pub route_mode: RouteMode,

    /// DNS configuration mode
    #[cfg(desktop)]
    pub dns_config_mode: DnsConfigMode,

    /// Enable Expresslane for Udp connections
    pub enable_expresslane: bool,

    /// Callback for expresslane key updates
    #[educe(Debug(ignore))]
    pub expresslane_cb: Option<lightway_core::ExpresslaneCbType<ConnectionState<ExtAppState>>>,

    /// External metrics provider for expresslane packet stats,
    /// supplied when packet processing happens outside the lightway runtime.
    #[educe(Debug(ignore))]
    pub expresslane_metrics: Option<lightway_core::ExpresslaneMetricsType>,

    /// Enable PMTU discovery for Udp connections
    pub enable_pmtud: bool,

    /// Base MTU for PMTU discovery
    pub pmtud_base_mtu: Option<u16>,

    /// Enable IO-uring interface for Tunnel
    #[cfg(feature = "io-uring")]
    pub enable_tun_iouring: bool,

    /// IO-uring submission queue count. Only applicable when
    /// `enable_tun_iouring` is `true`
    // Any value more than 1024 negatively impact the throughput
    #[cfg(feature = "io-uring")]
    pub iouring_entry_count: usize,

    /// IO-uring sqpoll idle time. If non-zero use a kernel thread to
    /// perform submission queue polling. After the given idle time
    /// the thread will go to sleep.
    #[cfg(feature = "io-uring")]
    pub iouring_sqpoll_idle_time: Duration,

    /// Inside packet codec's config
    pub inside_pkt_codec_config: Option<ClientInsidePacketCodecConfig>,

    /// Signal for notifying a network change event
    /// network change being defined as a change in
    /// wifi networks or a change of network interfaces
    #[educe(Debug(ignore))]
    pub network_change_signal: Option<mpsc::Receiver<()>>,

    /// Signal for Lightway to notify about the best connection when it is selected
    #[educe(Debug(ignore))]
    pub best_connection_selected_signal: Option<oneshot::Sender<BestConnectionInfo>>,

    /// Enable WolfSsl debugging
    #[cfg(feature = "debug")]
    pub tls_debug: bool,

    /// File path to save wireshark keylog
    #[cfg(feature = "debug")]
    pub keylog: Option<PathBuf>,
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

async fn handle_events<A: 'static + Send + EventCallback, ExtAppState: Send + Sync>(
    mut stream: EventStream,
    keepalive: Keepalive,
    weak: Weak<Mutex<Connection<ConnectionState<ExtAppState>>>>,
    enable_encoding_when_online: bool,
    mut event_handler: Option<A>,
    connected_signal: oneshot::Sender<()>,
    disconnected_signal: oneshot::Sender<()>,
) {
    let mut connected_signal = Some(connected_signal);
    let mut disconnected_signal = Some(disconnected_signal);
    while let Some(event) = stream.next().await {
        match &event {
            Event::StateChanged(state) => {
                if matches!(state, State::Online) {
                    if let Some(connected_signal) = connected_signal.take() {
                        let _ = connected_signal.send(());
                    }
                    keepalive.online().await;
                    let Some(conn) = weak.upgrade() else {
                        break; // Connection disconnected.
                    };

                    if enable_encoding_when_online
                        && let Err(e) = conn.lock().unwrap().set_encoding(true)
                    {
                        tracing::error!("Error encoutered when trying to toggle encoding. {}", e);
                    }
                } else if matches!(state, State::Disconnected)
                    && let Some(disconnected_tx) = disconnected_signal.take()
                {
                    let _ = disconnected_tx.send(());
                }
            }
            Event::KeepaliveReply => keepalive.reply_received().await,
            Event::FirstPacketReceived => {
                info!("First outside packet received");
            }
            Event::ExpresslaneStateChanged(state) => {
                info!(?state, "Expresslane State Change");
            }
            Event::EncodingStateChanged { enabled } => {
                info!("Encoding state changed to {enabled}");
            }

            // Server only events
            Event::SessionIdRotationStarted { .. }
            | Event::SessionIdRotationAcknowledged { .. }
            | Event::TlsKeysUpdateStart
            | Event::TlsKeysUpdateCompleted => {
                unreachable!("server only event received");
            }
        }
        if let Some(ref mut handler) = event_handler {
            handler.event(event);
        }
    }
}

/// An async function to handle all the outside traffic
/// You can pass in an optional oneshot channel to listen to when the socket is ready to read.
pub async fn outside_io_task<ExtAppState: Send + Sync>(
    conn: Arc<Mutex<Connection<ConnectionState<ExtAppState>>>>,
    mtu: usize,
    connection_type: ConnectionType,
    outside_io: Arc<dyn io::outside::OutsideIO>,
    keepalive: Keepalive,
    mut ready_signal: Option<oneshot::Sender<()>>,
) -> Result<()> {
    #[cfg(batch_receive)]
    const BUF_COUNT: usize = MAX_IO_BATCH_SIZE;
    #[cfg(not(batch_receive))]
    const BUF_COUNT: usize = 1;

    let mut bufs: [BytesMut; BUF_COUNT] = std::array::from_fn(|_| BytesMut::with_capacity(mtu));

    loop {
        // Unrecoverable errors: https://github.com/tokio-rs/tokio/discussions/5552
        outside_io.poll(tokio::io::Interest::READABLE).await?;

        // Send ready signal after first successful poll
        if let Some(tx) = ready_signal.take() {
            let _ = tx.send(());
        }

        #[cfg(batch_receive)]
        let count = match outside_io.recv_bufs(&mut bufs) {
            IOCallbackResult::Ok(n) => n,
            IOCallbackResult::WouldBlock => continue,
            IOCallbackResult::Err(err) => return Err(err.into()),
        };

        #[cfg(not(batch_receive))]
        let count = match outside_io.recv_buf(&mut bufs[0]) {
            IOCallbackResult::Ok(_) => 1,
            IOCallbackResult::WouldBlock => continue,
            IOCallbackResult::Err(err) => return Err(err.into()),
        };

        let pkts = bufs
            .iter_mut()
            .take(count)
            .map(|b| OutsidePacket::Wire(b, connection_type));
        conn.lock()
            .unwrap()
            .multiple_outside_data_received(pkts, |err| err.is_fatal(connection_type))?;

        for b in &mut bufs[..count] {
            b.clear();
            b.reserve(mtu);
        }

        keepalive.outside_activity().await
    }
}

const DEFAULT_TRACER_TRIGGER_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn inside_io_task<ExtAppState: Send + Sync>(
    conn: Arc<Mutex<Connection<ConnectionState<ExtAppState>>>>,
    inside_io: Arc<dyn io::inside::InsideIORecv<ExtAppState>>,
    tun_dns_ip: Ipv4Addr,
    keepalive: Keepalive,
    keepalive_config: KeepaliveConfig,
) -> Result<()> {
    let tracer_trigger_timeout = if keepalive_config.continuous {
        Duration::ZERO
    } else {
        keepalive_config
            .tracer_trigger_timeout
            .unwrap_or(DEFAULT_TRACER_TRIGGER_TIMEOUT)
    };
    let mut tracer_timeout_last_outside_data_rcvd: Option<Instant> = None;
    loop {
        let mut buf = match inside_io.recv_buf().await {
            IOCallbackResult::Ok(buf) => buf,
            IOCallbackResult::WouldBlock => continue, // Spuriously failed to read, keep waiting
            IOCallbackResult::Err(err) => {
                // Fatal error
                return Err(err.into());
            }
        };

        let last_outside_data_received = {
            let mut conn = conn.lock().unwrap();

            // Update source IP address to server assigned IP address
            let ip_config = conn.app_state().ip_config;
            if let Some(ip_config) = &ip_config {
                ipv4_update_source(buf.as_mut(), ip_config.client_ip);

                // Update TUN device DNS IP address to server provided DNS address
                let packet = Ipv4Packet::new(buf.as_ref());
                if let Some(packet) = packet
                    && packet.get_destination() == tun_dns_ip
                {
                    ipv4_update_destination(buf.as_mut(), ip_config.dns_ip);
                };
            }

            match conn.inside_data_received(&mut buf) {
                Ok(()) => conn.activity().last_outside_data_received,
                Err(ConnectionError::PluginDropWithReply(reply)) => {
                    // Send the reply packet to inside path
                    let _ = inside_io.try_send(reply, ip_config);
                    continue;
                }
                Err(ConnectionError::InvalidState) => {
                    // Ignore the packet till the connection is online
                    continue;
                }
                Err(ConnectionError::InvalidInsidePacket(_)) => {
                    // Ignore invalid inside packet
                    continue;
                }
                Err(err) => {
                    // Fatal error
                    return Err(err.into());
                }
            }
        };

        let now = Instant::now();
        let duration_since_last_outside_data = now.duration_since(last_outside_data_received);

        if !tracer_trigger_timeout.is_zero()
            && duration_since_last_outside_data > tracer_trigger_timeout
            && tracer_timeout_last_outside_data_rcvd.is_none_or(|x| x != last_outside_data_received)
        {
            {
                tracer_timeout_last_outside_data_rcvd = Some(last_outside_data_received);
                keepalive.tracer_delta_exceeded().await;
            }
        }
    }
}

async fn handle_network_change<ExtAppState: Send + Sync>(
    keepalive: Keepalive,
    mut network_change_signal: mpsc::Receiver<()>,
    weak: Weak<Mutex<lightway_core::Connection<ConnectionState<ExtAppState>>>>,
) -> ClientResult {
    while (network_change_signal.recv().await).is_some() {
        let Some(conn) = weak.upgrade() else {
            return ClientResult::UserDisconnect;
        };
        let conn_type = conn.lock().unwrap().connection_type();
        match conn_type {
            ConnectionType::Datagram => {
                info!("sending keepalives due to network change ..");
                keepalive.network_changed().await;
            }
            ConnectionType::Stream => {
                info!("client shutting down due to network change ..");
                let _ = conn.lock().unwrap().disconnect();
                return ClientResult::NetworkChange;
            }
        }
    }
    ClientResult::UserDisconnect
}

pub async fn handle_encoded_pkt_send<ExtAppState: Send + Sync>(
    conn: Weak<Mutex<lightway_core::Connection<ConnectionState<ExtAppState>>>>,
    rx: Option<UnboundedReceiver<BytesMut>>,
) -> Result<()> {
    let Some(mut rx) = rx else {
        return Ok(());
    };

    loop {
        let Some(mut encoded_packet) = rx.recv().await else {
            break; // Channel is closed
        };

        let Some(conn) = conn.upgrade() else {
            break; // Client disconnected
        };

        let mut conn = conn.lock().unwrap();

        match conn.send_to_outside(&mut encoded_packet, true) {
            Ok(()) => {}
            Err(ConnectionError::InvalidState) => {
                // Ignore the packet till the connection is online
            }
            Err(ConnectionError::InvalidInsidePacket(_)) => {
                // Ignore invalid inside packet
            }
            Err(err) => {
                // Fatal error
                return Err(err.into());
            }
        }
    }

    // Ready signal channel closed.
    Ok(())
}

pub async fn handle_decoded_pkt_send<ExtAppState: Send + Sync>(
    conn: Weak<Mutex<lightway_core::Connection<ConnectionState<ExtAppState>>>>,
    rx: Option<UnboundedReceiver<BytesMut>>,
) -> Result<()> {
    let Some(mut rx) = rx else {
        return Ok(());
    };

    loop {
        let Some(decoded_packet) = rx.recv().await else {
            break; // Channel is closed
        };

        let Some(conn) = conn.upgrade() else {
            break; // Client disconnected
        };

        let mut conn = conn.lock().unwrap();

        if let Err(err) = conn.send_to_inside(decoded_packet) {
            if err.is_fatal(conn.connection_type()) {
                return Err(err.into());
            }
            tracing::error!("Failed to process outside data: {err}");
        }
    }

    // Ready signal channel closed.
    Ok(())
}

pub async fn encoding_request_task<ExtAppState: Send + Sync>(
    weak: Weak<Mutex<Connection<ConnectionState<ExtAppState>>>>,
    mut signal: tokio::sync::mpsc::Receiver<bool>,
) {
    while let Some(enable) = signal.recv().await {
        let Some(conn) = weak.upgrade() else {
            break; // Connection disconnected.
        };

        if let Err(e) = conn.lock().unwrap().set_encoding(enable) {
            tracing::error!(
                "Error encoutered when trying to send encoding request. {}",
                e
            );
        }
    }

    tracing::info!("toggle encode task has finished");
}

/// Represents a connection to a server. When dropped, the route table will be removed.
pub struct ClientConnection<T: Send + Sync> {
    task: JoinHandle<anyhow::Result<ClientResult>>,
    conn: Arc<Mutex<Connection<ConnectionState<T>>>>,
    inside_io: Arc<dyn io::inside::InsideIO<T>>,
    #[cfg(desktop)]
    outside_io: Arc<dyn io::outside::OutsideIO>,
    connected_signal: Option<oneshot::Receiver<()>>,
    stop_signal: Option<oneshot::Sender<()>>,
    network_change_signal: mpsc::Sender<()>,
    encoding_request_signal: mpsc::Sender<bool>,
    #[cfg(desktop)]
    route_manager: Option<RouteManager>,
    #[cfg(desktop)]
    dns_manager: Option<DnsManager>,
}

impl<ExtAppState: Send + Sync> ClientConnection<ExtAppState> {
    /// Returns details about the established outside connection.
    pub fn outside_connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            socket: self.outside_io.socket(),
            peer_addr: self.outside_io.peer_addr(),
        }
    }

    #[cfg(desktop)]
    pub async fn initialize_routes(
        &mut self,
        route_mode: RouteMode,
        tun_peer_ip: IpAddr,
        tun_dns_ip: IpAddr,
    ) -> Result<()> {
        let server_ip = self.outside_io.peer_addr().ip();
        let tun_index = self.inside_io.if_index()?;

        tracing::trace!(
            "Starting route manager: mode: {:?}, server: {:?}, tun_index: {:?}, tun_peer_ip: {:?}, tun_dns_ip: {:?}",
            route_mode,
            server_ip,
            tun_index,
            tun_peer_ip,
            tun_dns_ip
        );
        let mut route_manager =
            RouteManager::new(route_mode, server_ip, tun_index, tun_peer_ip, tun_dns_ip)?;
        route_manager.start().await?;

        self.route_manager = Some(route_manager);
        info!("Routes configured");
        Ok(())
    }

    #[cfg(desktop)]
    pub fn set_dns(
        &mut self,
        dns_config_mode: DnsConfigMode,
        tun_dns_ip: IpAddr,
    ) -> Result<(), DnsManagerError> {
        if dns_config_mode == DnsConfigMode::Default {
            let tun_index = self
                .inside_io
                .if_index()
                .map_err(|e| DnsManagerError::FailedToSetDnsConfig(e.to_string()))?;
            let mut dns_manager = DnsManager::new(tun_index);
            dns_manager.set_dns(tun_dns_ip)?;
            self.dns_manager = Some(dns_manager);
            info!(?dns_config_mode, %tun_dns_ip, "DNS configured");
        }
        Ok(())
    }

    pub fn set_connection_inside_io(&self) {
        let inside_io: InsideIOSendCallbackArg<ConnectionState<ExtAppState>> =
            self.inside_io.clone().into_io_send_callback();
        self.conn.lock().unwrap().inside_io(inside_io);
    }
}

#[tracing::instrument(
    level = "info",
    fields(server = server_config.server.to_string(), mode = ?server_config.mode),
    skip(
        config,
        server_config,
        inside_io,
    )
)]
pub async fn connect<
    EventHandler: 'static + Send + EventCallback,
    ExtAppState: 'static + Default + Send + Sync,
>(
    config: &ClientConfig<'_, ExtAppState>,
    mut server_config: ClientConnectionConfig<EventHandler>,
    inside_io: Arc<dyn io::inside::InsideIO<ExtAppState>>,
) -> Result<ClientConnection<ExtAppState>> {
    let mut join_set = JoinSet::new();

    let (connection_type, outside_io): (ConnectionType, Arc<dyn io::outside::OutsideIO>) =
        match server_config.mode {
            ClientConnectionMode::Datagram(maybe_sock) => {
                #[cfg_attr(not(batch_receive), allow(unused_mut))]
                let mut sock = io::outside::Udp::new(server_config.server, maybe_sock)
                    .await
                    .inspect_err(|e| tracing::error!("Failed to create outside IO UDP socket: {e}"))
                    .context("Outside IO UDP")?;

                #[cfg(batch_receive)]
                if config.enable_batch_receive {
                    sock.enable_batch_receive();
                }

                (ConnectionType::Datagram, Arc::new(sock))
            }
            ClientConnectionMode::Stream(maybe_sock) => {
                let sock = io::outside::Tcp::new(server_config.server, maybe_sock)
                    .await
                    .inspect_err(|e| tracing::error!("Failed to create outside IO TCP socket: {e}"))
                    .context("Outside IO TCP")?;
                (ConnectionType::Stream, Arc::new(sock))
            }
        };

    outside_io.set_send_buffer_size(config.sndbuf.as_u64().try_into()?)?;
    outside_io.set_recv_buffer_size(config.rcvbuf.as_u64().try_into()?)?;

    let (event_cb, event_stream) = EventStreamCallback::new();

    let (ticker, ticker_task) = ConnectionTicker::new();
    let state = ConnectionState {
        ticker,
        ip_config: None,
        extended: Default::default(),
    };
    let (pmtud_timer, pmtud_timer_task) = DplpmtudTimer::new();

    #[cfg(feature = "debug")]
    if config.tls_debug {
        set_logging_callback(Some(wolfssl_tracing_callback));
    }

    let (inside_io_codec, encoded_pkt_receiver, decoded_pkt_receiver) =
        match &server_config.inside_pkt_codec {
            Some(codec_factory) => {
                let codec = codec_factory.build();
                (
                    Some((codec.encoder, codec.decoder)),
                    Some(codec.encoded_pkt_receiver),
                    Some(codec.decoded_pkt_receiver),
                )
            }
            None => (None, None, None),
        };

    let conn_builder = ClientContextBuilder::new(
        connection_type,
        config.root_ca_cert,
        None,
        Arc::new(ClientIpConfigCb),
        connection_ticker_cb,
    )?
    .with_cipher(server_config.cipher.into())?
    .with_inside_plugins(server_config.inside_plugins)
    .with_outside_plugins(server_config.outside_plugins)
    .when(config.enable_expresslane, |b| b.with_expresslane())
    .when(config.expresslane_cb.is_some(), |b| {
        b.with_expresslane_cb(config.expresslane_cb.clone().unwrap())
    })
    .when(config.expresslane_metrics.is_some(), |b| {
        b.with_expresslane_metrics(config.expresslane_metrics.clone().unwrap())
    })
    .build()
    .start_connect(
        outside_io.clone().into_io_send_callback(),
        config.outside_mtu,
    )?
    .with_auth(config.auth.clone())
    .with_event_cb(Box::new(event_cb))
    .with_inside_pkt_codec(inside_io_codec)
    .when_some(config.pmtud_base_mtu, |b, mtu| b.with_pmtud_base_mtu(mtu))
    .when_some(server_config.server_dn, |b, sdn| {
        b.with_server_domain_name_validation(sdn)
    })
    .when(connection_type.is_datagram() && config.enable_pmtud, |b| {
        b.with_pmtud_timer(pmtud_timer)
    })
    .when(config.enable_batch_receive, |b| {
        b.with_inside_batch_enabled()
    });

    #[cfg(feature = "postquantum")]
    let conn_builder = conn_builder.with_pq_crypto(config.keyshare.into());

    #[cfg(feature = "debug")]
    let conn_builder = conn_builder.when_some(config.keylog.clone(), |b, k| {
        b.with_key_logger(WiresharkKeyLogger::new(k))
    });

    let conn = Arc::new(Mutex::new(conn_builder.connect(state)?));

    let keepalive_config = keepalive::Config {
        interval: config.keepalive_interval,
        timeout: config.keepalive_timeout,
        continuous: config.continuous_keepalive,
        tracer_trigger_timeout: Some(config.tracer_packet_timeout),
    };
    let (keepalive, keepalive_task) =
        Keepalive::new(keepalive_config.clone(), Arc::downgrade(&conn));

    let (connected_tx, connected_rx) = oneshot::channel();
    let (disconnected_tx, disconnected_rx) = oneshot::channel();

    let event_handler = server_config.event_handler.take();
    join_set.spawn(handle_events(
        event_stream,
        keepalive.clone(),
        Arc::downgrade(&conn),
        config
            .inside_pkt_codec_config
            .as_ref()
            .is_some_and(|x| x.enable_encoding_at_connect),
        event_handler,
        connected_tx,
        disconnected_tx,
    ));

    let mut ticker_task = ticker_task.spawn(Arc::downgrade(&conn));
    pmtud_timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

    let mut outside_io_loop: JoinHandle<anyhow::Result<()>> = tokio::spawn(outside_io_task(
        conn.clone(),
        config.outside_mtu,
        connection_type,
        outside_io.clone(),
        keepalive.clone(),
        None,
    ));

    let mut inside_io_loop: JoinHandle<anyhow::Result<()>> = tokio::spawn(inside_io_task(
        conn.clone(),
        inside_io.clone(),
        config.tun_dns_ip,
        keepalive.clone(),
        keepalive_config,
    ));

    let (network_change_tx, network_change_rx) = tokio::sync::mpsc::channel(1);
    let mut network_change_task = tokio::spawn(handle_network_change(
        keepalive,
        network_change_rx,
        Arc::downgrade(&conn),
    ));

    let mut encoded_pkt_send_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(
        handle_encoded_pkt_send(Arc::downgrade(&conn), encoded_pkt_receiver),
    );

    let mut decoded_pkt_send_task: JoinHandle<anyhow::Result<()>> = tokio::spawn(
        handle_decoded_pkt_send(Arc::downgrade(&conn), decoded_pkt_receiver),
    );

    let (encoding_request_tx, encoding_request_rx) = mpsc::channel(1);
    tokio::spawn(encoding_request_task(
        Arc::downgrade(&conn),
        encoding_request_rx,
    ));

    let (stop_tx, stop_rx) = oneshot::channel();

    let stop_conn = conn.clone();
    let task = tokio::spawn(async move {
        let _join_set = join_set;
        let result = tokio::select! {
            _ = stop_rx => {
                info!("client shutting down ..");
                match stop_conn.lock().unwrap().disconnect() {
                    Ok(()) => Ok(ClientResult::UserDisconnect),
                    Err(e) => Err(e.into())
                }
            },
            Some(_) = keepalive_task => Err(anyhow!("Keepalive timeout")),
            io = &mut outside_io_loop => Err(anyhow!("Outside IO loop exited: {io:?}")),
            io = &mut inside_io_loop => Err(anyhow!("Inside IO loop exited: {io:?}")),
            io = &mut encoded_pkt_send_task, if server_config.inside_pkt_codec.is_some() => Err(anyhow!("Inside IO (Encoded packet send task) exited: {io:?}")),
            io = &mut decoded_pkt_send_task, if server_config.inside_pkt_codec.is_some() => Err(anyhow!("Inside IO (Decoded packet send task) exited: {io:?}")),
            _ = &mut ticker_task => Err(anyhow!("Ticker task stopped")),
            result = &mut network_change_task => {
                match result {
                    Ok(client_result) => {
                        info!("network change task result: {client_result:?}");
                        Ok(client_result)
                    }
                    Err(e) => {
                        Err(anyhow!("network change task error: {e:?}"))
                    }
                }
            },
        };

        if result.is_ok() {
            let _ = disconnected_rx.await;
        } else {
            tracing::warn!("Connection task ended:\n{:?}", result);
        }

        outside_io_loop.abort();
        inside_io_loop.abort();
        encoded_pkt_send_task.abort();
        decoded_pkt_send_task.abort();
        network_change_task.abort();
        ticker_task.abort();

        result
    });

    Ok(ClientConnection {
        task,
        conn,
        inside_io,
        #[cfg(desktop)]
        outside_io,
        connected_signal: Some(connected_rx),
        stop_signal: Some(stop_tx),
        network_change_signal: network_change_tx,
        encoding_request_signal: encoding_request_tx,
        #[cfg(desktop)]
        route_manager: None,
        #[cfg(desktop)]
        dns_manager: None,
    })
}

/// Returns the index of the best connection.
///
/// Receives `(index, connected_signal)` pairs from `connection_setup_rx` as connections
/// are set up, rather than requiring all connections to be ready upfront.
/// The channel closing signals that no more connections will arrive.
///
/// If `preferred_connection_wait_interval` is non-zero it will wait that
/// duration before returning the highest priority connection (lowest index).
/// If there is only one connection, or the preferred connection (index 0)
/// is the first to connect, it will not wait.
async fn find_best_connection(
    mut connection_setup_rx: mpsc::Receiver<(usize, oneshot::Receiver<()>)>,
    preferred_connection_wait_interval: Duration,
) -> Result<usize> {
    let mut wait_timer_task = tokio::spawn(tokio::time::sleep(preferred_connection_wait_interval));

    let mut connected_stream = StreamMap::new();
    let mut best_connection_index: Option<usize> = None;
    let mut channel_open = true;

    loop {
        tokio::select! {
            biased;
            // Highest priority to make sure we add connections to the stream as soon as they are ready
            item = connection_setup_rx.recv(), if channel_open => {
                if let Some((index, signal)) = item {
                    connected_stream.insert(index, signal.into_stream());
                } else {
                    channel_open = false;
                }
            }
            _ = &mut wait_timer_task, if !wait_timer_task.is_finished() => {
                if let Some(index) = best_connection_index {
                    tracing::debug!("Preferred connection wait finished, using best connection so far: {index}");
                    return Ok(index);
                }
                tracing::debug!("Preferred connection wait finished, but no connection so far. Waiting for next connection.");
            }
            Some((index, result)) = connected_stream.next() => {
                if let Err(e) = result {
                    tracing::debug!("Connection {index} is offline: {e:?}");
                    continue;
                }

                tracing::debug!("Connection {index} is online");

                if wait_timer_task.is_finished() {
                    tracing::debug!("Preferred connection wait finished, using only connection so far: {index}");
                    return Ok(index);
                }

                // We don't defer connection if it's the preferred connection
                if index == 0 {
                    tracing::debug!("Preferred connection is online, using it.");
                    return Ok(index);
                }

                best_connection_index = Some(best_connection_index.map_or(index, |i| i.min(index)));
            }
            else => return Err(anyhow!("All connections disconnected")),
        }
    }
}

/// Runs connection futures concurrently, feeds their connected signals to
/// [`find_best_connection`], and returns the best connection index along with
/// all successful connections.
///
/// Each connect future must yield `(index, Result<(connected_signal, connection)>)`.
/// The `connected_signal` is forwarded to the selection logic; the `connection` is
/// stored and returned alongside the winning index.
async fn select_best_from_futures<C, Fut>(
    mut connect_futs: FuturesUnordered<Fut>,
    preferred_connection_wait_interval: Duration,
) -> Result<(usize, Vec<(usize, C)>)>
where
    Fut: Future<Output = (usize, Result<(oneshot::Receiver<()>, C)>)>,
{
    if connect_futs.is_empty() {
        return Err(anyhow!("No servers available"));
    }

    let server_count = connect_futs.len();
    let mut connections: Vec<(usize, C)> = Vec::new();

    let (connection_setup_tx, connection_setup_rx) = mpsc::channel(server_count);
    let mut connection_setup_tx = Some(connection_setup_tx);
    let mut setup_complete = false;

    let mut find_best = std::pin::pin!(find_best_connection(
        connection_setup_rx,
        preferred_connection_wait_interval,
    ));

    loop {
        tokio::select! {
            biased;

            // Higher priority to ensure we add the connection to find_best_connection asap
            Some((orig_idx, result)) = connect_futs.next(), if !setup_complete => {
                match result {
                    Ok((signal, conn)) => {
                        let _ = connection_setup_tx.as_ref().unwrap().send((orig_idx, signal)).await.inspect_err(|e| tracing::warn!("Failed to send connection signal: {e}"));
                        connections.push((orig_idx, conn));
                    }
                    Err(e) => {
                        tracing::error!("Creating connection failed: {e}");
                    }
                }
                if connect_futs.is_empty() {
                    setup_complete = true;
                    drop(connection_setup_tx.take()); // close the signal channel
                    if connections.is_empty() {
                        return Err(anyhow!("No servers are able to connect"));
                    }
                }
            }

            index = &mut find_best => {
                return Ok((index?, connections));
            }
        }
    }
}

fn validate_client_config<
    EventHandler: 'static + Send + EventCallback,
    ExtAppState: Send + Sync,
>(
    config: &ClientConfig<'_, ExtAppState>,
    servers: &[ClientConnectionConfig<EventHandler>],
) -> Result<()> {
    if config.network_change_signal.is_some() && config.keepalive_interval.is_zero() {
        return Err(anyhow!(
            "Keepalive interval cannot be zero when network change signal is set"
        ));
    }

    if servers.is_empty() {
        return Err(anyhow!("At least one server should be specified"));
    }

    for server_config in servers {
        if server_config.inside_pkt_codec.is_some() && config.inside_pkt_codec_config.is_none() {
            return Err(anyhow!(
                "Inside packet codec config has to be provided if inside packet codec is used (Server: {})",
                server_config.server
            ));
        }
    }

    Ok(())
}

/// Launches connections concurrently and waits for the first one to complete.
/// If `config.preferred_connection_wait_interval` is set, it will wait that
/// duration after the first connection completes before returning the highest
/// priority connection (in the specified array order).
///
/// stop_signal sends a signal if the program received INT/TERM signals
pub async fn client<
    EventHandler: 'static + Send + EventCallback,
    ExtAppState: 'static + Default + Send + Sync,
>(
    mut config: ClientConfig<'_, ExtAppState>,
    mut stop_signal: oneshot::Receiver<()>,
    servers: Vec<ClientConnectionConfig<EventHandler>>,
) -> Result<ClientResult> {
    tracing::info!(
        "Client starting with config:\n{:#?}, servers:\n{:#?}",
        &config,
        &servers
    );

    validate_client_config(&config, &servers)?;

    let inside_io = match &config.inside_io {
        Some(io) => Arc::clone(io),
        #[cfg(feature = "io-uring")]
        None if config.enable_tun_iouring => Arc::new(
            io::inside::Tun::new_with_iouring(
                &config.tun_config,
                config.tun_local_ip,
                config.tun_dns_ip,
                config.iouring_entry_count,
                config.iouring_sqpoll_idle_time,
            )
            .await?,
        ),
        None => Arc::new(
            io::inside::Tun::new(&config.tun_config, config.tun_local_ip, config.tun_dns_ip)
                .await?,
        ),
    };
    if let Ok(device_name) = inside_io.name() {
        tracing::info!(
            message = "Interface Details",
            %device_name,
            if_index = inside_io.if_index().ok(),
            dns_ip = %config.tun_dns_ip,
            local_ip = %config.tun_local_ip,
            peer_ip = %config.tun_peer_ip,
        );
    }

    let preferred_connection_wait_interval = config.preferred_connection_wait_interval;

    let (best_connection_index, mut connections) = {
        let connect_futs: FuturesUnordered<_> = servers
            .into_iter()
            .enumerate()
            .map(|(index, server_config)| {
                let config = &config;
                let inside_io = inside_io.clone();
                async move {
                    let result = connect(config, server_config, inside_io)
                        .await
                        .map(|mut conn| (conn.connected_signal.take().unwrap(), conn));
                    (index, result)
                }
            })
            .collect();

        tokio::select! {
            result = select_best_from_futures(
                connect_futs,
                preferred_connection_wait_interval,
            ) => result?,

            _ = &mut stop_signal => {
                return Ok(ClientResult::UserDisconnect);
            }
        }
    };
    // connect_futs dropped here — releases &config borrow

    tracing::info!(
        message = "Best connection selected",
        connection_id = best_connection_index,
    );
    let pos = connections
        .iter()
        .position(|(idx, _)| *idx == best_connection_index)
        .unwrap();
    let (_, mut connection) = connections.swap_remove(pos);

    if let Some(signal) = config.best_connection_selected_signal.take()
        && signal
            .send(BestConnectionInfo {
                index: best_connection_index,
                connection: connection.outside_connection_info(),
            })
            .is_err()
    {
        tracing::error!("Failed to send best_connection_selected_signal");
    }

    for (_, conn) in connections.iter_mut() {
        let _ = conn.stop_signal.take().unwrap().send(());
    }

    if let Some(mut network_change_signal) = config.network_change_signal.take() {
        let connection_network_change_signal = connection.network_change_signal.clone();
        tokio::spawn(async move {
            while network_change_signal.recv().await.is_some() {
                if let Err(e) = connection_network_change_signal.send(()).await {
                    tracing::error!("Failed to send network_change_signal: {e}");
                }
            }
        });
    }

    if let Some(mut inside_pkt_codec_config) = config.inside_pkt_codec_config.take() {
        let connection_encoding_request_signal = connection.encoding_request_signal.clone();
        tokio::spawn(async move {
            while let Some(enabled) = inside_pkt_codec_config.encoding_request_signal.recv().await {
                if let Err(e) = connection_encoding_request_signal.send(enabled).await {
                    tracing::error!("Failed to send encoding_request_signal: {e}");
                }
            }
        });
    }

    let connection_stop_signal = connection.stop_signal.take().unwrap();
    tokio::spawn(async move {
        let _ = stop_signal.await;
        if let Err(()) = connection_stop_signal.send(()) {
            tracing::error!("Failed to send stop signal");
        }
    });

    connection.set_connection_inside_io();

    #[cfg(desktop)]
    connection
        .initialize_routes(
            config.route_mode,
            config.tun_peer_ip.into(),
            config.tun_dns_ip.into(),
        )
        .await?;

    #[cfg(desktop)]
    connection.set_dns(config.dns_config_mode, config.tun_dns_ip.into())?;

    let result = connection.task.await?;

    #[cfg(desktop)]
    if let Some(mut route_manager) = connection.route_manager {
        let _ = route_manager.stop().await;
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_case::test_case;

    #[test_case(1, vec![], false => None)]
    #[test_case(1, vec![0], true => Some(0))]
    #[test_case(2, vec![], false => None)]
    #[test_case(2, vec![0], true => Some(0))]
    #[test_case(2, vec![1], false => Some(1))]
    #[test_case(2, vec![0, 1], true => Some(0))]
    #[test_case(2, vec![1, 0], true => Some(0))]
    #[test_case(3, vec![2], false => Some(2))]
    #[test_case(3, vec![2, 1], false => Some(1))]
    #[test_case(3, vec![1, 2], false => Some(1))]
    #[test_case(3, vec![2, 1, 0], true => Some(0))]
    #[test_case(3, vec![1, 2, 0], true => Some(0))]
    #[test_case(3, vec![0, 1, 2], true => Some(0))]
    #[tokio::test]
    async fn test_find_best_connection(
        signals_len: usize,
        connected_signal_order: Vec<usize>,
        should_connect_before_wait_finishes: bool,
    ) -> Option<usize> {
        let (connection_setup_tx, connection_setup_rx) = mpsc::channel(signals_len);
        let (mut connected_txs, connected_rxs): (
            Vec<Option<oneshot::Sender<()>>>,
            Vec<oneshot::Receiver<()>>,
        ) = (0..signals_len)
            .map(|_| {
                let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                (Some(tx), rx)
            })
            .unzip();

        for (i, rx) in connected_rxs.into_iter().enumerate() {
            connection_setup_tx.try_send((i, rx)).unwrap();
        }
        drop(connection_setup_tx);

        let task = tokio::spawn(find_best_connection(
            connection_setup_rx,
            Duration::from_millis(200),
        ));

        tokio::spawn(async move {
            for i in connected_signal_order {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let tx = connected_txs[i].take().unwrap();
                // Will fail if preferred connection is already found and channel is closed
                let _ = tx.send(());
            }
        });

        let wait_duration = if should_connect_before_wait_finishes {
            Duration::from_millis(100)
        } else {
            Duration::from_millis(300)
        };

        tokio::select! {
            index = task => {
                index.unwrap().ok()
            }
            _ = tokio::time::sleep(wait_duration) => None
        }
    }

    #[tokio::test]
    async fn test_find_best_connection_connects_after_wait_finishes() {
        let (connection_setup_tx, connection_setup_rx) = mpsc::channel(2);
        let (_, rx0) = tokio::sync::oneshot::channel::<()>();
        let (tx1, rx1) = tokio::sync::oneshot::channel::<()>();

        connection_setup_tx.try_send((0, rx0)).unwrap();
        connection_setup_tx.try_send((1, rx1)).unwrap();
        drop(connection_setup_tx);

        let task = tokio::spawn(find_best_connection(
            connection_setup_rx,
            Duration::from_millis(200),
        ));

        tokio::spawn(async move {
            // Wait for after `preferred_connection_wait_interval`
            tokio::time::sleep(Duration::from_millis(300)).await;
            let _ = tx1.send(());
        });

        let best_connection_index = tokio::select! {
            index = task => {
                Some(index.unwrap().unwrap())
            }
            _ = tokio::time::sleep(Duration::from_millis(400)) => None
        };

        assert_eq!(best_connection_index, Some(1));
    }

    // select_best_from_futures tests

    // Helper type alias for boxed connect futures used in select_best_from_futures tests
    type BoxedConnectFut =
        std::pin::Pin<Box<dyn Future<Output = (usize, Result<(oneshot::Receiver<()>, ())>)>>>;

    #[tokio::test]
    async fn test_select_best_one_connect_fails_other_succeeds() {
        let (tx1, rx1) = oneshot::channel::<()>();

        let futs = FuturesUnordered::new();
        futs.push(Box::pin(async {
            (
                0usize,
                Err::<(oneshot::Receiver<()>, ()), _>(anyhow!("timeout")),
            )
        }) as BoxedConnectFut);
        futs.push(Box::pin(async move { (1usize, Ok((rx1, ()))) }));

        // Signal connection 1 as online shortly after setup
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx1.send(());
        });

        let (best_index, connections) = select_best_from_futures(futs, Duration::ZERO)
            .await
            .unwrap();

        assert_eq!(best_index, 1);
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].0, 1);
    }

    #[test_case(0, "No servers available" ; "empty futures")]
    #[test_case(1, "No servers are able to connect" ; "single future fails")]
    #[test_case(2, "No servers are able to connect" ; "all futures fail")]
    #[tokio::test]
    async fn test_select_best_all_futures_fail(num_futures: usize, expected_error: &str) {
        let futs: FuturesUnordered<BoxedConnectFut> = FuturesUnordered::new();
        for i in 0..num_futures {
            futs.push(Box::pin(async move {
                (i, Err::<(oneshot::Receiver<()>, ()), _>(anyhow!("fail")))
            }));
        }

        let result = select_best_from_futures(futs, Duration::ZERO).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), expected_error);
    }

    #[tokio::test]
    async fn test_select_best_preferred_connection_wins() {
        let (tx0, rx0) = oneshot::channel::<()>();
        let (tx1, rx1) = oneshot::channel::<()>();

        let futs = FuturesUnordered::new();
        futs.push(Box::pin(async move { (0usize, Ok((rx0, ()))) }) as BoxedConnectFut);
        futs.push(Box::pin(async move { (1usize, Ok((rx1, ()))) }));

        // Both connect, but server 1 signals first, then server 0 signals
        // within the preferred wait interval
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx1.send(());
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx0.send(());
        });

        let (best_index, connections) = select_best_from_futures(futs, Duration::from_millis(200))
            .await
            .unwrap();

        // Server 0 is preferred (lowest index) and connected within wait interval
        assert_eq!(best_index, 0);
        assert_eq!(connections.len(), 2);
    }

    #[tokio::test]
    async fn test_select_best_returns_all_successful_connections() {
        let (tx0, rx0) = oneshot::channel::<()>();
        let (tx1, _rx1) = oneshot::channel::<()>();
        let (tx2, rx2) = oneshot::channel::<()>();

        let futs = FuturesUnordered::new();
        futs.push(Box::pin(async move { (0usize, Ok((rx0, ()))) }) as BoxedConnectFut);
        futs.push(Box::pin(async {
            (
                1usize,
                Err::<(oneshot::Receiver<()>, ()), _>(anyhow!("fail")),
            )
        }));
        futs.push(Box::pin(async move { (2usize, Ok((rx2, ()))) }));

        // Signal connections 2 then 0
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx2.send(());
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx0.send(());
        });
        // tx1 intentionally dropped (connection 1 failed to connect)
        drop(tx1);

        let (best_index, connections) = select_best_from_futures(futs, Duration::from_millis(200))
            .await
            .unwrap();

        // Server 0 is preferred and connected within wait
        assert_eq!(best_index, 0);
        // Only 2 successful connections (server 1 failed)
        assert_eq!(connections.len(), 2);
        let indices: Vec<usize> = connections.iter().map(|(idx, _)| *idx).collect();
        assert!(indices.contains(&0));
        assert!(indices.contains(&2));
    }

    #[test_case(Duration::ZERO ; "immediate futures")]
    #[test_case(Duration::from_millis(50) ; "slow futures")]
    #[tokio::test]
    async fn test_select_best_all_succeed(future_delay: Duration) {
        let (tx0, rx0) = oneshot::channel::<()>();
        let (tx1, rx1) = oneshot::channel::<()>();
        let (tx2, rx2) = oneshot::channel::<()>();

        let futs = FuturesUnordered::new();
        futs.push(Box::pin(async move {
            tokio::time::sleep(future_delay).await;
            (0usize, Ok((rx0, ())))
        }) as BoxedConnectFut);
        futs.push(Box::pin(async move {
            tokio::time::sleep(future_delay).await;
            (1usize, Ok((rx1, ())))
        }));
        futs.push(Box::pin(async move {
            tokio::time::sleep(future_delay).await;
            (2usize, Ok((rx2, ())))
        }));

        tokio::spawn(async move {
            tokio::time::sleep(future_delay + Duration::from_millis(10)).await;
            let _ = tx2.send(());
            let _ = tx1.send(());
            let _ = tx0.send(());
        });

        let (best_index, connections) = select_best_from_futures(futs, Duration::from_millis(200))
            .await
            .unwrap();

        assert_eq!(best_index, 0);
        assert_eq!(connections.len(), 3);
    }

    #[test_case(
        vec![1],
        1 ;
        "single non preferred when preferred never signals"
    )]
    #[test_case(
        vec![3, 2],
        2 ;
        "lowest non preferred selected from multiple"
    )]
    #[tokio::test]
    async fn test_select_best_non_preferred_wins_after_wait(
        signal_order: Vec<usize>,
        expected_best: usize,
    ) {
        let max_idx = *signal_order.iter().max().unwrap();
        let mut signal_txs = Vec::new();
        let futs = FuturesUnordered::new();

        for i in 0..=max_idx {
            let (tx, rx) = oneshot::channel::<()>();
            if signal_order.contains(&i) {
                signal_txs.push((i, tx));
            }
            // Non-signaling senders dropped here, receiver sees RecvError
            futs.push(Box::pin(async move { (i, Ok((rx, ()))) }) as BoxedConnectFut);
        }

        // Order senders to match signal_order
        let ordered_txs: Vec<_> = signal_order
            .iter()
            .map(|&idx| {
                let pos = signal_txs.iter().position(|(i, _)| *i == idx).unwrap();
                signal_txs.remove(pos)
            })
            .collect();

        tokio::spawn(async move {
            for (_, tx) in ordered_txs {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let _ = tx.send(());
            }
        });

        let (best_index, connections) = select_best_from_futures(futs, Duration::from_millis(50))
            .await
            .unwrap();

        assert_eq!(best_index, expected_best);
        assert_eq!(connections.len(), max_idx + 1);
    }

    #[tokio::test]
    async fn test_select_best_connections_never_signal() {
        // Connections set up successfully but never signal as "online".
        // Senders must be dropped so receivers see RecvError
        let (tx0, rx0) = oneshot::channel::<()>();
        let (tx1, rx1) = oneshot::channel::<()>();
        drop(tx0);
        drop(tx1);

        let futs = FuturesUnordered::new();
        futs.push(Box::pin(async move { (0usize, Ok((rx0, ()))) }) as BoxedConnectFut);
        futs.push(Box::pin(async move { (1usize, Ok((rx1, ()))) }));

        let result = select_best_from_futures(futs, Duration::from_millis(50)).await;
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "All connections disconnected"
        );
    }
}
