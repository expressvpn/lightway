mod debug;
pub mod io;
pub mod keepalive;

use anyhow::{anyhow, Context, Result};
use bytes::BytesMut;
use bytesize::ByteSize;
use futures::future::OptionFuture;
use keepalive::Keepalive;
use lightway_app_utils::{
    args::Cipher, connection_ticker_cb, ConnectionTicker, ConnectionTickerState, DplpmtudTimer,
    EventStream, EventStreamCallback, TunConfig,
};
use lightway_core::{
    ipv4_update_destination, ipv4_update_source, BuilderPredicates, ClientContextBuilder,
    ClientIpConfig, Connection, ConnectionError, ConnectionType, Event, EventCallback,
    IOCallbackResult, InsideIpConfig, OutsidePacket, State,
};

// re-export so client app does not need to depend on lightway-core
#[cfg(feature = "debug")]
pub use lightway_core::enable_tls_debug;
pub use lightway_core::{
    AuthMethod, PluginFactoryError, PluginFactoryList, RootCertificate, Version, MAX_INSIDE_MTU,
    MAX_OUTSIDE_MTU,
};
use pnet::packet::ipv4::Ipv4Packet;

#[cfg(feature = "debug")]
use std::path::PathBuf;
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex, Weak},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_stream::StreamExt;
use tracing::info;

#[cfg(feature = "debug")]
use crate::debug::WiresharkKeyLogger;

/// Connection type
/// Applications can also attach socket for library to use directly,
/// if there is any customisations needed
pub enum ClientConnectionType {
    Stream(Option<TcpStream>),
    Datagram(Option<UdpSocket>),
}

impl std::fmt::Debug for ClientConnectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stream(_) => f.debug_tuple("Stream").finish(),
            Self::Datagram(_) => f.debug_tuple("Datagram").finish(),
        }
    }
}

#[derive(Debug)]
pub enum ClientResult {
    UserDisconnect,
    NetworkChange,
}

#[derive(educe::Educe)]
#[educe(Debug)]
pub struct ClientConfig<'cert, A: 'static + Send + EventCallback> {
    /// Connection mode
    pub mode: ClientConnectionType,

    /// Auth parameters to use for connection
    #[educe(Debug(ignore))]
    pub auth: AuthMethod,

    /// CA certificate
    #[educe(Debug(ignore))]
    pub root_ca_cert: RootCertificate<'cert>,

    /// Outside (wire) MTU
    pub outside_mtu: usize,

    /// Inside (tunnel) MTU (requires `CAP_NET_ADMIN`)
    pub inside_mtu: Option<u16>,

    /// Tun device to use
    pub tun_config: TunConfig,

    /// Local IP to use in Tun device
    pub tun_local_ip: Ipv4Addr,

    /// Peer IP to use in Tun device
    pub tun_peer_ip: Ipv4Addr,

    /// DNS IP to use in Tun device
    pub tun_dns_ip: Ipv4Addr,

    /// Cipher to use for encryption
    pub cipher: Cipher,

    /// Enable Post Quantum Crypto
    #[cfg(feature = "postquantum")]
    pub enable_pqc: bool,

    /// Interval between keepalives
    pub keepalive_interval: Duration,

    /// Keepalive timeout
    pub keepalive_timeout: Duration,

    /// Enables keepalives to be sent constantly instead
    /// of only during network change events
    pub continuous_keepalive: bool,

    /// Socket send buffer size
    pub sndbuf: Option<ByteSize>,
    /// Socket receive buffer size
    pub rcvbuf: Option<ByteSize>,

    /// Enable PMTU discovery for Udp connections
    pub enable_pmtud: bool,

    /// Enable IO-uring interface for Tunnel
    #[cfg(feature = "io-uring")]
    pub enable_tun_iouring: bool,

    /// IO-uring submission queue count. Only applicable when
    /// `enable_tun_iouring` is `true`
    // Any value more than 1024 negatively impact the throughput
    #[cfg(feature = "io-uring")]
    pub iouring_entry_count: usize,

    /// Server domain name to validate
    pub server_dn: Option<String>,

    /// Server to connect to
    pub server: String,

    /// Inside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub inside_plugins: PluginFactoryList,

    /// Outside plugins to use
    #[educe(Debug(method(debug_fmt_plugin_list)))]
    pub outside_plugins: PluginFactoryList,

    /// Specifies if the program responds to INT/TERM signals
    #[educe(Debug(ignore))]
    pub stop_signal: oneshot::Receiver<()>,

    /// Signal for notifying a network change event
    /// network change being defined as a change in
    /// wifi networks or a change of network interfaces
    #[educe(Debug(ignore))]
    pub network_change_signal: Option<mpsc::Receiver<()>>,

    /// Allow injection of a custom handler for event callback
    #[educe(Debug(ignore))]
    pub event_handler: Option<A>,

    /// File path to save wireshark keylog
    #[cfg(feature = "debug")]
    pub keylog: Option<PathBuf>,
}

fn debug_fmt_plugin_list(
    list: &PluginFactoryList,
    f: &mut std::fmt::Formatter,
) -> Result<(), std::fmt::Error> {
    write!(f, "{} plugins", list.len())
}

pub struct ClientIpConfigCb;

impl<T: Send + Sync> ClientIpConfig<ConnectionState<T>> for ClientIpConfigCb {
    fn ip_config(&self, state: &mut ConnectionState<T>, ip_config: InsideIpConfig) {
        state.ip_config = Some(ip_config);
    }
}

pub struct ConnectionState<T: Send + Sync = ()> {
    /// Handler for tick callbacks.
    pub ticker: ConnectionTicker,
    /// InsideIpConfig received from server
    pub ip_config: Option<InsideIpConfig>,
    /// Other extended state
    pub extended: T,
}

impl<T: Send + Sync> ConnectionTickerState for ConnectionState<T> {
    fn connection_ticker(&self) -> &ConnectionTicker {
        &self.ticker
    }
}

async fn handle_events<A: 'static + Send + EventCallback>(
    mut stream: EventStream,
    keepalive: Keepalive,
    event_handler: Option<A>,
) {
    while let Some(event) = stream.next().await {
        match &event {
            Event::StateChanged(state) => {
                if matches!(state, State::Online) {
                    keepalive.online().await
                }
            }
            Event::KeepaliveReply => keepalive.reply_received().await,

            // Server only events
            Event::SessionIdRotationAcknowledged { .. }
            | Event::TlsKeysUpdateStart
            | Event::TlsKeysUpdateCompleted => {
                unreachable!("server only event received");
            }
        }
        if let Some(ref handler) = event_handler {
            handler.event(event);
        }
    }
}

pub async fn outside_io_task<T: Send + Sync>(
    conn: Arc<Mutex<Connection<ConnectionState<T>>>>,
    mtu: usize,
    connection_type: ConnectionType,
    outside_io: Arc<dyn io::outside::OutsideIO>,
    keepalive: Keepalive,
) -> Result<()> {
    let mut buf = BytesMut::with_capacity(mtu);
    loop {
        // Recover full capacity
        buf.clear();
        buf.reserve(mtu);

        // Unrecoverable errors: https://github.com/tokio-rs/tokio/discussions/5552
        outside_io.poll(tokio::io::Interest::READABLE).await?;

        match outside_io.recv_buf(&mut buf) {
            IOCallbackResult::Ok(_nr) => {}
            IOCallbackResult::WouldBlock => continue, // Spuriously failed to read, keep waiting
            IOCallbackResult::Err(err) => {
                // Fatal error
                return Err(err.into());
            }
        };

        let pkt = OutsidePacket::Wire(&mut buf, connection_type);
        if let Err(err) = conn.lock().unwrap().outside_data_received(pkt) {
            if err.is_fatal(connection_type) {
                return Err(err.into());
            }
            tracing::error!("Failed to process outside data: {err}");
        }

        keepalive.outside_activity().await
    }
}

pub async fn inside_io_task<T: Send + Sync>(
    conn: Arc<Mutex<Connection<ConnectionState<T>>>>,
    inside_io: Arc<dyn io::inside::InsideIO>,
    tun_dns_ip: Ipv4Addr,
) -> Result<()> {
    loop {
        let mut buf = match inside_io.recv_buf().await {
            IOCallbackResult::Ok(buf) => buf,
            IOCallbackResult::WouldBlock => continue, // Spuriously failed to read, keep waiting
            IOCallbackResult::Err(err) => {
                // Fatal error
                return Err(err.into());
            }
        };

        let mut conn = conn.lock().unwrap();

        // Update source IP address to server assigned IP address
        let ip_config = conn.app_state().ip_config;
        if let Some(ip_config) = &ip_config {
            ipv4_update_source(buf.as_mut(), ip_config.client_ip);

            // Update TUN device DNS IP address to server provided DNS address
            let packet = Ipv4Packet::new(buf.as_ref());
            if let Some(packet) = packet {
                if packet.get_destination() == tun_dns_ip {
                    ipv4_update_destination(buf.as_mut(), ip_config.dns_ip);
                }
            };
        }

        match conn.inside_data_received(&mut buf) {
            Ok(()) => {}
            Err(ConnectionError::PluginDropWithReply(reply)) => {
                // Send the reply packet to inside path
                let _ = inside_io.try_send(reply, ip_config);
            }
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
}

async fn handle_network_change(
    keepalive: Keepalive,
    mut network_change_signal: mpsc::Receiver<()>,
    weak: Weak<Mutex<lightway_core::Connection<ConnectionState>>>,
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

fn validate_client_config<A: 'static + Send + EventCallback>(
    config: &ClientConfig<'_, A>,
) -> Result<()> {
    if config.network_change_signal.is_some() && config.keepalive_interval.is_zero() {
        return Err(anyhow!(
            "Keepalive interval cannot be zero when network change signal is set"
        ));
    }
    Ok(())
}

pub async fn client<A: 'static + Send + EventCallback>(
    mut config: ClientConfig<'_, A>,
) -> Result<ClientResult> {
    println!("Client starting with config:\n{:#?}", &config);

    validate_client_config(&config)?;

    let mut join_set = JoinSet::new();

    let (connection_type, outside_io): (ConnectionType, Arc<dyn io::outside::OutsideIO>) =
        match config.mode {
            ClientConnectionType::Datagram(maybe_sock) => {
                let sock = io::outside::Udp::new(&config.server, maybe_sock)
                    .await
                    .context("Outside IO UDP")?;

                (ConnectionType::Datagram, sock)
            }
            ClientConnectionType::Stream(maybe_sock) => {
                let sock = io::outside::Tcp::new(&config.server, maybe_sock)
                    .await
                    .context("Outside IO TCP")?;
                (ConnectionType::Stream, sock)
            }
        };

    if let Some(size) = config.sndbuf {
        outside_io.set_send_buffer_size(size.as_u64().try_into()?)?;
    }

    if let Some(size) = config.rcvbuf {
        outside_io.set_recv_buffer_size(size.as_u64().try_into()?)?;
    }

    #[cfg(feature = "io-uring")]
    let iouring = if config.enable_tun_iouring {
        Some(config.iouring_entry_count)
    } else {
        None
    };

    let inside_io = Arc::new(
        io::inside::Tun::new(
            config.tun_config,
            config.tun_local_ip,
            config.tun_dns_ip,
            #[cfg(feature = "io-uring")]
            iouring,
        )
        .await
        .context("Tun creation")?,
    );

    let (event_cb, event_stream) = EventStreamCallback::new();

    let (ticker, ticker_task) = ConnectionTicker::new();
    let state = ConnectionState {
        ticker,
        ip_config: None,
        extended: (),
    };
    let (pmtud_timer, pmtud_timer_task) = DplpmtudTimer::new();

    let conn_builder = ClientContextBuilder::new(
        connection_type,
        config.root_ca_cert,
        inside_io.clone(),
        Arc::new(ClientIpConfigCb),
    )?
    .with_cipher(config.cipher.into())?
    .with_schedule_tick_cb(connection_ticker_cb)
    .with_inside_plugins(config.inside_plugins)
    .with_outside_plugins(config.outside_plugins)
    .build()
    .start_connect(
        outside_io.clone().into_io_send_callback(),
        config.outside_mtu,
    )?
    .with_auth(config.auth)
    .with_event_cb(Box::new(event_cb))
    .when_some(config.server_dn, |b, sdn| {
        b.with_server_domain_name_validation(sdn)
    })
    .when(connection_type.is_datagram() && config.enable_pmtud, |b| {
        b.with_pmtud_timer(pmtud_timer)
    });

    #[cfg(feature = "postquantum")]
    let conn_builder = conn_builder.when(config.enable_pqc, |b| b.with_pq_crypto());

    #[cfg(feature = "debug")]
    let conn_builder = conn_builder.when_some(config.keylog, |b, k| {
        b.with_key_logger(WiresharkKeyLogger::new(k))
    });

    let conn = Arc::new(Mutex::new(conn_builder.connect(state)?));

    let (keepalive, keepalive_task) = Keepalive::new(
        keepalive::Config {
            interval: config.keepalive_interval,
            timeout: config.keepalive_timeout,
            continuous: config.continuous_keepalive,
        },
        Arc::downgrade(&conn),
    );

    let event_handler = config.event_handler.take();
    join_set.spawn(handle_events(
        event_stream,
        keepalive.clone(),
        event_handler,
    ));

    ticker_task.spawn(Arc::downgrade(&conn), &mut join_set);
    pmtud_timer_task.spawn(Arc::downgrade(&conn), &mut join_set);

    let outside_io_loop: JoinHandle<anyhow::Result<()>> = tokio::spawn(outside_io_task(
        conn.clone(),
        config.outside_mtu,
        connection_type,
        outside_io,
        keepalive.clone(),
    ));

    let inside_io_loop: JoinHandle<anyhow::Result<()>> =
        tokio::spawn(inside_io_task(conn.clone(), inside_io, config.tun_dns_ip));

    let network_change_task: OptionFuture<JoinHandle<ClientResult>> =
        match config.network_change_signal {
            Some(network_change_signal) => Some(tokio::spawn(handle_network_change(
                keepalive,
                network_change_signal,
                Arc::downgrade(&conn),
            )))
            .into(),
            None => None.into(),
        };

    tokio::select! {
        Some(_) = keepalive_task => Err(anyhow!("Keepalive timeout")),
        io = outside_io_loop => Err(anyhow!("Outside IO loop exited: {io:?}")),
        io = inside_io_loop => Err(anyhow!("Inside IO loop exited: {io:?}")),
        _ = config.stop_signal => {
            info!("client shutting down ..");
            let _ = conn.lock().unwrap().disconnect();
            Ok(ClientResult::UserDisconnect)
        },
        Some(result) = network_change_task => {
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
    }
}
