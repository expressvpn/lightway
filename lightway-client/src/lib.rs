mod debug;
mod io;
mod keepalive;

use crate::io::inside::InsideIO;
use anyhow::{anyhow, Result};
use bytes::BytesMut;
use bytesize::ByteSize;
use keepalive::Keepalive;
use lightway_app_utils::{
    args::Cipher, connection_ticker_cb, ConnectionTicker, ConnectionTickerState, DplpmtudTimer,
    EventStream, EventStreamCallback,
};
use lightway_core::{
    ipv4_update_destination, ipv4_update_source, BuilderPredicates, ClientContextBuilder,
    ClientIpConfig, ConnectionError, ConnectionType, Event, IOCallbackResult, InsideIpConfig,
    OutsidePacket, State,
};

// re-export so client app does not need to depend on lightway-core
pub use lightway_core::{
    AuthMethod, PluginFactoryError, PluginFactoryList, RootCertificate, Version, MAX_INSIDE_MTU,
    MAX_OUTSIDE_MTU,
};
use pnet::packet::ipv4::Ipv4Packet;

#[cfg(feature = "debug")]
use std::path::PathBuf;
use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::{TcpStream, UdpSocket},
    task::JoinHandle,
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

#[derive(educe::Educe)]
#[educe(Debug)]
pub struct ClientConfig<'cert> {
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
    pub inside_mtu: Option<i32>,

    /// Tun device name to use
    #[cfg(feature = "linux-tun")]
    pub tun_name: String,

    /// Tun FD to write to for non-linux platform
    #[cfg(not(feature = "linux-tun"))]
    pub tun_fd: std::os::fd::RawFd,

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

    /// Socket send buffer size
    pub sndbuf: Option<ByteSize>,
    /// Socket receive buffer size
    pub rcvbuf: Option<ByteSize>,

    /// Enable PMTU discovery for Udp connections
    pub enable_pmtud: bool,

    /// Enable IO-uring interface for Tunnel
    pub enable_tun_iouring: bool,

    /// IO-uring submission queue count. Only applicable when
    /// `enable_tun_iouring` is `true`
    // Any value more than 1024 negatively impact the throughput
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

struct ClientIpConfigCb;

impl ClientIpConfig<ConnectionState> for ClientIpConfigCb {
    fn ip_config(&self, state: &mut ConnectionState, ip_config: InsideIpConfig) {
        tracing::debug!("Got IP from server: {ip_config:?}");
        state.ip_config = Some(ip_config);
    }
}

pub(crate) struct ConnectionState {
    // Handler for tick callbacks.
    ticker: ConnectionTicker,
    // InsideIpConfig received from server
    pub(crate) ip_config: Option<InsideIpConfig>,
}

impl ConnectionTickerState for ConnectionState {
    fn connection_ticker(&self) -> &ConnectionTicker {
        &self.ticker
    }
}

async fn handle_events(mut stream: EventStream, keepalive: Keepalive) {
    while let Some(event) = stream.next().await {
        match event {
            Event::StateChanged(state) => {
                tracing::debug!("State changed to {:?}", state);
                if matches!(state, State::Online) {
                    keepalive.online().await
                }
            }
            Event::KeepaliveReply => keepalive.reply_received().await,

            // Server only events
            Event::SessionIdRotationAcknowledged { .. } | Event::TlsKeysUpdate => {
                unreachable!("server only event received");
            }
        }
    }
}

pub async fn client(config: ClientConfig<'_>) -> Result<()> {
    println!("Client starting with config:\n{:#?}", &config);

    let (connection_type, outside_io): (ConnectionType, Arc<dyn io::outside::OutsideIO>) =
        match config.mode {
            ClientConnectionType::Datagram(maybe_sock) => {
                let sock = io::outside::Udp::new(&config.server, maybe_sock).await?;
                (ConnectionType::Datagram, sock)
            }
            ClientConnectionType::Stream(maybe_sock) => {
                let sock = io::outside::Tcp::new(&config.server, maybe_sock).await?;
                (ConnectionType::Stream, sock)
            }
        };

    if let Some(size) = config.sndbuf {
        outside_io.set_send_buffer_size(size.as_u64().try_into()?)?;
    }

    if let Some(size) = config.rcvbuf {
        outside_io.set_recv_buffer_size(size.as_u64().try_into()?)?;
    }

    #[cfg(feature = "linux-tun")]
    let iouring = if config.enable_tun_iouring {
        Some(config.iouring_entry_count)
    } else {
        None
    };

    #[cfg(feature = "linux-tun")]
    let inside_io = Arc::new(
        io::inside::Tun::from_name(
            &config.tun_name,
            config.tun_local_ip,
            config.tun_dns_ip,
            config.inside_mtu,
            iouring,
        )
        .await?,
    );

    #[cfg(not(feature = "linux-tun"))]
    let inside_io = Arc::new(
        io::inside::Tun::from_fd(
            config.tun_fd,
            config.tun_local_ip,
            config.tun_dns_ip,
            config.inside_mtu,
        )
        .await?,
    );

    let (event_cb, event_stream) = EventStreamCallback::new();

    let (ticker, ticker_task) = ConnectionTicker::new();
    let state = ConnectionState {
        ticker,
        ip_config: None,
    };
    let (pmtud_timer, pmtud_timer_task) = DplpmtudTimer::new();

    let conn_builder = ClientContextBuilder::new(
        connection_type,
        config.root_ca_cert,
        inside_io.clone().into_io_send_callback(),
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
        },
        Arc::downgrade(&conn),
    );

    tokio::spawn(handle_events(event_stream, keepalive.clone()));

    ticker_task.spawn(Arc::downgrade(&conn));
    pmtud_timer_task.spawn(Arc::downgrade(&conn));

    let outside_io_loop_conn = conn.clone();
    let outside_io_loop: JoinHandle<anyhow::Error> = tokio::spawn(async move {
        let conn = outside_io_loop_conn;

        loop {
            let poll_result = outside_io.poll(tokio::io::Interest::READABLE).await;

            if let Err(e) = poll_result {
                // Unrecoverable errors: https://github.com/tokio-rs/tokio/discussions/5552
                break e;
            }

            let mut buf = BytesMut::with_capacity(config.outside_mtu);

            match outside_io.recv_buf(&mut buf) {
                IOCallbackResult::Ok(_nr) => {}
                IOCallbackResult::WouldBlock => continue, // Spuriously failed to read, keep waiting
                IOCallbackResult::Err(err) => {
                    // Fatal error
                    break err.into();
                }
            };

            let pkt = OutsidePacket::Wire(buf, connection_type);
            if let Err(err) = conn.lock().unwrap().outside_data_received(pkt) {
                if err.is_fatal(connection_type) {
                    break err.into();
                }
                tracing::error!("Failed to process outside data: {err}");
            }

            keepalive.outside_activity().await
        }
    });

    let inside_io_loop_conn = conn.clone();
    let inside_io_loop: JoinHandle<anyhow::Error> = tokio::spawn(async move {
        let conn = inside_io_loop_conn;

        loop {
            let mut buf = match inside_io.recv_buf().await {
                IOCallbackResult::Ok(buf) => buf,
                IOCallbackResult::WouldBlock => continue, // Spuriously failed to read, keep waiting
                IOCallbackResult::Err(err) => {
                    // Fatal error
                    break err.into();
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
                    if packet.get_destination() == config.tun_dns_ip {
                        ipv4_update_destination(buf.as_mut(), ip_config.dns_ip);
                    }
                };
            }

            match conn.inside_data_received(buf) {
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
                    break err.into();
                }
            }
        }
    });

    let (ctrlc_tx, mut ctrlc_rx) = tokio::sync::mpsc::channel(1);
    ctrlc::set_handler(move || {
        ctrlc_tx.blocking_send(()).expect("CtrlC handler failed");
    })?;

    tokio::select! {
        Some(_) = keepalive_task => Err(anyhow!("Keepalive timeout")),
        io = outside_io_loop => Err(anyhow!("Outside IO loop exited: {io:?}")),
        io = inside_io_loop => Err(anyhow!("Inside IO loop exited: {io:?}")),
        _ = ctrlc_rx.recv() => {
            info!("sigint/sigterm received, gracefully shutting down");
            let _ = conn.lock().unwrap().disconnect();
            Err(anyhow!("sigint/sigterm received"))
        }
    }
}
