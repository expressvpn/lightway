use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use bytes::BytesMut;
use lightway_core::{
    ConnectionType, IOCallbackResult, MAX_OUTSIDE_MTU, OutsideIOSendCallback, OutsidePacket, State,
    Version,
};
use socket2::SockRef;
use tokio::io::AsyncReadExt as _;
use tracing::{debug, info, instrument, warn};

use crate::{connection_manager::ConnectionManager, metrics};

use super::Server;
use super::ws_tcp::WsTcpStream;

struct TcpStream {
    sock: Arc<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
}

impl OutsideIOSendCallback for TcpStream {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.sock.try_write(buf) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

async fn handle_proxy_protocol(sock: &mut tokio::net::TcpStream) -> Result<SocketAddr> {
    use ppp::v2::{Header, ParseError};

    // https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt §2.2
    const MINIMUM_LENGTH: usize = 16;

    let mut header: Vec<u8> = [0; MINIMUM_LENGTH].into();
    if let Err(err) = sock.read_exact(&mut header[..MINIMUM_LENGTH]).await {
        return Err(anyhow!(err).context("Failed to read initial PROXY header"));
    };
    let rest = match Header::try_from(&header[..]) {
        // Failure tells us exactly how many more bytes are required.
        Err(ParseError::Partial(_, rest)) => rest,

        Ok(_) => {
            // The initial 16 bytes is never enough to actually succeed.
            return Err(anyhow!("Unexpectedly parsed initial PROXY header"));
        }
        Err(err) => {
            return Err(anyhow!(err).context("Failed to parse initial PROXY header"));
        }
    };

    header.resize(MINIMUM_LENGTH + rest, 0);

    if let Err(err) = sock.read_exact(&mut header[MINIMUM_LENGTH..]).await {
        return Err(anyhow!(err).context("Failed to read remainder of PROXY header"));
    };

    let header = match Header::try_from(&header[..]) {
        Ok(h) => h,
        Err(err) => {
            return Err(anyhow!(err).context("Failed to parse complete PROXY header"));
        }
    };

    let addr = match header.addresses {
        ppp::v2::Addresses::Unspecified => {
            return Err(anyhow!("Unspecified PROXY connection"));
        }
        ppp::v2::Addresses::IPv4(addr) => {
            SocketAddr::new(addr.source_address.into(), addr.source_port)
        }
        ppp::v2::Addresses::IPv6(_) => {
            return Err(anyhow!("IPv6 PROXY connection"));
        }
        ppp::v2::Addresses::Unix(_) => {
            return Err(anyhow!("Unix PROXY connection"));
        }
    };
    Ok(addr)
}

#[instrument(level = "trace", skip_all)]
async fn handle_connection(
    mut sock: tokio::net::TcpStream,
    mut peer_addr: SocketAddr,
    local_addr: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    proxy_protocol: bool,
    websocket: bool,
    ws_path: Arc<String>,
) {
    if proxy_protocol {
        peer_addr = match handle_proxy_protocol(&mut sock).await {
            Ok(real_addr) => real_addr,
            Err(err) => {
                debug!(?err, "Failed to process PROXY header");
                metrics::connection_accept_proxy_header_failed();
                return;
            }
        };
    }

    let sock = Arc::new(sock);

    if websocket {
        handle_ws_read_loop(sock, peer_addr, local_addr, conn_manager, &ws_path).await;
    } else {
        handle_tcp_read_loop(sock, peer_addr, local_addr, conn_manager).await;
    }
}

async fn handle_tcp_read_loop(
    sock: Arc<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
) {
    let outside_io = Arc::new(TcpStream {
        sock: sock.clone(),
        peer_addr,
    });
    let Ok(conn) =
        conn_manager.create_streaming_connection(Version::MINIMUM, local_addr, outside_io)
    else {
        return;
    };
    drop(conn_manager);

    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
    let age_expiration_interval: Duration =
        crate::connection_manager::CONNECTION_AGE_EXPIRATION_INTERVAL
            .try_into()
            .unwrap();
    let err: anyhow::Error = loop {
        tokio::select! {
            res = sock.readable() => {
                if let Err(e) = res {
                    break anyhow!(e).context("Sock readable error");
                }
            },
            _ = tokio::time::sleep(age_expiration_interval) => {
                if !matches!(conn.state(), State::Online) {
                    break anyhow!("Connection not online (may be aged out or evicted)");
                }
                continue;
            }
        }

        buf.clear();
        buf.reserve(MAX_OUTSIDE_MTU);

        match sock.try_read_buf(&mut buf) {
            Ok(0) => {
                break anyhow!("End of stream");
            }
            Ok(_nr) => {}
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                continue;
            }
            Err(err) => break anyhow!(err).context("TCP read error"),
        };

        let pkt = OutsidePacket::Wire(&mut buf, ConnectionType::Stream);
        if let Err(err) = conn.outside_data_received(pkt) {
            warn!("Failed to process outside data: {err}");
            if conn.handle_outside_data_error(&err).is_break() {
                break anyhow!(err).context("Outside data fatal error");
            }
        }
    };

    let _ = conn.disconnect();
    info!("Connection closed: {:?}", err);
}

async fn handle_ws_read_loop(
    sock: Arc<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
    conn_manager: Arc<ConnectionManager>,
    ws_path: &str,
) {
    let ws = match WsTcpStream::accept(sock, peer_addr, ws_path).await {
        Ok(ws) => Arc::new(ws),
        Err(err) => {
            debug!(?err, %peer_addr, "WebSocket handshake failed");
            return;
        }
    };

    let Ok(conn) =
        conn_manager.create_streaming_connection(Version::MINIMUM, local_addr, ws.clone())
    else {
        return;
    };
    drop(conn_manager);

    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
    let age_expiration_interval: Duration =
        crate::connection_manager::CONNECTION_AGE_EXPIRATION_INTERVAL
            .try_into()
            .unwrap();
    let err: anyhow::Error = loop {
        tokio::select! {
            res = ws.readable() => {
                if let Err(e) = res {
                    break anyhow!(e).context("Sock readable error");
                }
            },
            _ = tokio::time::sleep(age_expiration_interval) => {
                if !matches!(conn.state(), State::Online) {
                    break anyhow!("Connection not online (may be aged out or evicted)");
                }
                continue;
            }
        }

        buf.clear();
        buf.reserve(MAX_OUTSIDE_MTU);

        match ws.recv_buf(&mut buf) {
            IOCallbackResult::Ok(_) => {}
            IOCallbackResult::WouldBlock => continue,
            IOCallbackResult::Err(err) => break anyhow!(err).context("WebSocket read error"),
        };

        let pkt = OutsidePacket::Wire(&mut buf, ConnectionType::Stream);
        if let Err(err) = conn.outside_data_received(pkt) {
            warn!("Failed to process outside data: {err}");
            if conn.handle_outside_data_error(&err).is_break() {
                break anyhow!(err).context("Outside data fatal error");
            }
        }
    };

    let _ = conn.disconnect();
    info!("WebSocket connection closed: {:?}", err);
}

pub(crate) struct TcpServer {
    conn_manager: Arc<ConnectionManager>,
    sock: Arc<tokio::net::TcpListener>,
    proxy_protocol: bool,
    websocket: bool,
    ws_path: Arc<String>,
}

impl TcpServer {
    pub(crate) async fn new(
        conn_manager: Arc<ConnectionManager>,
        bind_address: SocketAddr,
        proxy_protocol: bool,
        sock: Option<tokio::net::TcpListener>,
        websocket: bool,
        ws_path: String,
    ) -> Result<TcpServer> {
        let sock = match sock {
            Some(s) => s,
            None => tokio::net::TcpListener::bind(bind_address).await?,
        };
        let sock = Arc::new(sock);

        Ok(Self {
            conn_manager,
            sock,
            proxy_protocol,
            websocket,
            ws_path: Arc::new(ws_path),
        })
    }
}

#[async_trait]
impl Server for TcpServer {
    async fn run(&mut self) -> Result<()> {
        info!(
            "Accepting traffic on {} (websocket={})",
            self.sock.local_addr()?,
            self.websocket
        );

        loop {
            let (sock, peer_addr) = match self.sock.accept().await {
                Ok(r) => r,
                Err(err) => {
                    warn!(?err, "Failed to accept a new connection");
                    metrics::connection_accept_failed();
                    continue;
                }
            };

            sock.set_nodelay(true)?;
            let local_addr = match SockRef::from(&sock).local_addr() {
                Ok(local_addr) => local_addr,
                Err(err) => {
                    debug!(?err, "Failed to get local addr");
                    return Err(err.into());
                }
            };
            let Some(local_addr) = local_addr.as_socket() else {
                debug!("Failed to convert local addr to socketaddr");
                return Err(anyhow!("Failed to convert local addr to socketaddr"));
            };

            tokio::spawn(handle_connection(
                sock,
                peer_addr,
                local_addr,
                self.conn_manager.clone(),
                self.proxy_protocol,
                self.websocket,
                self.ws_path.clone(),
            ));
        }
    }
}
