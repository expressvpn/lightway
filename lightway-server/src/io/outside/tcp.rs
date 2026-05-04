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

    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
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

    let outside_io = Arc::new(TcpStream {
        sock: sock.clone(),
        peer_addr,
    });
    // TCP has no version indication, default to the minimum
    // supported version.
    let Ok(conn) =
        conn_manager.create_streaming_connection(Version::MINIMUM, local_addr, outside_io)
    else {
        return;
    };

    let age_expiration_interval: Duration = conn_manager.connection_age_expiration_interval();

    // We no longer need to hold this reference.
    drop(conn_manager);

    let mut buf = BytesMut::with_capacity(MAX_OUTSIDE_MTU);
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

        // Recover full capacity
        buf.clear();
        buf.reserve(MAX_OUTSIDE_MTU);

        match sock.try_read_buf(&mut buf) {
            Ok(0) => {
                // EOF
                break anyhow!("End of stream");
            }
            Ok(_nr) => {}
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                // Spuriously failed to read, keep waiting
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

    // Disconnect the session in case of TCP shutdown or other fatal failures.
    //
    // Note that it is possible, disconnect has been called in `conn.handle_outside_data_error` already
    // in case of fatal error case. It is still fine to call it again, since `disconnect`
    // call is idempotent and no-op if it is already disconnected
    //
    // But we need this disconnect in case of TCP connection shutdown
    let _ = conn.disconnect();

    info!("Connection closed: {:?}", err);
}

pub(crate) struct TcpServer {
    conn_manager: Arc<ConnectionManager>,
    sock: Arc<tokio::net::TcpListener>,
    proxy_protocol: bool,
}

impl TcpServer {
    pub(crate) async fn new(
        conn_manager: Arc<ConnectionManager>,
        bind_address: SocketAddr,
        proxy_protocol: bool,
        sock: Option<tokio::net::TcpListener>,
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
        })
    }
}

#[async_trait]
impl Server for TcpServer {
    async fn run(&mut self) -> Result<()> {
        info!("Accepting traffic on {}", self.sock.local_addr()?);

        loop {
            let (sock, peer_addr) = match self.sock.accept().await {
                Ok(r) => r,
                Err(err) => {
                    // Some of the errors which accept(2) can return
                    // <https://pubs.opengroup.org/onlinepubs/9699919799.2013edition/functions/accept.html>
                    // while never a good thing needn't necessarily be
                    // fatal to the entire server and prevent us from
                    // servicing existing connections or potentially
                    // new connections in the future.
                    warn!(?err, "Failed to accept a new connection");
                    metrics::connection_accept_failed();
                    continue;
                }
            };

            sock.set_nodelay(true)?;
            let local_addr = match SockRef::from(&sock).local_addr() {
                Ok(local_addr) => local_addr,
                Err(err) => {
                    // Since we have a bound socket this shouldn't happen.
                    debug!(?err, "Failed to get local addr");
                    return Err(err.into());
                }
            };
            let Some(local_addr) = local_addr.as_socket() else {
                // Since we only bind to IP sockets this shouldn't happen.
                debug!("Failed to convert local addr to socketaddr");
                return Err(anyhow!("Failed to convert local addr to socketaddr"));
            };

            tokio::spawn(handle_connection(
                sock,
                peer_addr,
                local_addr,
                self.conn_manager.clone(),
                self.proxy_protocol,
            ));
        }
    }
}
