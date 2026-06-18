use super::{OutsideIO, OutsideSocket};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use lightway_app_utils::sockopt;
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;

#[cfg(batch_receive)]
mod batch_receive;

pub struct Udp {
    sock: Arc<tokio::net::UdpSocket>,
    peer_addr: SocketAddr,
    default_ip_pmtudisc: sockopt::IpPmtudisc,
    /// Whether the socket has been `connect()`-ed to `peer_addr` so that `send`
    /// can be used in place of `send_to`. macOS only; see
    /// [`Udp::enable_connected_send`].
    #[cfg(macos)]
    connected: bool,
    #[cfg(batch_receive)]
    batch_receive_enabled: bool,
}

impl Udp {
    pub async fn new(remote_addr: SocketAddr, sock: Option<UdpSocket>) -> Result<Self> {
        let peer_addr = tokio::net::lookup_host(remote_addr)
            .await?
            .next()
            .ok_or(anyhow!("Lookup of {remote_addr} results in no address"))?;

        let unspecified_ip = if peer_addr.ip().is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };

        let sock = match sock {
            Some(s) => s,
            None => tokio::net::UdpSocket::bind((unspecified_ip, 0)).await?,
        };
        let default_ip_pmtudisc = sockopt::get_ip_mtu_discover(&sock)?;
        // Check for the socket's writable ready status, so that it can be used
        // successfuly in TLS's `OutsideIOSendCallback` callback
        sock.writable().await?;

        Ok(Self {
            sock: Arc::new(sock),
            peer_addr,
            default_ip_pmtudisc,
            #[cfg(macos)]
            connected: false,
            #[cfg(batch_receive)]
            batch_receive_enabled: false,
        })
    }

    /// `connect()` the underlying socket to `peer_addr`.
    ///
    /// On a connected UDP socket the kernel resolves the route once, at connect
    /// time, so each subsequent `send` skips the per-packet route lookup that
    /// `send_to` performs.
    #[cfg(macos)]
    fn connect_socket(&self) -> std::io::Result<()> {
        socket2::SockRef::from(&self.sock).connect(&self.peer_addr.into())
    }

    /// Switch this socket to connected-send mode for upload throughput on macOS.
    ///
    /// The cached route is bound to the current egress interface, so the caller
    /// MUST invoke [`OutsideIO::reconnect`] on every network change — otherwise
    /// a network change strands the socket on a dead route/source address.
    #[cfg(macos)]
    pub fn enable_connected_send(&mut self) -> std::io::Result<()> {
        self.connect_socket()?;
        self.connected = true;
        tracing::info!("Outside UDP socket connected; using connected send");
        Ok(())
    }

    #[cfg(batch_receive)]
    pub fn enable_batch_receive(&mut self) {
        #[cfg(apple)]
        if !lightway_app_utils::recvmsg_x::is_batch_receive_available() {
            tracing::warn!(
                "batch receive function is not available on this system, batch receive disabled"
            );
            return;
        }
        tracing::info!("Using batch receiver");
        self.batch_receive_enabled = true;
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

#[async_trait]
impl OutsideIO for Udp {
    fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.sock);
        if let Err(e) = socket.set_send_buffer_size(size) {
            tracing::warn!("Failed to set UDP send buffer size to {size}: {e}");
        }
        Ok(())
    }
    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.sock);
        if let Err(e) = socket.set_recv_buffer_size(size) {
            tracing::warn!("Failed to set UDP recv buffer size to {size}: {e}");
        }
        Ok(())
    }

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        let r = self.sock.ready(interest).await?;
        Ok(r)
    }

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize> {
        match self.sock.try_recv_buf(buf) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    #[cfg(batch_receive)]
    /// If the config explicitly turned off batch receive, it will just run regular `recv_from` function.
    fn recv_bufs(
        &self,
        bufs: &mut [bytes::BytesMut; lightway_core::MAX_IO_BATCH_SIZE],
    ) -> IOCallbackResult<usize> {
        if !self.batch_receive_enabled {
            return match self.recv_buf(&mut bufs[0]) {
                IOCallbackResult::Ok(_size) => IOCallbackResult::Ok(1),
                others => others,
            };
        }

        use std::os::fd::AsRawFd;

        let fd = self.sock.as_raw_fd();

        loop {
            match self.sock.try_io(tokio::io::Interest::READABLE, || {
                batch_receive::recv_multiple(fd, bufs, lightway_core::MAX_IO_BATCH_SIZE)
            }) {
                Ok(n) => return IOCallbackResult::Ok(n),
                // try_io may return WouldBlock even if the socket isn't actually
                // readable. Break with 0 to wait for another readable event emitted.
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return IOCallbackResult::WouldBlock;
                }
                // Interrupted means the syscall was interrupted by a signal and can be
                // retried immediately without waiting for another readable event.
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return IOCallbackResult::Err(e),
            }
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    #[cfg(macos)]
    fn reconnect(&self) {
        // Only refresh the route if connected-send mode is actually in use.
        if !self.connected {
            return;
        }
        match self.connect_socket() {
            Ok(()) => tracing::debug!("Reconnected outside UDP socket after network change"),
            Err(e) => tracing::warn!("Failed to reconnect outside UDP socket: {e}"),
        }
    }

    fn socket(&self) -> OutsideSocket {
        #[cfg(unix)]
        use std::os::fd::AsRawFd;
        #[cfg(windows)]
        use std::os::windows::io::AsRawSocket;
        #[cfg(unix)]
        let handle = self.sock.as_raw_fd();
        #[cfg(windows)]
        let handle = self.sock.as_raw_socket();
        OutsideSocket::Udp(handle)
    }
}

impl OutsideIOSendCallback for Udp {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        // On a connected socket the destination is already known, so `send`
        // skips the per-packet route lookup that `send_to` performs - a
        // measurable upload throughput win on macOS. Falls back to `send_to`
        // when the socket isn't connected (e.g. no network change monitoring to
        // refresh the cached route after a network change).
        #[cfg(macos)]
        let result = if self.connected {
            self.sock.try_send(buf)
        } else {
            self.sock.try_send_to(buf, self.peer_addr)
        };
        #[cfg(not(macos))]
        let result = self.sock.try_send_to(buf, self.peer_addr);

        match result {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::ConnectionRefused) => {
                // Possibly the server isn't listening (yet).
                //
                // Swallow the error so the TLS socket does not
                // enter the error state, and DTLS would handles the retransmission as well.
                //
                // This way we can continue if/when the server shows up.
                //
                // Returning the number of bytes requested to be sent to mock
                // that the send is successful.
                // Otherwise, TLS perceives that no data is sent and try
                // to send the same data again, creating a live-lock until
                // the network is reachable.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NetworkUnreachable) => {
                // This case indicates network unreachable error.
                // Possibly there is a network change at the moment.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOBUFS)) => {
                // No buffer space available
                // UDP sockets may have this error when the system is overloaded.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::PermissionDenied) => {
                IOCallbackResult::Ok(buf.len())
            }
            #[cfg(macos)]
            Err(err) if matches!(err.kind(), std::io::ErrorKind::AddrNotAvailable) => {
                // The source address is no longer valid (e.g. Switched WiFi hotspots)
                // It should eventually recover by itself after a while.
                // If the user has disconnected from the internet, keepalive should fail
                // due to missed reply (`keepalive_timeout`).
                IOCallbackResult::Ok(buf.len())
            }
            #[cfg(macos)]
            Err(err)
                if self.connected && matches!(err.kind(), std::io::ErrorKind::HostUnreachable) =>
            {
                // A connected socket can surface "no route to host" the moment a
                // network change tears down the cached route. The reconnect on
                // network change refreshes it; swallow so TLS does not enter an
                // error state in the meantime. Only relevant when we explicitly
                // use `send`; `send_to` should surface this error as before.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) => {
                tracing::warn!("Outside IO Send failed: {err:?}");
                IOCallbackResult::Err(err)
            }
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(self.sock.as_ref(), sockopt::IpPmtudisc::Probe)
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(self.sock.as_ref(), self.default_ip_pmtudisc)
    }
}
