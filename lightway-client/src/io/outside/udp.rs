use super::{OutsideIO, OutsideSocket};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use lightway_app_utils::sockopt;
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, RwLock},
};
use tokio::net::UdpSocket;
use tokio::sync::Notify;

#[cfg(batch_receive)]
mod batch_receive;

pub struct Udp {
    /// The live socket. Held behind interior mutability so that
    /// [`Udp::reconnect`] can swap in a freshly bound + connected socket after a
    /// network change while the [`crate::outside_io_task`] reader keeps its same
    /// `Arc<dyn OutsideIO>`. Reads on the hot path clone the `Arc` (a lock-free
    /// atomic bump under an uncontended read lock); swaps are rare.
    sock: RwLock<Arc<UdpSocket>>,
    peer_addr: SocketAddr,
    default_ip_pmtudisc: sockopt::IpPmtudisc,
    /// Whether the socket has been `connect()`ed to `peer_addr`. When set, sends
    /// use `send()` (no per-packet destination) and the socket is re-established
    /// on a network change.
    connected: bool,
    /// True when we bound the socket ourselves (and therefore own its local
    /// binding). False when an already-bound socket was injected by an embedder
    /// (mobile), in which case `reconnect()` re-associates via `connect()`
    /// rather than rebinding a socket we do not own.
    owns_socket: bool,
    /// Wakes the reader loop parked in [`Udp::poll`] after `reconnect()` swaps
    /// the inner socket, so the next iteration re-polls the fresh socket instead
    /// of remaining parked on the stale one.
    reconnect_notify: Notify,
    #[cfg(batch_receive)]
    batch_receive_enabled: bool,
}

impl Udp {
    /// Create the outside UDP IO.
    ///
    /// `connect` requests that the socket be `connect()`ed to the resolved peer
    /// address. Connecting is a best-effort performance optimisation: on failure
    /// we log and continue unconnected rather than failing the connection.
    pub async fn new(
        remote_addr: SocketAddr,
        sock: Option<UdpSocket>,
        connect: bool,
    ) -> Result<Self> {
        let peer_addr = tokio::net::lookup_host(remote_addr)
            .await?
            .next()
            .ok_or(anyhow!("Lookup of {remote_addr} results in no address"))?;

        let unspecified_ip = if peer_addr.ip().is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };

        // Whether we bound the socket ourselves (own the binding) or adopted an
        // injected one.
        let owns_socket = sock.is_none();
        let sock = match sock {
            Some(s) => s,
            None => tokio::net::UdpSocket::bind((unspecified_ip, 0)).await?,
        };
        let default_ip_pmtudisc = sockopt::get_ip_mtu_discover(&sock)?;

        // Connect (best-effort) before checking writability so that a connected
        // socket is fully associated with the peer once returned.
        let mut connected = false;
        if connect {
            match sock.connect(peer_addr).await {
                Ok(()) => {
                    connected = true;
                    tracing::info!("Connected outside UDP socket to {peer_addr}");
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to connect outside UDP socket to {peer_addr}, \
                         continuing unconnected: {e}"
                    );
                }
            }
        }

        // Check for the socket's writable ready status, so that it can be used
        // successfuly in TLS's `OutsideIOSendCallback` callback
        sock.writable().await?;

        Ok(Self {
            sock: RwLock::new(Arc::new(sock)),
            peer_addr,
            default_ip_pmtudisc,
            connected,
            owns_socket,
            reconnect_notify: Notify::new(),
            #[cfg(batch_receive)]
            batch_receive_enabled: false,
        })
    }

    /// The currently active socket.
    fn current_sock(&self) -> Arc<UdpSocket> {
        self.sock.read().unwrap().clone()
    }

    fn set_sock(&self, sock: Arc<UdpSocket>) {
        *self.sock.write().unwrap() = sock;
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
        let sock = self.current_sock();
        let socket = socket2::SockRef::from(sock.as_ref());
        if let Err(e) = socket.set_send_buffer_size(size) {
            tracing::warn!("Failed to set UDP send buffer size to {size}: {e}");
        }
        Ok(())
    }
    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let sock = self.current_sock();
        let socket = socket2::SockRef::from(sock.as_ref());
        if let Err(e) = socket.set_recv_buffer_size(size) {
            tracing::warn!("Failed to set UDP recv buffer size to {size}: {e}");
        }
        Ok(())
    }

    fn send_buffer_size(&self) -> Result<usize> {
        let sock = self.current_sock();
        let socket = socket2::SockRef::from(sock.as_ref());
        Ok(socket.send_buffer_size()?)
    }
    fn recv_buffer_size(&self) -> Result<usize> {
        let sock = self.current_sock();
        let socket = socket2::SockRef::from(sock.as_ref());
        Ok(socket.recv_buffer_size()?)
    }

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        let sock = self.current_sock();
        if self.connected {
            // Race the socket readiness against a reconnect notification. If
            // `reconnect()` swaps the inner socket while we are parked here, the
            // old socket may never become readable again (its local binding /
            // route went stale on the network change). Returning with no
            // readiness makes the reader loop re-poll and pick up the fresh
            // socket on its next iteration.
            tokio::select! {
                r = sock.ready(interest) => Ok(r?),
                _ = self.reconnect_notify.notified() => Ok(tokio::io::Ready::EMPTY),
            }
        } else {
            Ok(sock.ready(interest).await?)
        }
    }

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize> {
        match self.current_sock().try_recv_buf(buf) {
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

        let sock = self.current_sock();
        let fd = sock.as_raw_fd();

        loop {
            match sock.try_io(tokio::io::Interest::READABLE, || {
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

    /// Re-establish the connected socket after a network change.
    ///
    /// The peer (server) address is fixed; the problem a network change creates
    /// is that the *local* interface/route pinned at `connect()` time goes
    /// stale. An unconnected socket tolerates this (route is looked up per send),
    /// but a connected one does not.
    ///
    /// For a socket we own we **rebind**: bind a fresh socket on the now-current
    /// default route, reapply the send/recv buffer sizes and IP_MTU_DISCOVER
    /// setting captured from the old socket, `connect()` it, and swap it in. This
    /// is the robust option: a bare `connect()` re-association can leave a stale
    /// *local* binding in place, whereas a rebind picks the current default
    /// source address. The tradeoff is that the socket's fd changes; on desktop
    /// this is fine because routes are keyed on the server IP, not the fd.
    ///
    /// For an injected socket (mobile/embedding) we do not own the binding, so we
    /// only re-associate via `connect()` on the same fd, keeping the embedder's
    /// fd valid.
    ///
    /// No-op for an unconnected socket (nothing is pinned).
    async fn reconnect(&self) -> Result<()> {
        if !self.connected {
            return Ok(());
        }

        let old = self.current_sock();

        if self.owns_socket {
            let unspecified_ip = if self.peer_addr.ip().is_ipv6() {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            };
            let new_sock = UdpSocket::bind((unspecified_ip, 0)).await?;

            // Reapply the sockopts the old socket carried so throughput and PMTUD
            // behaviour survive the rebind.
            {
                let old_ref = socket2::SockRef::from(old.as_ref());
                let new_ref = socket2::SockRef::from(&new_sock);
                if let Ok(sz) = old_ref.send_buffer_size() {
                    let _ = new_ref.set_send_buffer_size(sz);
                }
                if let Ok(sz) = old_ref.recv_buffer_size() {
                    let _ = new_ref.set_recv_buffer_size(sz);
                }
            }
            if let Ok(pmtu) = sockopt::get_ip_mtu_discover(old.as_ref()) {
                let _ = sockopt::set_ip_mtu_discover(&new_sock, pmtu);
            }

            new_sock.connect(self.peer_addr).await?;
            new_sock.writable().await?;

            self.set_sock(Arc::new(new_sock));
            tracing::info!(
                "Rebound and reconnected outside UDP socket to {} after network change",
                self.peer_addr
            );
        } else {
            // We do not own the injected socket's binding; re-associate in place.
            old.connect(self.peer_addr).await?;
            tracing::info!(
                "Re-connected injected outside UDP socket to {} after network change",
                self.peer_addr
            );
        }

        // Wake the reader parked on the old socket so it re-polls the new one.
        self.reconnect_notify.notify_one();
        Ok(())
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    fn socket(&self) -> OutsideSocket {
        #[cfg(unix)]
        use std::os::fd::AsRawFd;
        #[cfg(windows)]
        use std::os::windows::io::AsRawSocket;
        let sock = self.current_sock();
        #[cfg(unix)]
        let handle = sock.as_raw_fd();
        #[cfg(windows)]
        let handle = sock.as_raw_socket();
        OutsideSocket::Udp(handle)
    }
}

impl OutsideIOSendCallback for Udp {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        let sock = self.current_sock();
        // A connected socket sends with `send()` (no per-packet destination),
        // which is the whole point of the optimisation. An unconnected one keeps
        // the explicit destination.
        let result = if self.connected {
            sock.try_send(buf)
        } else {
            sock.try_send_to(buf, self.peer_addr)
        };
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
            Err(err) => {
                tracing::warn!("Outside IO Send failed: {err:?}");
                IOCallbackResult::Err(err)
            }
        }
    }

    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(self.current_sock().as_ref(), sockopt::IpPmtudisc::Probe)
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(self.current_sock().as_ref(), self.default_ip_pmtudisc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use tokio::io::Interest;

    /// A loopback UDP peer standing in for the server.
    async fn fake_peer() -> (UdpSocket, SocketAddr) {
        let sock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = sock.local_addr().unwrap();
        (sock, addr)
    }

    /// Receive one datagram from `udp`, polling until data is available.
    async fn recv_one(udp: &Udp) -> Vec<u8> {
        loop {
            udp.poll(Interest::READABLE).await.unwrap();
            let mut buf = BytesMut::with_capacity(2048);
            match udp.recv_buf(&mut buf) {
                IOCallbackResult::Ok(n) => return buf[..n].to_vec(),
                IOCallbackResult::WouldBlock => continue,
                IOCallbackResult::Err(e) => panic!("recv_buf error: {e:?}"),
            }
        }
    }

    fn send(udp: &Udp, payload: &[u8]) {
        match OutsideIOSendCallback::send(udp, payload) {
            IOCallbackResult::Ok(n) => assert_eq!(n, payload.len()),
            other => panic!("unexpected send result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn connected_send_and_recv() {
        let (peer, peer_addr) = fake_peer().await;
        let udp = Udp::new(peer_addr, None, true).await.unwrap();
        assert!(udp.connected);
        assert!(udp.owns_socket);

        send(&udp, b"ping");
        let mut rbuf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..n], b"ping");

        peer.send_to(b"pong", from).await.unwrap();
        assert_eq!(recv_one(&udp).await, b"pong");
    }

    #[tokio::test]
    async fn unconnected_send_and_recv() {
        let (peer, peer_addr) = fake_peer().await;
        let udp = Udp::new(peer_addr, None, false).await.unwrap();
        assert!(!udp.connected);

        send(&udp, b"ping");
        let mut rbuf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..n], b"ping");

        peer.send_to(b"pong", from).await.unwrap();
        assert_eq!(recv_one(&udp).await, b"pong");
    }

    #[tokio::test]
    async fn reconnect_rebinds_and_still_works() {
        let (peer, peer_addr) = fake_peer().await;
        let udp = Udp::new(peer_addr, None, true).await.unwrap();

        // Prove it works before reconnect.
        send(&udp, b"before");
        let mut rbuf = [0u8; 64];
        let (n, _from) = peer.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..n], b"before");

        let old = udp.socket().raw_handle();
        udp.reconnect().await.unwrap();
        // Rebind should have produced a fresh socket (new fd) for an owned socket.
        assert_ne!(udp.socket().raw_handle(), old);

        // Still sends and receives after the rebind. The peer must reply to the
        // new local address, so read `from` fresh.
        send(&udp, b"after");
        let (n, from) = peer.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..n], b"after");
        peer.send_to(b"reply", from).await.unwrap();
        assert_eq!(recv_one(&udp).await, b"reply");
    }

    #[tokio::test]
    async fn reconnect_on_unconnected_is_noop() {
        let (_peer, peer_addr) = fake_peer().await;
        let udp = Udp::new(peer_addr, None, false).await.unwrap();
        let fd = udp.socket().raw_handle();
        udp.reconnect().await.unwrap();
        // Unconnected reconnect must not touch the socket.
        assert_eq!(udp.socket().raw_handle(), fd);
    }

    #[tokio::test]
    async fn reconnect_injected_socket_reconnects_in_place() {
        let (peer, peer_addr) = fake_peer().await;
        let injected = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let udp = Udp::new(peer_addr, Some(injected), true).await.unwrap();
        assert!(udp.connected);
        assert!(!udp.owns_socket);

        let fd = udp.socket().raw_handle();
        udp.reconnect().await.unwrap();
        // Injected sockets are re-associated in place; the fd must be preserved.
        assert_eq!(udp.socket().raw_handle(), fd);

        send(&udp, b"hi");
        let mut rbuf = [0u8; 64];
        let (n, _from) = peer.recv_from(&mut rbuf).await.unwrap();
        assert_eq!(&rbuf[..n], b"hi");
    }
}
