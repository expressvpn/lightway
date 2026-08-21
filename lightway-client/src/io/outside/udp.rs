#[cfg(linux)]
use super::OutsideIORecvGro;
use super::{OutsideIO, OutsideSocket};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use lightway_app_utils::sockopt;
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};
#[cfg(any(ios, tvos, all(test, apple)))]
use std::sync::OnceLock;
#[cfg(apple)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
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
    /// Whether connected-send mode was requested; see
    /// [`Udp::enable_connected_send`]. Set once during setup, before the socket
    /// is shared. Apple platforms only.
    #[cfg(apple)]
    connect_requested: bool,
    /// Whether the socket is currently `connect()`-ed to `peer_addr` so that
    /// `send` can be used in place of `send_to`. Cleared by [`Udp::downgrade`]
    /// when the pinned route/source address dies; restored by
    /// [`OutsideIO::reconnect`] on the next network-change event.
    #[cfg(apple)]
    connected: AtomicBool,
    /// Callback registered via [`Udp::on_dead_socket`], fired when the
    /// connected socket turns out to be permanently dead. iOS/tvOS only
    /// (compiled into Apple test builds so the unit tests can run on macOS).
    #[cfg(any(ios, tvos, all(test, apple)))]
    dead_socket_cb: OnceLock<Arc<dyn Fn() + Send + Sync>>,
    /// Latch ensuring the dead-socket callback fires at most once per socket
    /// instance.
    #[cfg(any(ios, tvos, all(test, apple)))]
    dead: AtomicBool,
    /// Consecutive swallowed send errors, reset by a successful send; see
    /// [`Udp::note_swallowed_send`].
    swallowed_sends: AtomicU64,
    #[cfg(batch_receive)]
    batch_receive_enabled: bool,
    #[cfg(linux)]
    gro_enabled: bool,
    /// Latched `true` (for the socket's lifetime) once a `UDP_SEGMENT`
    /// send is rejected with a capability error; read via
    /// [`OutsideIOSendCallback::gso_enabled`].
    #[cfg(linux)]
    gso_broken: std::sync::atomic::AtomicBool,
}

impl Udp {
    pub async fn new(
        remote_addr: SocketAddr,
        sock: Option<UdpSocket>,
        #[cfg(all(linux, not(feature = "mobile")))] fwmark: u32,
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

        let sock = match sock {
            Some(s) => s,
            None => tokio::net::UdpSocket::bind((unspecified_ip, 0)).await?,
        };

        // Apply the firewall mark *before* the socket is used for anything, so
        // that no packet can escape unmarked and be captured by the tunnel's
        // own routes.
        #[cfg(all(linux, not(feature = "mobile")))]
        if fwmark != 0 {
            let socket = socket2::SockRef::from(&sock);
            match socket.set_mark(fwmark) {
                Ok(_) => tracing::info!("Applied firewall mark to outside socket"),
                Err(e) => tracing::warn!("Fail to set so mark on socket: {}", e),
            }
        }

        let default_ip_pmtudisc = sockopt::get_ip_mtu_discover(&sock)?;
        // Check for the socket's writable ready status, so that it can be used
        // successfuly in TLS's `OutsideIOSendCallback` callback
        sock.writable().await?;

        Ok(Self {
            sock: Arc::new(sock),
            peer_addr,
            default_ip_pmtudisc,
            #[cfg(apple)]
            connect_requested: false,
            #[cfg(apple)]
            connected: AtomicBool::new(false),
            #[cfg(any(ios, tvos, all(test, apple)))]
            dead_socket_cb: OnceLock::new(),
            #[cfg(any(ios, tvos, all(test, apple)))]
            dead: AtomicBool::new(false),
            swallowed_sends: AtomicU64::new(0),
            #[cfg(batch_receive)]
            batch_receive_enabled: false,
            #[cfg(linux)]
            gro_enabled: false,
            #[cfg(linux)]
            gso_broken: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// `connect()` the underlying socket to `peer_addr`.
    ///
    /// On a connected UDP socket the kernel resolves the route once, at connect
    /// time, so each subsequent `send` skips the per-packet route lookup that
    /// `send_to` performs.
    #[cfg(apple)]
    fn connect_socket(&self) -> std::io::Result<()> {
        socket2::SockRef::from(&self.sock).connect(&self.peer_addr.into())
    }

    /// Switch this socket to connected-send mode for throughput on Apple platforms.
    ///
    /// The cached route is bound to the current egress interface, so the caller
    /// MUST invoke [`OutsideIO::reconnect`] on every network change — otherwise
    /// a network change strands the socket on a dead route/source address.
    #[cfg(apple)]
    pub fn enable_connected_send(&mut self) -> std::io::Result<()> {
        // Requested before attempted: if this initial connect fails, a later
        // network-change reconnect can still establish the fast path.
        self.connect_requested = true;
        self.connect_socket()?;
        self.connected.store(true, Ordering::Relaxed);
        tracing::info!(
            "Outside UDP socket connected; using connected send (local address {})",
            local_addr_str(&self.sock)
        );
        Ok(())
    }

    /// Register a callback fired when the connected socket turns out to be
    /// permanently dead: on iOS an interface change can defunct the
    /// `connect()`-ed flow, after which every send on this fd fails with
    /// `EPIPE` forever. Registering a callback is what opts this socket into
    /// swallowing those sends — without one they stay on the fatal path,
    /// which is the enforcement that a recovery handler exists.
    ///
    /// The callback runs inside the send callback, under the connection
    /// lock: it must be non-blocking and must not re-enter the connection.
    /// It is invoked at most once per socket instance and is expected to
    /// arrange, elsewhere, for this socket to be replaced.
    #[cfg(any(ios, tvos, all(test, apple)))]
    pub fn on_dead_socket(&self, cb: Arc<dyn Fn() + Send + Sync>) -> std::io::Result<()> {
        self.dead_socket_cb
            .set(cb)
            .map_err(|_e| std::io::Error::other("Dead socket callback has been set already"))
    }

    /// Drop back to unconnected sends on the same fd.
    ///
    /// `send_to` on a connected UDP socket fails with `EISCONN`, so the
    /// association has to be dissolved before falling back. `disconnectx` also
    /// resets the implicitly bound local address, so subsequent sends re-select
    /// the route and source address per packet — correct on whatever network we
    /// are now on, just without the connected-send saving. The next
    /// network-change reconnect restores the fast path.
    #[cfg(apple)]
    fn downgrade(&self) {
        let pinned = local_addr_str(&self.sock);
        // Flip first so concurrent senders switch to `send_to`; a send racing
        // the dissolve gets `EISCONN`/`ENOTCONN`, which `send` swallows.
        self.connected.store(false, Ordering::Relaxed);
        match lightway_app_utils::udp_disconnect::udp_disconnect(self.sock.as_ref()) {
            Ok(()) => {}
            // NotConnected: already dissolved (e.g. a reconnect failed mid-way).
            Err(e) if matches!(e.kind(), std::io::ErrorKind::NotConnected) => {}
            Err(e) => {
                tracing::warn!("Failed to dissolve outside UDP socket association: {e}");
                return;
            }
        }
        tracing::info!(
            "Outside UDP socket (was pinned to {pinned}) downgraded to unconnected send until next network change"
        );
    }

    /// Send errors around a network change are expected and absorbed (DTLS
    /// retransmission recovers), but a sustained stream of them means the
    /// tunnel is down with no trace in the logs. Log the 1st, 2nd, 4th, ...
    /// of each consecutive run, so onset and magnitude stay visible without
    /// flooding.
    fn note_swallowed_send(&self, err: &std::io::Error) {
        let count = self.swallowed_sends.fetch_add(1, Ordering::Relaxed) + 1;
        if count.is_power_of_two() {
            tracing::debug!("Swallowing outside UDP send error ({count} consecutive): {err}");
        }
    }

    /// Switch this socket to the GRO receive path and ask the kernel to
    /// coalesce trains of equal-size datagrams into one buffer per
    /// `recvmsg`. The receive path moves to
    /// [`OutsideIORecvGro::recv_gro_batch`] unconditionally; the
    /// `UDP_GRO` sockopt is best-effort, and on failure (kernel < 5.0)
    /// this logs and continues, with that path degrading to one wire
    /// packet per slot.
    #[cfg(linux)]
    pub fn enable_gro(&mut self) {
        // Two independent optimizations are in play here, each worth
        // having on its own:
        //
        //  1. Socket-read coalescing, via the `UDP_GRO` sockopt below.
        //     Note the direction of causality: a valid UDP checksum on
        //     the peer's datagrams is necessary but *not* sufficient for
        //     the kernel to coalesce — the receiving socket must set this
        //     sockopt too, and that is what actually does the work.
        //     Measured on Linux 6.x with identical, correctly-checksummed
        //     senders: a receiver *with* the sockopt got 1 `recvmsg` of
        //     14000 bytes with the cmsg reporting seg=1400, while a
        //     receiver *without* it got 10 separate 1400-byte `recv()`
        //     calls and no coalescing.
        //  2. TUN-write coalescing, via `TcpGroTable` on the inside
        //     path, which merges segments before they are written to the
        //     TUN. This is unrelated to how the datagrams arrived.
        //
        // A peer that sends zero-checksum UDP is skipped by the kernel
        // GRO engine by design, which costs (1) but not (2) — that holds
        // for any non-conforming peer.
        //
        // So route receives through `recv_gro_batch` whenever offload is
        // requested, not only when the sockopt succeeds: that path
        // degrades to plain single-datagram slots when the kernel does
        // not coalesce (old kernel, or such a peer), and (2) still
        // applies.
        self.gro_enabled = true;
        match lightway_app_utils::sockopt::socket_enable_udp_gro(self.sock.as_ref()) {
            Ok(()) => tracing::info!("UDP GRO enabled on outside socket"),
            Err(e) => tracing::warn!(
                "UDP_GRO sockopt unavailable ({e}); using per-datagram receive with userspace TUN coalescing"
            ),
        }
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

    /// Run `f` under `try_io(READABLE)`, mapping the spurious
    /// `WouldBlock` that `try_io` may report (so the caller waits for
    /// the next readiness event) and retrying immediately when a
    /// signal interrupts the syscall.
    #[cfg(batch_receive)]
    fn try_readable_io<T>(&self, mut f: impl FnMut() -> std::io::Result<T>) -> IOCallbackResult<T> {
        loop {
            match self.sock.try_io(tokio::io::Interest::READABLE, &mut f) {
                Ok(n) => return IOCallbackResult::Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    return IOCallbackResult::WouldBlock;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                #[cfg(apple)]
                Err(e) if self.connect_requested && is_icmp_derived_err(&e) => {
                    tracing::debug!("Ignoring ICMP-derived error on connected UDP recv: {e}");
                    return IOCallbackResult::WouldBlock;
                }
                Err(e) => return IOCallbackResult::Err(e),
            }
        }
    }

    /// Map the result of the GSO `sendmsg` into an [`IOCallbackResult`],
    /// swallowing the same transient errors the per-datagram `send` path
    /// does so the TLS socket does not enter the error state. `len` is the
    /// batch's total byte count, reported as "sent" for the swallowed
    /// cases — the aggregate is treated as delivered and DTLS
    /// retransmission covers it rather than live-locking the TLS record.
    #[cfg(linux)]
    fn map_send_result(res: std::io::Result<usize>, len: usize) -> IOCallbackResult<usize> {
        match res {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            // Server may not be listening yet; swallow so DTLS retransmits
            // rather than live-locking the TLS record on repeated resends.
            Err(err) if matches!(err.kind(), std::io::ErrorKind::ConnectionRefused) => {
                IOCallbackResult::Ok(len)
            }
            // Transient around a network change.
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NetworkUnreachable) => {
                IOCallbackResult::Ok(len)
            }
            // Send buffer momentarily full under load.
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOBUFS)) => {
                IOCallbackResult::Ok(len)
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::PermissionDenied) => {
                IOCallbackResult::Ok(len)
            }
            Err(err) => {
                tracing::warn!("Outside IO GSO send failed: {err:?}");
                IOCallbackResult::Err(err)
            }
        }
    }

    /// Errno families where the egress path can't do UDP GSO at all, as
    /// opposed to a transient condition. `EIO` is the kernel refusing a
    /// `UDP_SEGMENT` send when the device lacks TX checksum offload (the
    /// dominant cause); `EINVAL`/`EOPNOTSUPP` cover other outright
    /// rejections. Transient errors (`ENOBUFS`, `ECONNREFUSED`, ...) and
    /// the sizing error `EMSGSIZE` are handled elsewhere and must not latch.
    #[cfg(linux)]
    fn is_gso_unsupported(err: &std::io::Error) -> bool {
        matches!(
            err.raw_os_error(),
            Some(libc::EIO) | Some(libc::EINVAL) | Some(libc::EOPNOTSUPP)
        )
    }

    /// Latch the GSO-unsupported flag when a send error shows the device
    /// cannot segment. Logs once, on the false→true transition only.
    #[cfg(linux)]
    fn note_gso_send_error(&self, err: &std::io::Error) {
        if Self::is_gso_unsupported(err) && !self.gso_broken.swap(true, Ordering::Release) {
            tracing::warn!(
                "kernel rejected UDP_SEGMENT send ({err}); the egress device likely lacks \
                 TX checksum offload. Disabling GSO on this socket and falling back to \
                 per-datagram sends"
            );
        }
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

    fn send_buffer_size(&self) -> Result<usize> {
        let socket = socket2::SockRef::from(&self.sock);
        Ok(socket.send_buffer_size()?)
    }
    fn recv_buffer_size(&self) -> Result<usize> {
        let socket = socket2::SockRef::from(&self.sock);
        Ok(socket.recv_buffer_size()?)
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
            #[cfg(apple)]
            Err(err) if self.connect_requested && is_icmp_derived_err(&err) => {
                tracing::debug!("Ignoring ICMP-derived error on connected UDP recv: {err}");
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

        self.try_readable_io(|| {
            batch_receive::recv_multiple(fd, bufs, lightway_core::MAX_IO_BATCH_SIZE)
        })
    }

    #[cfg(linux)]
    fn as_gro(self: Arc<Self>) -> Option<Arc<dyn OutsideIORecvGro>> {
        if self.gro_enabled { Some(self) } else { None }
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    #[cfg(apple)]
    fn reconnect(&self) {
        // Only refresh the route if connected-send mode is actually in use.
        // Checked against the request, not the current state, so a downgraded
        // socket is re-pinned once a network change lands.
        if !self.connect_requested {
            return;
        }
        // `connect()` on a connected datagram socket dissolves the old
        // association and re-runs route and source-address selection under one
        // socket lock (see soconnectlock in xnu's uipc_socket.c), so this both
        // refreshes the pinned route and re-selects the local address — on the
        // same fd and local port.
        let before = local_addr_str(&self.sock);
        match self.connect_socket() {
            Ok(()) => {
                self.connected.store(true, Ordering::Relaxed);
                tracing::debug!(
                    "Reconnected outside UDP socket after network change, local address {before} -> {}",
                    local_addr_str(&self.sock)
                );
            }
            Err(e) => {
                // Better a slow socket than a wedged one: drop to unconnected
                // sends (per-packet route lookup always resolves the current
                // network) and let a later network change restore the fast path.
                tracing::warn!("Failed to reconnect outside UDP socket, using send_to: {e}");
                self.downgrade();
            }
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

#[cfg(linux)]
impl OutsideIORecvGro for Udp {
    fn recv_gro_batch(
        &self,
        bufs: &mut [bytes::BytesMut; lightway_core::MAX_IO_BATCH_SIZE],
        gro_sizes: &mut [Option<u16>; lightway_core::MAX_IO_BATCH_SIZE],
    ) -> IOCallbackResult<usize> {
        use std::os::fd::AsRawFd;
        let fd = self.sock.as_raw_fd();
        self.try_readable_io(|| batch_receive::recv_multiple_gro(fd, bufs, gro_sizes))
    }
}

impl OutsideIOSendCallback for Udp {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        // On a connected socket the destination is already known, so `send`
        // skips the per-packet route lookup that `send_to` performs - a
        // measurable throughput win on Apple platforms. Falls back to `send_to` when the
        // socket isn't connected (mode not enabled, or downgraded after the
        // pinned route/source address died).
        #[cfg(apple)]
        let connected = self.connected.load(Ordering::Relaxed);
        #[cfg(apple)]
        let result = if connected {
            self.sock.try_send(buf)
        } else {
            self.sock.try_send_to(buf, self.peer_addr)
        };
        #[cfg(not(apple))]
        let result = self.sock.try_send_to(buf, self.peer_addr);

        match result {
            Ok(nr) => {
                self.swallowed_sends.store(0, Ordering::Relaxed);
                IOCallbackResult::Ok(nr)
            }
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
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NetworkUnreachable) => {
                // This case indicates network unreachable error.
                // Possibly there is a network change at the moment.
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOBUFS)) => {
                // No buffer space available
                // UDP sockets may have this error when the system is overloaded.
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::PermissionDenied) => {
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            #[cfg(apple)]
            Err(err) if matches!(err.kind(), std::io::ErrorKind::AddrNotAvailable) => {
                // The source address is no longer valid (e.g. Switched WiFi hotspots)
                // An unconnected socket recovers by itself: the kernel re-selects
                // the source address on every send.
                // If the user has disconnected from the internet, keepalive should fail
                // due to missed reply (`keepalive_timeout`).
                //
                // A connected socket is pinned to the dead address and will fail
                // this way forever, so drop back to unconnected sends rather than
                // waiting on a network-change event that may never come (e.g. a
                // DHCP renewal that changes the address but not the default
                // route). The next network change re-pins the fast path.
                if connected {
                    self.downgrade();
                }
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            #[cfg(apple)]
            Err(err) if connected && matches!(err.kind(), std::io::ErrorKind::HostUnreachable) => {
                // A connected socket can surface "no route to host" the moment a
                // network change tears down the cached route. The reconnect on
                // network change refreshes it; swallow so TLS does not enter an
                // error state in the meantime. Only relevant when we explicitly
                // use `send`; `send_to` should surface this error as before.
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            #[cfg(apple)]
            Err(err)
                if self.connect_requested
                    && (matches!(err.kind(), std::io::ErrorKind::NotConnected)
                        || matches!(err.raw_os_error(), Some(libc::EISCONN))) =>
            {
                // A send raced a reconnect/downgrade transition of the
                // association (`send` on a just-dissolved socket, or `send_to`
                // on a just-connected one). The next send takes the settled
                // path; DTLS retransmission covers this packet.
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            #[cfg(any(ios, tvos, all(test, apple)))]
            Err(err)
                if self.connect_requested
                    && matches!(err.kind(), std::io::ErrorKind::BrokenPipe)
                    && self.dead_socket_cb.get().is_some() =>
            {
                // iOS defuncts the connected flow on an interface change
                // (e.g. cellular -> WiFi), after which every send on this fd
                // fails with EPIPE: the fd is unrecoverable, and `send_to`
                // fails identically so downgrading would not help. Fire the
                // registered callback (once) to request a replacement socket
                // and swallow the error — DTLS retransmission covers the
                // packet and the keepalive timeout remains the liveness
                // backstop.
                if !self.dead.swap(true, Ordering::Relaxed)
                    && let Some(cb) = self.dead_socket_cb.get()
                {
                    cb();
                }
                self.note_swallowed_send(&err);
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) => {
                tracing::warn!("Outside IO Send failed: {err:?}");
                IOCallbackResult::Err(err)
            }
        }
    }

    /// Send concatenated wire packets in one `sendmsg` with a
    /// `UDP_SEGMENT` control message; the kernel splits the payload
    /// into `gso_size`-byte datagrams.
    #[cfg(linux)]
    fn send_gso(&self, bufs: &[std::io::IoSlice<'_>], gso_size: u16) -> IOCallbackResult<usize> {
        use lightway_app_utils::cmsg;
        use socket2::{MsgHdr, SockRef};
        use tokio::io::Interest;

        const CMSG_SIZE: usize = cmsg::Message::space::<u16>();

        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let peer_addr = socket2::SockAddr::from(self.peer_addr);

        let res = self.sock.try_io(Interest::WRITABLE, || {
            let sock = SockRef::from(self.sock.as_ref());

            let mut cmsg = cmsg::BufferMut::<CMSG_SIZE>::zeroed();
            let mut builder = cmsg.builder();
            builder.fill_next(libc::SOL_UDP, libc::UDP_SEGMENT, gso_size)?;

            let msghdr = MsgHdr::new()
                .with_addr(&peer_addr)
                .with_buffers(bufs)
                .with_control(cmsg.as_ref());

            sock.sendmsg(&msghdr, 0)
        });

        // Latch off on a capability error so the connection drops to the
        // per-segment fallback instead of failing here on every batch.
        if let Err(ref err) = res {
            self.note_gso_send_error(err);
        }

        // Note `map_send_result` swallows several transient errors as
        // `Ok(len)` so TLS does not live-lock resending the same record.
        // That contract was written for a single datagram; applied here
        // it reports an entire discarded batch as fully sent.
        Self::map_send_result(res, total_len)
    }

    #[cfg(not(linux))]
    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn gso_enabled(&self) -> bool {
        #[cfg(linux)]
        {
            !self.gso_broken.load(Ordering::Acquire)
        }
        // Non-Linux has no `UDP_SEGMENT`; `send_gso` is unsupported.
        #[cfg(not(linux))]
        {
            false
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

#[cfg(apple)]
fn local_addr_str(sock: &tokio::net::UdpSocket) -> String {
    sock.local_addr()
        .map_or_else(|e| e.to_string(), |a| a.to_string())
}

#[cfg(all(test, linux))]
mod linux_tests {
    use super::*;
    use std::io::Error;

    async fn make_udp() -> Udp {
        // No server is needed: these tests exercise the latch bookkeeping,
        // not an actual send. `peer_addr` just has to be a valid address.
        let peer_addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        Udp::new(peer_addr, None, 0).await.unwrap()
    }

    #[test]
    fn classifies_capability_errors() {
        for errno in [libc::EIO, libc::EINVAL, libc::EOPNOTSUPP] {
            assert!(
                Udp::is_gso_unsupported(&Error::from_raw_os_error(errno)),
                "errno {errno} should latch GSO off"
            );
        }
    }

    #[test]
    fn ignores_transient_and_sizing_errors() {
        for errno in [
            libc::ENOBUFS,
            libc::ECONNREFUSED,
            libc::ENETUNREACH,
            libc::EPERM,
            libc::EAGAIN,
            libc::EMSGSIZE,
        ] {
            assert!(
                !Udp::is_gso_unsupported(&Error::from_raw_os_error(errno)),
                "errno {errno} must not latch GSO off"
            );
        }
    }

    #[tokio::test]
    async fn latches_gso_off_on_capability_error() {
        let udp = make_udp().await;
        // Enabled by default.
        assert!(OutsideIOSendCallback::gso_enabled(&udp));

        // A capability error latches it off for good.
        udp.note_gso_send_error(&Error::from_raw_os_error(libc::EIO));
        assert!(!OutsideIOSendCallback::gso_enabled(&udp));

        // Idempotent: staying off after a repeat.
        udp.note_gso_send_error(&Error::from_raw_os_error(libc::EIO));
        assert!(!OutsideIOSendCallback::gso_enabled(&udp));
    }

    #[tokio::test]
    async fn transient_error_keeps_gso_enabled() {
        let udp = make_udp().await;
        udp.note_gso_send_error(&Error::from_raw_os_error(libc::ENOBUFS));
        assert!(OutsideIOSendCallback::gso_enabled(&udp));
    }
}

/// ICMP errors (port/host/net unreachable) are delivered asynchronously to a
/// *connected* UDP socket and surface on the next syscall; an unconnected
/// socket never sees them. They are transient from the tunnel's point of view
/// (server restart, router mid-transition) and DTLS retransmission recovers
/// once the peer is reachable again, so they must not tear the connection down.
#[cfg(apple)]
fn is_icmp_derived_err(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::HostUnreachable
            | std::io::ErrorKind::NetworkUnreachable
    )
}

#[cfg(all(test, apple))]
mod tests {
    use super::*;
    use std::time::Duration;

    async fn recv_str(peer: &UdpSocket) -> (String, SocketAddr) {
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buf))
            .await
            .expect("timed out waiting for datagram")
            .expect("peer recv failed");
        (String::from_utf8_lossy(&buf[..n]).into_owned(), from)
    }

    #[tokio::test]
    async fn connected_send_and_reconnect_keep_fd_and_port() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mut udp = Udp::new(peer_addr, None).await.unwrap();
        udp.enable_connected_send().unwrap();
        assert!(udp.connected.load(Ordering::Relaxed));
        let local_before = udp.sock.local_addr().unwrap();

        assert!(matches!(
            OutsideIOSendCallback::send(&udp, b"one"),
            IOCallbackResult::Ok(3)
        ));
        let (msg, from) = recv_str(&peer).await;
        assert_eq!(msg, "one");
        assert_eq!(from.port(), local_before.port());

        // Reconnect re-runs route/source selection on the same fd: the local
        // port must survive and the fast path must keep working.
        OutsideIO::reconnect(&udp);
        assert!(udp.connected.load(Ordering::Relaxed));
        assert_eq!(udp.sock.local_addr().unwrap().port(), local_before.port());

        assert!(matches!(
            OutsideIOSendCallback::send(&udp, b"two"),
            IOCallbackResult::Ok(3)
        ));
        let (msg, from) = recv_str(&peer).await;
        assert_eq!(msg, "two");
        assert_eq!(from.port(), local_before.port());
    }

    #[tokio::test]
    async fn downgrade_falls_back_to_unconnected_send_and_reconnect_restores() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mut udp = Udp::new(peer_addr, None).await.unwrap();
        udp.enable_connected_send().unwrap();
        let port = udp.sock.local_addr().unwrap().port();

        // Simulate the send path detecting a dead pin (EADDRNOTAVAIL).
        udp.downgrade();
        assert!(!udp.connected.load(Ordering::Relaxed));

        // Sends must keep flowing via `send_to` on the same fd/port.
        assert!(matches!(
            OutsideIOSendCallback::send(&udp, b"slow"),
            IOCallbackResult::Ok(4)
        ));
        let (msg, from) = recv_str(&peer).await;
        assert_eq!(msg, "slow");
        assert_eq!(from.port(), port);

        // The next network-change reconnect restores the fast path.
        OutsideIO::reconnect(&udp);
        assert!(udp.connected.load(Ordering::Relaxed));
        assert!(matches!(
            OutsideIOSendCallback::send(&udp, b"fast"),
            IOCallbackResult::Ok(4)
        ));
        let (msg, from) = recv_str(&peer).await;
        assert_eq!(msg, "fast");
        assert_eq!(from.port(), port);
    }

    #[tokio::test]
    async fn reconnect_is_noop_when_not_requested() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let udp = Udp::new(peer_addr, None).await.unwrap();
        OutsideIO::reconnect(&udp);
        assert!(!udp.connected.load(Ordering::Relaxed));

        // Still sends via `send_to`.
        assert!(matches!(
            OutsideIOSendCallback::send(&udp, b"plain"),
            IOCallbackResult::Ok(5)
        ));
        let (msg, _) = recv_str(&peer).await;
        assert_eq!(msg, "plain");
    }

    /// `shutdown(SHUT_WR)` on a connected UDP socket makes Darwin fail every
    /// subsequent `send` with EPIPE — the same permanent failure signature as
    /// a defunct flow after an interface change.
    fn shutdown_write(sock: &UdpSocket) {
        socket2::SockRef::from(sock)
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown(SHUT_WR) failed");
    }

    #[tokio::test]
    async fn dead_socket_hook_swallows_epipe_and_fires_once() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mut udp = Udp::new(peer_addr, None).await.unwrap();
        udp.enable_connected_send().unwrap();

        let fired = Arc::new(AtomicU64::new(0));
        let fired_by_cb = fired.clone();
        udp.on_dead_socket(Arc::new(move || {
            fired_by_cb.fetch_add(1, Ordering::Relaxed);
        }))
        .expect("first registration must succeed");

        shutdown_write(&udp.sock);

        // Every failing send must be swallowed (fake success, DTLS
        // retransmission covers the packets), and the callback must fire
        // exactly once no matter how many sends fail.
        for _ in 0..3 {
            assert!(matches!(
                OutsideIOSendCallback::send(&udp, b"data"),
                IOCallbackResult::Ok(4)
            ));
        }
        assert_eq!(fired.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dead_socket_hook_registration_is_once_only() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let udp = Udp::new(peer_addr, None).await.unwrap();
        assert!(udp.on_dead_socket(Arc::new(|| {})).is_ok());
        assert!(udp.on_dead_socket(Arc::new(|| {})).is_err());
    }

    #[tokio::test]
    async fn epipe_without_dead_socket_hook_stays_fatal() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mut udp = Udp::new(peer_addr, None).await.unwrap();
        udp.enable_connected_send().unwrap();

        shutdown_write(&udp.sock);

        // Without a registered recovery handler there is nothing to replace
        // the dead socket: swallowing would turn a hard failure into a silent
        // black hole, so the error must stay on the fatal path.
        match OutsideIOSendCallback::send(&udp, b"data") {
            IOCallbackResult::Err(e) => {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe)
            }
            IOCallbackResult::Ok(_) => panic!("expected Err(BrokenPipe), got Ok"),
            IOCallbackResult::WouldBlock => {
                panic!("expected Err(BrokenPipe), got WouldBlock")
            }
        }
    }

    #[tokio::test]
    async fn icmp_unreachable_is_not_fatal_on_connected_recv() {
        // Bind then drop a peer so the port is closed; sends to it generate
        // ICMP port unreachable, which a connected socket surfaces as
        // ECONNREFUSED on a following send or recv.
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        drop(peer);

        let mut udp = Udp::new(peer_addr, None).await.unwrap();
        udp.enable_connected_send().unwrap();

        let mut buf = bytes::BytesMut::with_capacity(2048);
        for _ in 0..3 {
            // The send-side surfacing is swallowed (ConnectionRefused arm).
            assert!(!matches!(
                OutsideIOSendCallback::send(&udp, b"ping"),
                IOCallbackResult::Err(_)
            ));
            tokio::time::sleep(Duration::from_millis(10)).await;
            // The recv side must map it to WouldBlock, never a fatal Err that
            // would tear the connection down.
            assert!(!matches!(udp.recv_buf(&mut buf), IOCallbackResult::Err(_)));
        }
    }
}
