#[cfg(any(linux, android))]
use super::OutsideIORecvGro;
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
    #[cfg(batch_receive)]
    batch_receive_enabled: bool,
    #[cfg(any(linux, android))]
    gro_enabled: bool,
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
            #[cfg(batch_receive)]
            batch_receive_enabled: false,
            #[cfg(any(linux, android))]
            gro_enabled: false,
        })
    }

    /// Switch this socket to the GRO receive path and ask the kernel to
    /// coalesce trains of equal-size datagrams into one buffer per
    /// `recvmsg`. The receive path moves to
    /// [`OutsideIORecvGro::recv_gro_batch`] unconditionally; the
    /// `UDP_GRO` sockopt is best-effort, and on failure (kernel < 5.0)
    /// this logs and continues, with that path degrading to one wire
    /// packet per slot.
    #[cfg(any(linux, android))]
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
                Err(e) => return IOCallbackResult::Err(e),
            }
        }
    }

    /// Map the result of a UDP send syscall into an
    /// [`IOCallbackResult`], swallowing transient errors (see the
    /// per-arm comments) so the TLS socket does not enter the error
    /// state. `len` is the number of bytes the caller asked to send,
    /// reported as "sent" for the swallowed cases.
    fn map_send_result(res: std::io::Result<usize>, len: usize) -> IOCallbackResult<usize> {
        match res {
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
                IOCallbackResult::Ok(len)
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NetworkUnreachable) => {
                // This case indicates network unreachable error.
                // Possibly there is a network change at the moment.
                IOCallbackResult::Ok(len)
            }
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOBUFS)) => {
                // No buffer space available
                // UDP sockets may have this error when the system is overloaded.
                IOCallbackResult::Ok(len)
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::PermissionDenied) => {
                IOCallbackResult::Ok(len)
            }
            #[cfg(macos)]
            Err(err) if matches!(err.kind(), std::io::ErrorKind::AddrNotAvailable) => {
                // The source address is no longer valid (e.g. Switched WiFi hotspots)
                // It should eventually recover by itself after a while.
                // If the user has disconnected from the internet, keepalive should fail
                // due to missed reply (`keepalive_timeout`).
                IOCallbackResult::Ok(len)
            }
            Err(err) => {
                tracing::warn!("Outside IO Send failed: {err:?}");
                IOCallbackResult::Err(err)
            }
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

    #[cfg(any(linux, android))]
    fn as_gro(self: Arc<Self>) -> Option<Arc<dyn OutsideIORecvGro>> {
        if self.gro_enabled { Some(self) } else { None }
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
        #[cfg(unix)]
        let handle = self.sock.as_raw_fd();
        #[cfg(windows)]
        let handle = self.sock.as_raw_socket();
        OutsideSocket::Udp(handle)
    }
}

#[cfg(any(linux, android))]
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
        Self::map_send_result(self.sock.try_send_to(buf, self.peer_addr), buf.len())
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

        // `map_send_result` deliberately swallows several transient
        // errors as `Ok(len)` so TLS does not live-lock resending the
        // same record. That contract was written for a single datagram;
        // here it silently discards a whole batch, so count it.
        //
        // Detecting the swallow by "input was `Err`, output is `Ok`"
        // rather than re-listing the error kinds keeps this from drifting
        // out of sync with `map_send_result`'s arms.
        let was_err = res.is_err();
        let out = Self::map_send_result(res, total_len);
        if was_err && matches!(out, IOCallbackResult::Ok(_)) {
            // Every wire packet in the batch is `gso_size` bytes except a
            // possibly-shorter final one.
            let segments = match gso_size {
                0 => 1,
                stride => total_len.div_ceil(stride as usize) as u64,
            };
            crate::metrics::outside_gso_batch_shed(segments);
        }
        out
    }

    #[cfg(not(linux))]
    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
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
