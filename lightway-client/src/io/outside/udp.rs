#[cfg(linux)]
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
    #[cfg(linux)]
    gro_enabled: bool,
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
            #[cfg(batch_receive)]
            batch_receive_enabled: false,
            #[cfg(linux)]
            gro_enabled: false,
        })
    }

    /// Enable UDP GRO on the socket so the kernel coalesces trains of
    /// equal-size datagrams into one buffer per `recvmsg`. On failure
    /// (kernel < 5.0) logs and leaves the per-packet receive path in
    /// place — [`OutsideIO::as_gro`] will report the capability as
    /// absent.
    #[cfg(linux)]
    pub fn enable_gro(&mut self) {
        // Route receives through `recv_gro` whenever offload is
        // requested — not only when the sockopt succeeds. `recv_gro`
        // degrades to a plain single-datagram `recvmsg` when the
        // kernel does not coalesce (old kernel, or a server that sends
        // zero-checksum UDP, which the kernel GRO engine skips by
        // design), and userspace TUN-side coalescing still applies in
        // that case. The `UDP_GRO` sockopt is a best-effort bonus that
        // additionally coalesces on the socket read when the server's
        // datagrams carry a checksum.
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

    /// Map the result of a UDP send syscall into an
    /// [`IOCallbackResult`], swallowing transient errors (see the
    /// per-arm comments) so the TLS socket does not enter the error
    /// state. `len` is the number of bytes the caller asked to send,
    /// reported as "sent" for the swallowed cases.
    fn map_send_result(&self, res: std::io::Result<usize>, len: usize) -> IOCallbackResult<usize> {
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
    #[allow(unsafe_code)]
    fn recv_gro(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<(usize, Option<u16>)> {
        use lightway_app_utils::cmsg;
        use socket2::{MaybeUninitSlice, MsgHdrMut, SockRef};
        use tokio::io::Interest;

        // The kernel reports the coalesced segment size as one
        // `UDP_GRO` control message carrying a C int.
        const CONTROL_SIZE: usize = cmsg::Message::space::<libc::c_int>();

        let res = self.sock.try_io(Interest::READABLE, || {
            let sock = SockRef::from(self.sock.as_ref());

            let mut control = cmsg::Buffer::<CONTROL_SIZE>::new();
            // Scope the msghdr so its borrow of `control` ends before
            // the control messages are parsed below.
            let (n, control_len) = {
                let mut data = [MaybeUninitSlice::new(buf.spare_capacity_mut())];
                let mut msghdr = MsgHdrMut::new()
                    .with_buffers(&mut data)
                    .with_control(control.spare_capacity_mut());

                let n = sock.recvmsg(&mut msghdr, 0)?;
                (n, msghdr.control_len())
            };

            // SAFETY: the kernel initialized `control_len` bytes of
            // the control buffer.
            let gro_size = unsafe { control.iter(control_len as cmsg::LibcControlLen) }
                .find_map(|m| match m {
                    cmsg::Message::UdpGroSegments(s) => Some(s),
                    _ => None,
                });

            Ok((n, gro_size))
        });

        match res {
            Ok((n, gro_size)) => {
                // SAFETY: recvmsg wrote exactly `n` initialized bytes
                // into the spare capacity advertised above.
                unsafe { buf.set_len(buf.len() + n) };
                IOCallbackResult::Ok((n, gro_size))
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }
}

impl OutsideIOSendCallback for Udp {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        self.map_send_result(self.sock.try_send_to(buf, self.peer_addr), buf.len())
    }

    /// Send concatenated wire packets in one `sendmsg` with a
    /// `UDP_SEGMENT` control message; the kernel splits the payload
    /// into `gso_size`-byte datagrams.
    #[cfg(target_os = "linux")]
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

        self.map_send_result(res, total_len)
    }

    #[cfg(not(target_os = "linux"))]
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
