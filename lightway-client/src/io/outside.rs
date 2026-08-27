pub mod tcp;
pub mod udp;

pub use tcp::Tcp;
pub use udp::Udp;

use anyhow::Result;
use async_trait::async_trait;
#[cfg(batch_receive)]
use lightway_core::MAX_IO_BATCH_SIZE;
use lightway_core::{IOCallbackResult, OutsideIOSendCallbackArg};
use std::{net::SocketAddr, sync::Arc};

/// Platform-agnostic OS socket handle.
/// `RawFd` (i32) on Unix, `RawSocket` (u64) on Windows.
#[cfg(unix)]
pub type RawSocketHandle = std::os::fd::RawFd;
#[cfg(windows)]
pub type RawSocketHandle = std::os::windows::io::RawSocket;

/// The underlying outside socket, tagged with its transport type.
/// Lets callers distinguish UDP from TCP without peeking at the handle.
#[derive(Debug, Clone, Copy)]
pub enum OutsideSocket {
    Udp(RawSocketHandle),
    Tcp(RawSocketHandle),
}

impl OutsideSocket {
    pub fn raw_handle(&self) -> RawSocketHandle {
        match self {
            Self::Udp(h) | Self::Tcp(h) => *h,
        }
    }
}

#[async_trait]
pub trait OutsideIO: Sync + Send {
    fn set_send_buffer_size(&self, size: usize) -> Result<()>;
    fn set_recv_buffer_size(&self, size: usize) -> Result<()>;

    fn send_buffer_size(&self) -> Result<usize>;
    fn recv_buffer_size(&self) -> Result<usize>;

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready>;

    /// Receive a single packet into `buf`. Returns how many bytes were read.
    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize>;

    /// Receive packets into `bufs`, filling up to `bufs.len()` entries.
    /// Returns how many buffers were actually written (always `>= 1` on `Ok`).
    ///
    /// Caller must reserve spare capacity ≥ `mtu` on every given buffer.
    ///
    /// The default implementation reads a single packet into `bufs[0]` and is
    /// appropriate for stream transports (e.g. TCP) or UDP without batch support.
    /// Transports with a native batch-receive syscall should override this.
    #[cfg(batch_receive)]
    fn recv_bufs(
        &self,
        bufs: &mut [bytes::BytesMut; MAX_IO_BATCH_SIZE],
    ) -> IOCallbackResult<usize> {
        match self.recv_buf(&mut bufs[0]) {
            IOCallbackResult::Ok(_size) => IOCallbackResult::Ok(1),
            others => others,
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg;

    fn peer_addr(&self) -> SocketAddr;

    /// Re-establish the socket's connected route after a network change.
    ///
    /// On Apple and Linux desktop the outside UDP socket may be `connect()`-ed
    /// so each send can skip the per-packet route lookup. When the network
    /// changes the cached route and bound source address go stale, so the
    /// association has to be refreshed by re-`connect()`ing. On Linux this
    /// also flushes the route cached by `IP_UNICAST_IF` at the original
    /// `connect()` time, which `setsockopt` alone does not update.
    /// Default is a no-op for transports that don't use a connected socket.
    #[cfg(any(apple, all(linux, not(feature = "mobile"))))]
    fn reconnect(&self) {}

    /// Re-pin the socket's egress interface after a network change.
    ///
    /// On Linux and Windows the outside socket is pinned with
    /// `IP_UNICAST_IF`/`IPV6_UNICAST_IF` so that egress selection does not
    /// depend on the routing table. A roam normally keeps the same interface
    /// index, but switching adapters (Wi-Fi to Ethernet, docking) does not, so
    /// the pin is refreshed from the interface of the freshly installed server
    /// route. `if_index` of `0` means "unknown", and is ignored.
    ///
    /// Default is a no-op for transports that do not pin (TCP pins once,
    /// before `connect`, after which the option has no effect).
    #[cfg(all(any(linux, windows), not(feature = "mobile")))]
    fn pin_egress_interface(&self, _if_index: u32) {}

    /// Returns the underlying socket tagged with its transport type.
    fn socket(&self) -> OutsideSocket;
}
