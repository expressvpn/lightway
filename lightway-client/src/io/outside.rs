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

    /// Upgrade to the GRO-capable interface, when this instance has
    /// UDP GRO enabled on its socket. Default: not supported.
    /// Capability is per-instance — a socket where the `UDP_GRO`
    /// sockopt was not (or could not be) enabled returns `None`.
    #[cfg(linux)]
    fn as_gro(self: Arc<Self>) -> Option<Arc<dyn OutsideIORecvGro>> {
        None
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg;

    fn peer_addr(&self) -> SocketAddr;

    /// Returns the underlying socket tagged with its transport type.
    fn socket(&self) -> OutsideSocket;
}

/// Outside IO backends that can receive GRO aggregates. Obtained from
/// [`OutsideIO::as_gro`]; the GRO outside loop only accepts this type,
/// so the capability check happens once at startup.
///
/// Implementers must also override [`OutsideIO::as_gro`] to return
/// `Some(self)` — the default `None` hides the capability.
#[cfg(linux)]
pub trait OutsideIORecvGro: OutsideIO {
    /// Receive one datagram — possibly a GRO aggregate of many wire
    /// packets — into `buf`'s spare capacity.
    ///
    /// Returns the bytes received and, when the kernel coalesced,
    /// `Some(gro_size)`: every wire packet in `buf` is exactly
    /// `gro_size` bytes except a possibly-shorter final one. `None`
    /// means `buf` holds a single wire packet.
    ///
    /// Caller must ensure `buf` has spare capacity for a maximum-size
    /// aggregate (64KiB) or the tail of the aggregate is truncated.
    fn recv_gro(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<(usize, Option<u16>)>;
}
