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

    /// Upgrade to the GRO-aware batched receive interface, when this
    /// instance routes receives through it. Default: not supported.
    /// Capability is per-instance but does not require the `UDP_GRO`
    /// sockopt to have stuck — the batched loop degrades to plain
    /// single-datagram slots when the kernel does not coalesce.
    #[cfg(any(linux, android))]
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
#[cfg(any(linux, android))]
pub trait OutsideIORecvGro: OutsideIO {
    /// Fill up to `MAX_IO_BATCH_SIZE` datagrams in a single `recvmmsg`,
    /// writing each datagram's GRO segment size into `gro_sizes[i]`
    /// (`None` if the kernel did not coalesce that message). Returns the
    /// datagram count (`>= 1` on `Ok`).
    ///
    /// Each datagram may itself be a GRO aggregate of many wire packets:
    /// when `gro_sizes[i]` is `Some(gro_size)`, every wire packet in
    /// `bufs[i]` is exactly `gro_size` bytes except a possibly-shorter
    /// final one; `None` means `bufs[i]` holds a single wire packet.
    ///
    /// This is the read-side batching that cuts one `recvmsg` per
    /// datagram down to one syscall per batch. It stacks with the
    /// kernel's own socket-read coalescing, which is driven by the
    /// `UDP_GRO` sockopt on the receiving socket: a valid UDP checksum
    /// on the sender's datagrams is necessary but *not* sufficient — the
    /// sockopt is what does the work. Measured on Linux 6.x with
    /// identical, correctly-checksummed senders, a receiver *with* the
    /// sockopt got 1 `recvmsg` of 14000 bytes whose cmsg reported
    /// `seg=1400`; a receiver *without* it got 10 separate 1400-byte
    /// `recv()` calls and no coalescing at all.
    ///
    /// A peer that sends zero-checksum UDP is skipped by the kernel GRO
    /// engine by design, so every `gro_sizes[i]` comes back `None` and
    /// each slot holds a single wire packet. That costs the socket-read
    /// coalescing only; the independent TUN-write coalescing
    /// (`TcpGroTable` on the inside path) is unaffected.
    ///
    /// Caller must ensure each buffer has spare capacity for a
    /// maximum-size aggregate (64KiB) or the tail of the aggregate is
    /// truncated.
    fn recv_gro_batch(
        &self,
        bufs: &mut [bytes::BytesMut; MAX_IO_BATCH_SIZE],
        gro_sizes: &mut [Option<u16>; MAX_IO_BATCH_SIZE],
    ) -> IOCallbackResult<usize>;
}
