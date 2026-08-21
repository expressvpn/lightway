use crate::tls::IOCallbackResult;
use bytes::BytesMut;
use std::{io::IoSlice, net::SocketAddr, sync::Arc};

/// Maximum number of packets handled in a single batched IO call —
/// covers both inbound (recvmmsg-style) reads and outbound
/// (sendmmsg-style) writes across both inside (TUN) and outside (socket) IO paths.
pub const MAX_IO_BATCH_SIZE: usize = 32;

/// Application provided callback used to send inside data.
pub trait InsideIOSendCallback<AppState> {
    /// Called when Lightway wishes to send some inside data
    ///
    /// Send as many bytes as possible from the provided buffer,
    /// return the number of bytes actually consumed. If the operation would
    /// block [`std::io::ErrorKind::WouldBlock`] then return
    /// [`IOCallbackResult::WouldBlock`].
    fn send(&self, buf: BytesMut, state: &mut AppState) -> IOCallbackResult<usize>;

    /// MTU supported by this inside I/O path
    fn mtu(&self) -> usize;

    /// Interface Index of tun
    fn if_index(&self) -> std::io::Result<u32>;

    /// Name of 'Tun' interface
    fn name(&self) -> std::io::Result<String>;
}

/// Convenience type to use as function arguments
pub type InsideIOSendCallbackArg<AppState> = Arc<dyn InsideIOSendCallback<AppState> + Send + Sync>;

/// Application provided callback used to send outside data.
pub trait OutsideIOSendCallback {
    /// Called when Lightway wishes to send some outside data
    ///
    /// Send as many bytes as possible from the provided buffer,
    /// return the number of bytes actually consumed. If the operation would
    /// block [`std::io::ErrorKind::WouldBlock`] then return
    /// [`IOCallbackResult::WouldBlock`].
    ///
    /// This is the same method as [`crate::tls::IOCallbacks::send`].
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize>;

    /// Get the peer's [`SocketAddr`]
    fn peer_addr(&self) -> SocketAddr;

    /// Set the peer's [`SocketAddr`], returning the previous value
    fn set_peer_addr(&self, _addr: SocketAddr) -> SocketAddr {
        // Default is to ignore if not supported.
        self.peer_addr()
    }

    /// Force enable the IPv4 DF bit is set for all packets (UDP only).
    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        Err(std::io::Error::other("pmtud probe not supported"))
    }

    /// Stop force enabling the IPv4 DF bit (UDP only).
    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        Err(std::io::Error::other("pmtud probe not supported"))
    }

    /// Send concatenated wire packets via kernel GSO (`UDP_SEGMENT`).
    /// The implementation gathers `bufs` into one payload via
    /// `sendmsg`, which the kernel splits into `gso_size`-byte
    /// segments. The trailing segment may be shorter than `gso_size`.
    fn send_gso(&self, bufs: &[IoSlice<'_>], gso_size: u16) -> IOCallbackResult<usize>;

    /// Whether kernel UDP GSO (`UDP_SEGMENT`) is usable on this socket.
    /// Starts `true`; an implementation may latch it `false` once a send
    /// is rejected with a capability error (typically `EIO` on an egress
    /// device without TX checksum offload, which UDP GSO requires). When
    /// `false` the connection sends one datagram per segment instead of
    /// coalescing. Transports that never call `send_gso` keep the default.
    fn gso_enabled(&self) -> bool {
        true
    }
}

/// Convenience type to use as function arguments
pub type OutsideIOSendCallbackArg = Arc<dyn OutsideIOSendCallback + Send + Sync>;
