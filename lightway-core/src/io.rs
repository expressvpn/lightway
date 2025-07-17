use bytes::BytesMut;
use std::{net::SocketAddr, sync::Arc};
use wolfssl::IOCallbackResult;

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
    /// This is the same method as [`wolfssl::IOCallbacks::send`].
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
}

/// Convenience type to use as function arguments
pub type OutsideIOSendCallbackArg = Arc<dyn OutsideIOSendCallback + Send + Sync>;
