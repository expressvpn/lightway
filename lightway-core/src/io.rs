use std::{net::SocketAddr, sync::Arc};

use bytes::{Bytes, BytesMut};
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
}

/// Convenience type to use as function arguments
pub type InsideIOSendCallbackArg<AppState> = Arc<dyn InsideIOSendCallback<AppState> + Send + Sync>;

/// A byte buffer to be sent, may be owned or borrowed.
pub enum CowBytes<'a> {
    /// An owned buffer
    Owned(Bytes),
    /// A borrowed buffer
    Borrowed(&'a [u8]),
}

impl CowBytes<'_> {
    /// Convert this buffer into an owned `Bytes`. Cheap if this
    /// instance if `::Owned`, but copied if not.
    pub fn into_owned(self) -> Bytes {
        match self {
            CowBytes::Owned(b) => b,
            CowBytes::Borrowed(b) => Bytes::copy_from_slice(b),
        }
    }

    /// Gain access to the underlying byte buffer.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            CowBytes::Owned(b) => b.as_ref(),
            CowBytes::Borrowed(b) => b,
        }
    }
}

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
    fn send(&self, buf: CowBytes) -> IOCallbackResult<usize>;

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
