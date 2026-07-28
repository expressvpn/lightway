pub mod tun;

use anyhow::Result;
use bytes::BytesMut;
use std::sync::Arc;
pub use tun::Tun;

use async_trait::async_trait;
#[cfg(linux)]
use lightway_core::VirtioNetHdr;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
};

use crate::ConnectionState;

#[async_trait]
/// Trait for InsideIORecv
/// This will be used client app to fetch inside packets
pub trait InsideIORecv<ExtAppState: Send + Sync>: Send + Sync {
    async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize>;

    fn try_send(&self, pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize>;

    /// MTU of the underlying interface.
    fn mtu(&self) -> usize;

    /// Upgrade to the GSO-capable interface, when this instance supports
    /// GSO reads. Default: not supported. Capability is per-instance —
    /// a TUN opened without offload returns `None`.
    #[cfg(linux)]
    fn as_gso(self: Arc<Self>) -> Option<Arc<dyn InsideIORecvGso<ExtAppState>>> {
        None
    }

    fn into_io_send_callback(
        self: Arc<Self>,
    ) -> InsideIOSendCallbackArg<ConnectionState<ExtAppState>>;
}

/// Inside IO backends that can receive GSO superpackets. Obtained from
/// [`InsideIORecv::as_gso`]; the GSO inside loop only accepts this type,
/// so the capability check happens once at startup.
///
/// Implementers must also override [`InsideIORecv::as_gso`] to return
/// `Some(self)` — the default `None` hides the capability.
#[cfg(linux)]
#[async_trait]
pub trait InsideIORecvGso<ExtAppState: Send + Sync>: InsideIORecv<ExtAppState> {
    /// Receive a GSO superpacket into `buf`.
    ///
    /// Implementations write into `buf.spare_capacity_mut()` so the
    /// caller can reuse one allocation across iterations with no
    /// zero-init cost. On `Ok((n, hdr))`, the virtio header has been
    /// parsed (`hdr`), `set_len` + `advance(VIRTIO_NET_HDR_LEN)` have
    /// run, and `buf` holds exactly the IP packet (`n == buf.len()`).
    /// Caller must ensure `buf.capacity()` is large enough for one
    /// virtio header plus the largest expected aggregate.
    ///
    /// Returns `WouldBlock` on EAGAIN, on a short read that didn't
    /// contain a full virtio header, or when the virtio header
    /// itself fails to decode (each cause is logged + metered
    /// inside the impl). Returns `Err` on IO errors.
    async fn recv_gso(&self, buf: &mut BytesMut) -> IOCallbackResult<(usize, VirtioNetHdr)>;
}

/// Trait for InsideIO
///
/// This is a super trait which includes both InsideIORecv and InsideIOSendCallback
/// A default blanket implementation is provided, so users has to only implement
/// InsideIORecv and InsideIOSendCallback in their data structures.
pub trait InsideIO<ExtAppState: Send + Sync = ()>:
    InsideIORecv<ExtAppState> + InsideIOSendCallback<ConnectionState<ExtAppState>>
{
}

/// Default blanket implementation for InsideIO
impl<
    ExtAppState: Send + Sync,
    U: Send
        + Sync
        + Sized
        + InsideIOSendCallback<ConnectionState<ExtAppState>>
        + InsideIORecv<ExtAppState>,
> InsideIO<ExtAppState> for U
{
}
