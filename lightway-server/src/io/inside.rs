pub(crate) mod tun;

pub(crate) use tun::Tun;

use crate::connection::ConnectionState;
use async_trait::async_trait;
#[cfg(target_os = "linux")]
use lightway_core::VirtioNetHdr;
use lightway_core::{IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg};
use std::sync::Arc;

#[async_trait]
pub trait InsideIORecv: Sync + Send {
    async fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize>;

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
    #[cfg(target_os = "linux")]
    async fn recv_gso(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<(usize, VirtioNetHdr)>;

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState>;
}

/// Trait for InsideIO
pub trait InsideIO: InsideIORecv + InsideIOSendCallback<ConnectionState> {}
