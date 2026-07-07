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

    /// Upgrade to the GSO-capable interface, when this instance supports
    /// GSO reads. Default: not supported. Capability is per-instance —
    /// a TUN opened without offload returns `None`.
    #[cfg(linux)]
    fn as_gso(self: Arc<Self>) -> Option<Arc<dyn InsideIORecvGso>> {
        None
    }

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState>;
}

/// Trait for InsideIO
pub trait InsideIO: InsideIORecv + InsideIOSendCallback<ConnectionState> {}

/// Inside IO backends that can receive GSO superpackets. Obtained from
/// [`InsideIORecv::as_gso`]; the GSO inside loop only accepts this type,
/// so the capability check happens once at startup.
///
/// Implementers must also override [`InsideIORecv::as_gso`] to return
/// `Some(self)` — the default `None` hides the capability.
#[cfg(linux)]
#[async_trait]
pub trait InsideIORecvGso: InsideIORecv {
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
    async fn recv_gso(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<(usize, VirtioNetHdr)>;
}

#[cfg(all(test, linux))]
mod tests {
    use super::*;
    use bytes::BytesMut;

    /// Backend without the GSO capability: only the base trait.
    struct NoGso;

    #[async_trait]
    impl InsideIORecv for NoGso {
        async fn recv_buf(&self, _buf: &mut BytesMut) -> IOCallbackResult<usize> {
            unimplemented!("not needed for capability tests")
        }

        fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState> {
            unimplemented!("not needed for capability tests")
        }
    }

    /// Backend with the GSO capability: overrides the upgrade.
    struct WithGso;

    #[async_trait]
    impl InsideIORecv for WithGso {
        async fn recv_buf(&self, _buf: &mut BytesMut) -> IOCallbackResult<usize> {
            unimplemented!("not needed for capability tests")
        }

        fn as_gso(self: Arc<Self>) -> Option<Arc<dyn InsideIORecvGso>> {
            Some(self)
        }

        fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState> {
            unimplemented!("not needed for capability tests")
        }
    }

    #[async_trait]
    impl InsideIORecvGso for WithGso {
        async fn recv_gso(&self, _buf: &mut BytesMut) -> IOCallbackResult<(usize, VirtioNetHdr)> {
            // Proves dispatch through the typed handle without needing
            // to construct a VirtioNetHdr.
            IOCallbackResult::Err(std::io::Error::other("mock recv_gso reached"))
        }
    }

    #[test]
    fn default_as_gso_is_none() {
        assert!(Arc::new(NoGso).as_gso().is_none());
    }

    #[test]
    fn as_gso_is_none_through_a_trait_object() {
        let io: Arc<dyn InsideIORecv> = Arc::new(NoGso);
        assert!(io.as_gso().is_none());
    }

    #[tokio::test]
    async fn upgraded_handle_dispatches_recv_gso() {
        let gso = Arc::new(WithGso).as_gso().expect("override upgrades");
        let mut buf = BytesMut::new();
        assert!(matches!(
            gso.recv_gso(&mut buf).await,
            IOCallbackResult::Err(_)
        ));
    }
}
