pub mod tun;

use anyhow::Result;
use bytes::BytesMut;
use std::sync::Arc;
pub use tun::Tun;

use async_trait::async_trait;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig, MAX_INSIDE_MTU,
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

    /// Change the MTU of the underlying interface.
    fn set_mtu(&self, _mtu: u16) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    /// Extra capacity a [`Self::recv_buf`] buffer needs beyond [`Self::mtu`].
    ///
    /// Non-zero only for a TUN opened with offload, where the kernel
    /// prepends a `virtio_net_hdr` to every read and silently truncates
    /// if the buffer has no room for it. Included in [`Self::recv_buf_size`].
    fn vnet_headroom(&self) -> usize {
        0
    }

    /// Size of the buffer a [`Self::recv_buf`] read needs.
    ///
    /// At least the current MTU, so a full packet always fits. Never below
    /// `MAX_INSIDE_MTU` either: the client may raise the MTU up to that
    /// while a read is already waiting, and a smaller buffer would truncate
    /// the first larger packet.
    fn recv_buf_size(&self) -> usize {
        self.mtu().max(MAX_INSIDE_MTU) + self.vnet_headroom()
    }

    fn into_io_send_callback(
        self: Arc<Self>,
    ) -> InsideIOSendCallbackArg<ConnectionState<ExtAppState>>;
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
