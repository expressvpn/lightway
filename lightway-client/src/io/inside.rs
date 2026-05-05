pub mod tun;

use anyhow::Result;
use bytes::BytesMut;
use std::sync::Arc;
pub use tun::Tun;

use async_trait::async_trait;
#[cfg(linux)]
use lightway_app_utils::InsideRecvMultipleBuffers;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
};

use crate::ConnectionState;

#[async_trait]
/// Trait for InsideIORecv
/// This will be used client app to fetch inside packets
pub trait InsideIORecv<ExtAppState: Send + Sync>: Send + Sync {
    async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize>;

    /// Receive multiple packets into caller-owned buffers. `buffers` is
    /// scratch reused across calls; each `Tun` impl uses only the part it
    /// needs. `bufs` entries must be pre-sized to MTU; populated entries
    /// are truncated to each packet's length on return.
    ///
    /// Returns the number of packets written.
    ///
    /// Linux and client only.
    #[cfg(linux)]
    async fn recv_multiple_buf(
        &self,
        tun_buffer: &mut InsideRecvMultipleBuffers,
        bufs: &mut [BytesMut],
    ) -> IOCallbackResult<usize>;

    fn try_send(&self, pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize>;

    /// MTU of the underlying interface.
    fn mtu(&self) -> usize;

    /// Returns whether the underlying TUN reports UDP/TCP GSO support.
    #[cfg(linux)]
    fn gso(&self) -> (bool, bool);

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
