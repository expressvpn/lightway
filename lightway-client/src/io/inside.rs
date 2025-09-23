pub mod tun;

use anyhow::Result;
use bytes::BytesMut;
use std::sync::Arc;
pub use tun::Tun;

use async_trait::async_trait;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
};

use crate::ConnectionState;

#[async_trait]
/// Trait for InsideIORecv
/// This will be used client app to fetch inside packets
pub trait InsideIORecv<ExtAppState: Send + Sync>: Send + Sync {
    async fn recv_buf(&self) -> IOCallbackResult<BytesMut>;

    fn try_send(&self, pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize>;

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
    #[cfg(windows)]
    fn set_dns_servers(&self, dns_servers: &[IpAddr]) -> std::io::Result<()> {
        Ok(())
    }
    #[cfg(windows)]
    fn clear_dns_servers(&self) -> std::io::Result<()> {
        Ok(())
    }
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
