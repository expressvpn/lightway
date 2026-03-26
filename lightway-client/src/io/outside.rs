pub mod tcp;
pub mod udp;
pub mod ws_tcp;

pub use tcp::Tcp;
pub use udp::Udp;
pub use ws_tcp::WsTcp;

use anyhow::Result;
use async_trait::async_trait;
use lightway_core::{IOCallbackResult, OutsideIOSendCallbackArg};
use std::{net::SocketAddr, sync::Arc};

#[async_trait]
pub trait OutsideIO: Sync + Send {
    fn set_send_buffer_size(&self, size: usize) -> Result<()>;
    fn set_recv_buffer_size(&self, size: usize) -> Result<()>;

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready>;

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize>;

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg;

    fn peer_addr(&self) -> SocketAddr;
}
