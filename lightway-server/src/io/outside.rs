pub(crate) mod datagram;
pub(crate) mod tcp;
pub(crate) mod udp;

pub(crate) use tcp::TcpServer;
pub(crate) use udp::UdpServer;

use anyhow::Result;
use async_trait::async_trait;

#[async_trait]
pub(crate) trait Server {
    async fn run(&mut self) -> Result<()>;
}
