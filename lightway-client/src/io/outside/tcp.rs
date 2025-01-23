use anyhow::Result;
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;

use super::OutsideIO;
use lightway_core::{CowBytes, IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};

pub struct Tcp(tokio::net::TcpStream, SocketAddr);

impl Tcp {
    pub async fn new(remote_addr: &str, maybe_sock: Option<TcpStream>) -> Result<Arc<Self>> {
        let sock = match maybe_sock {
            Some(s) => s,
            None => tokio::net::TcpStream::connect(remote_addr).await?,
        };
        sock.set_nodelay(true)?;
        let peer_addr = sock.peer_addr()?;
        Ok(Arc::new(Self(sock, peer_addr)))
    }
}

#[async_trait]
impl OutsideIO for Tcp {
    fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.0);
        socket.set_send_buffer_size(size)?;
        Ok(())
    }
    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.0);
        socket.set_recv_buffer_size(size)?;
        Ok(())
    }

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        let r = self.0.ready(interest).await?;
        Ok(r)
    }

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize> {
        match self.0.try_read_buf(buf) {
            Ok(0) => {
                use std::io::{Error, ErrorKind::ConnectionAborted};
                IOCallbackResult::Err(Error::new(ConnectionAborted, "End of stream"))
            }
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> OutsideIOSendCallbackArg {
        self
    }
}

impl OutsideIOSendCallback for Tcp {
    fn send(&self, buf: CowBytes) -> IOCallbackResult<usize> {
        match self.0.try_write(buf.as_bytes()) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.1
    }
}
