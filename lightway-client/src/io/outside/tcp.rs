use anyhow::Result;
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;

use super::{OutsideIO, OutsideSocket};
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};

pub struct Tcp(tokio::net::TcpStream, SocketAddr);

impl Tcp {
    pub async fn new(remote_addr: SocketAddr, maybe_sock: Option<TcpStream>) -> Result<Self> {
        let sock = match maybe_sock {
            Some(s) => s,
            None => tokio::net::TcpStream::connect(remote_addr).await?,
        };
        sock.set_nodelay(true)?;
        let peer_addr = sock.peer_addr()?;
        Ok(Self(sock, peer_addr))
    }

    fn peer_addr(&self) -> SocketAddr {
        self.1
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

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    fn socket(&self) -> OutsideSocket {
        #[cfg(unix)]
        use std::os::fd::AsRawFd;
        #[cfg(windows)]
        use std::os::windows::io::AsRawSocket;
        #[cfg(unix)]
        let handle = self.0.as_raw_fd();
        #[cfg(windows)]
        let handle = self.0.as_raw_socket();
        OutsideSocket::Tcp(handle)
    }
}

impl OutsideIOSendCallback for Tcp {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.0.try_write(buf) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }
}
