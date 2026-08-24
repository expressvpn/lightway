use anyhow::Result;
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;

use super::{OutsideIO, OutsideSocket};
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};

pub struct Tcp(tokio::net::TcpStream, SocketAddr);

impl Tcp {
    pub async fn new(
        remote_addr: SocketAddr,
        maybe_sock: Option<TcpStream>,
        #[cfg(all(linux, not(feature = "mobile")))] fwmark: u32,
        #[cfg(all(windows, not(feature = "mobile")))] pin_egress_interface: bool,
    ) -> Result<Self> {
        let sock = match maybe_sock {
            Some(s) => {
                #[cfg(all(linux, not(feature = "mobile")))]
                if fwmark != 0 {
                    let socket = socket2::SockRef::from(&s);
                    match socket.set_mark(fwmark) {
                        Ok(_) => tracing::info!("Applied firewall mark to outside TCP socket"),
                        Err(e) => tracing::warn!("Failed to set SO_MARK on TCP socket: {}", e),
                    }
                }
                s
            }
            None => {
                let socket = if remote_addr.is_ipv6() {
                    tokio::net::TcpSocket::new_v6()?
                } else {
                    tokio::net::TcpSocket::new_v4()?
                };

                // SO_MARK must be set before connect() so that the SYN packet is also
                // marked, ensuring all traffic (including connection setup) is subject
                // to policy routing rules based on the mark.
                #[cfg(all(linux, not(feature = "mobile")))]
                if fwmark != 0 {
                    match socket2::SockRef::from(&socket).set_mark(fwmark) {
                        Ok(_) => tracing::info!("Applied firewall mark to outside TCP socket"),
                        Err(e) => tracing::warn!("Failed to set SO_MARK on TCP socket: {}", e),
                    }
                }

                // The route lookup that binds the local address happens at
                // connect() and IP_UNICAST_IF has no effect on an already-connected
                // socket, so pin must be applied before connect.
                #[cfg(all(windows, not(feature = "mobile")))]
                if pin_egress_interface {
                    use std::os::windows::io::AsRawSocket;
                    match crate::platform::windows::egress::pin_to_peer_interface(
                        socket.as_raw_socket(),
                        remote_addr,
                    ) {
                        Ok(if_index) => tracing::info!(
                            "Pinned outside TCP socket egress to interface {if_index}"
                        ),
                        Err(e) => {
                            tracing::warn!("Failed to pin outside TCP socket egress: {e}")
                        }
                    }
                }

                socket.connect(remote_addr).await?
            }
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
        if let Err(e) = socket.set_send_buffer_size(size) {
            tracing::warn!("Failed to set TCP send buffer size to {size}: {e}");
        }
        Ok(())
    }
    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.0);
        if let Err(e) = socket.set_recv_buffer_size(size) {
            tracing::warn!("Failed to set TCP recv buffer size to {size}: {e}");
        }
        Ok(())
    }

    fn send_buffer_size(&self) -> Result<usize> {
        let socket = socket2::SockRef::from(&self.0);
        Ok(socket.send_buffer_size()?)
    }
    fn recv_buffer_size(&self) -> Result<usize> {
        let socket = socket2::SockRef::from(&self.0);
        Ok(socket.recv_buffer_size()?)
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

    fn send_gso(&self, _bufs: &[std::io::IoSlice<'_>], _gso_size: u16) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }
}
