use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;

use super::OutsideIO;
use lightway_app_utils::sockopt;
use lightway_core::{CowBytes, IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};

pub struct Udp {
    sock: tokio::net::UdpSocket,
    peer_addr: SocketAddr,
    default_ip_pmtudisc: sockopt::IpPmtudisc,
}

impl Udp {
    pub async fn new(remote_addr: &str, sock: Option<UdpSocket>) -> Result<Arc<Self>> {
        let sock = match sock {
            Some(s) => s,
            None => tokio::net::UdpSocket::bind("0.0.0.0:0").await?,
        };
        let default_ip_pmtudisc = sockopt::get_ip_mtu_discover(&sock)?;

        let peer_addr = tokio::net::lookup_host(remote_addr)
            .await?
            .next()
            .ok_or(anyhow!("Lookup of {remote_addr} results in no address"))?;
        Ok(Arc::new(Self {
            sock,
            peer_addr,
            default_ip_pmtudisc,
        }))
    }
}

#[async_trait]
impl OutsideIO for Udp {
    fn set_send_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.sock);
        socket.set_send_buffer_size(size)?;
        Ok(())
    }
    fn set_recv_buffer_size(&self, size: usize) -> Result<()> {
        let socket = socket2::SockRef::from(&self.sock);
        socket.set_recv_buffer_size(size)?;
        Ok(())
    }

    async fn poll(&self, interest: tokio::io::Interest) -> Result<tokio::io::Ready> {
        let r = self.sock.ready(interest).await?;
        Ok(r)
    }

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize> {
        match self.sock.try_recv_buf(buf) {
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

impl OutsideIOSendCallback for Udp {
    fn send(&self, buf: CowBytes) -> IOCallbackResult<usize> {
        match self.sock.try_send_to(buf.as_bytes(), self.peer_addr) {
            Ok(nr) => IOCallbackResult::Ok(nr),
            Err(err) if matches!(err.kind(), std::io::ErrorKind::WouldBlock) => {
                IOCallbackResult::WouldBlock
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::ConnectionRefused) => {
                // Possibly the server isn't listening (yet).
                //
                // Swallow the error so the WolfSSL socket does not
                // enter the error state.
                //
                // This way we can continue if/when the server shows up.
                IOCallbackResult::Ok(0)
            }
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENETUNREACH)) => {
                // This case indicates network unreachable error.
                // Possibly there is a network change at the moment.
                //
                // Swallow the socket error so the error is not passed to the
                // WolfSSL layer. Then the WolfSSL layer would not enter a
                // fatal error state
                //
                // Note: this case should be matched by
                // matches!(err.kind(), std::io::ErrorKind::NetworkUnreachable)
                // However, at the time of implementing this match case,
                // the version of rust we use does not support NetworkUnreachable.
                // This match case can be rewritten to use NetworkUnreachable
                // once rust is updated to support it.
                IOCallbackResult::Ok(0)
            }
            Err(err) => IOCallbackResult::Err(err),
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(&self.sock, sockopt::IpPmtudisc::Probe)
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(&self.sock, self.default_ip_pmtudisc)
    }
}
