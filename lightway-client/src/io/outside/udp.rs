use anyhow::{Result, anyhow};
use async_trait::async_trait;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;

use super::OutsideIO;
use lightway_app_utils::sockopt;
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};

pub struct Udp {
    sock: tokio::net::UdpSocket,
    peer_addr: SocketAddr,
    default_ip_pmtudisc: sockopt::IpPmtudisc,
}

impl Udp {
    pub async fn new(remote_addr: SocketAddr, sock: Option<UdpSocket>) -> Result<Arc<Self>> {
        let peer_addr = tokio::net::lookup_host(remote_addr)
            .await?
            .next()
            .ok_or(anyhow!("Lookup of {remote_addr} results in no address"))?;

        let unspecified_ip = if peer_addr.ip().is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };

        let sock = match sock {
            Some(s) => s,
            None => tokio::net::UdpSocket::bind((unspecified_ip, 0)).await?,
        };
        let default_ip_pmtudisc = sockopt::get_ip_mtu_discover(&sock)?;
        // Check for the socket's writable ready status, so that it can be used
        // successfuly in WolfSsl's `OutsideIOSendCallback` callback
        sock.writable().await?;

        Ok(Arc::new(Self {
            sock,
            peer_addr,
            default_ip_pmtudisc,
        }))
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
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

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }
}

impl OutsideIOSendCallback for Udp {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        match self.sock.try_send_to(buf, self.peer_addr) {
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
                //
                // Returning the number of bytes requested to be sent to mock
                // that the send is successful.
                // Otherwise, WolfSSL perceives that no data is sent and try
                // to send the same data again, creating a live-lock until
                // the network is reachable.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::NetworkUnreachable) => {
                // This case indicates network unreachable error.
                // Possibly there is a network change at the moment.
                //
                // Swallow the socket error so the error is not passed to the
                // WolfSSL layer. Then the WolfSSL layer would not enter a
                // fatal error state
                //
                // Returning the number of bytes requested to be sent to mock
                // that the send is successful.
                // Otherwise, WolfSSL perceives that no data is sent and try
                // to send the same data again, creating a live-lock until the
                // network is reachable.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOBUFS)) => {
                // No buffer space available
                // UDP sockets may have this error when the system is overloaded.
                //
                // Swallow the socket error so the error is not passed to the
                // WolfSSL layer, and DTLS would handle retransmission as well.
                //
                // Returning the number of bytes requested to be sent to mock
                // that to send is successful.
                // Otherwise, WolfSSL perceives that no data is sent and try
                // to send the same data again, creating a live-lock as it may take a while
                // to clear up send buffer.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) => {
                tracing::warn!("Outside IO Send failed: {err:?}");
                IOCallbackResult::Err(err)
            }
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr()
    }

    fn enable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(&self.sock, sockopt::IpPmtudisc::Probe)
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(&self.sock, self.default_ip_pmtudisc)
    }
}
