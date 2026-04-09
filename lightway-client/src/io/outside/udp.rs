use super::OutsideIO;
#[cfg(batch_receive)]
use crate::io::outside::udp_batch_receiver::BatchReceiver;
#[cfg(batch_receive)]
use crate::io::outside::udp_batch_receiver::BatchReceiverConsumerError;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use lightway_app_utils::sockopt;
use lightway_core::{IOCallbackResult, OutsideIOSendCallback, OutsideIOSendCallbackArg};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::net::UdpSocket;

pub struct Udp {
    sock: Arc<tokio::net::UdpSocket>,
    peer_addr: SocketAddr,
    default_ip_pmtudisc: sockopt::IpPmtudisc,
    #[cfg(batch_receive)]
    batch_receiver: Option<BatchReceiver>,
}

impl Udp {
    pub async fn new(remote_addr: SocketAddr, sock: Option<UdpSocket>) -> Result<Self> {
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

        Ok(Self {
            sock: Arc::new(sock),
            peer_addr,
            default_ip_pmtudisc,
            #[cfg(batch_receive)]
            batch_receiver: None,
        })
    }

    #[cfg(batch_receive)]
    pub fn enable_batch_receive(&mut self) {
        self.batch_receiver = Some(BatchReceiver::new(self.sock.clone()));
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

    #[cfg(batch_receive)]
    /// If `batch_receiver` is on, it will try to acquire a permit
    /// of a Semaphore to see if the ring buffer has any packets in it.
    async fn readable(&self) -> Result<()> {
        if let Some(receiver) = self.batch_receiver.as_ref() {
            // Wait until the recv task has pushed at least one packet into recv_queue.
            receiver.recv_queue_ready().await?;
        } else {
            self.poll(tokio::io::Interest::READABLE).await?;
        }
        Ok(())
    }

    fn recv_buf(&self, buf: &mut bytes::BytesMut) -> IOCallbackResult<usize> {
        #[cfg(batch_receive)]
        if let Some(receiver) = self.batch_receiver.as_ref() {
            return match receiver.pop_recv_consumer() {
                Ok(b) => {
                    let len = b.len();
                    *buf = b;
                    IOCallbackResult::Ok(len)
                }
                Err(BatchReceiverConsumerError::EmptyBuffer(_)) => IOCallbackResult::WouldBlock,
                Err(BatchReceiverConsumerError::SemaphoreClosed(e)) => IOCallbackResult::Err(e),
            };
        }
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
                // enter the error state, and DTLS would handle retransmission as well.
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
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.raw_os_error(), Some(libc::ENOBUFS)) => {
                // No buffer space available
                // UDP sockets may have this error when the system is overloaded.
                IOCallbackResult::Ok(buf.len())
            }
            Err(err) if matches!(err.kind(), std::io::ErrorKind::PermissionDenied) => {
                IOCallbackResult::Ok(buf.len())
            }
            #[cfg(macos)]
            Err(err) if matches!(err.kind(), std::io::ErrorKind::AddrNotAvailable) => {
                // The source address is no longer valid (e.g. Switched WiFi hotspots)
                // It should eventually recover by itself after a while.
                // If the user has disconnected from the internet, keepalive should fail
                // due to missed reply (`keepalive_timeout`).
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
        sockopt::set_ip_mtu_discover(self.sock.as_ref(), sockopt::IpPmtudisc::Probe)
    }

    fn disable_pmtud_probe(&self) -> std::io::Result<()> {
        sockopt::set_ip_mtu_discover(self.sock.as_ref(), self.default_ip_pmtudisc)
    }
}
