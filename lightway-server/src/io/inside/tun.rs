use crate::connection::ConnectionState;
#[cfg(linux)]
use crate::io::inside::InsideIORecvGso;
use crate::{
    io::inside::{InsideIO, InsideIORecv, InsideIORecvBatch},
    metrics,
};
use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use lightway_app_utils::{Tun as AppUtilsTun, TunConfig};
#[cfg(target_os = "linux")]
use lightway_core::VirtioNetHdr;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, ipv4_update_source,
};
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
#[cfg(feature = "io-uring")]
use std::time::Duration;

pub(crate) struct Tun(AppUtilsTun);

impl Tun {
    pub async fn new(tun: &TunConfig) -> Result<Self> {
        let tun = AppUtilsTun::direct(tun).await?;
        Ok(Tun(tun))
    }

    #[cfg(feature = "io-uring")]
    pub async fn new_with_iouring(
        tun: &TunConfig,
        ring_size: usize,
        sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        let tun = AppUtilsTun::iouring(tun, ring_size, sqpoll_idle_time).await?;
        Ok(Tun(tun))
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

#[async_trait]
impl InsideIORecv for Tun {
    async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        match self.0.recv_buf(buf).await {
            IOCallbackResult::Ok(n) => {
                metrics::tun_to_client(n);
                IOCallbackResult::Ok(n)
            }
            e => e,
        }
    }

    fn as_batch(self: Arc<Self>) -> Option<Arc<dyn InsideIORecvBatch>> {
        Some(self)
    }

    #[cfg(linux)]
    fn as_gso(self: Arc<Self>) -> Option<Arc<dyn InsideIORecvGso>> {
        if self.0.supports_gso() {
            Some(self)
        } else {
            None
        }
    }

    fn into_io_send_callback(self: Arc<Self>) -> InsideIOSendCallbackArg<ConnectionState> {
        self
    }
}

#[async_trait]
impl InsideIORecvBatch for Tun {
    async fn recv_buf_many(&self, pkts: &mut Vec<BytesMut>, max: usize) -> IOCallbackResult<usize> {
        // `pkts` may arrive non-empty; meter only what this call appended.
        let start = pkts.len();
        match self.0.recv_buf_many(pkts, max).await {
            IOCallbackResult::Ok(n) => {
                for pkt in &pkts[start..] {
                    metrics::tun_to_client(pkt.len());
                }
                IOCallbackResult::Ok(n)
            }
            e => e,
        }
    }
}

#[cfg(linux)]
#[async_trait]
impl InsideIORecvGso for Tun {
    async fn recv_gso(&self, buf: &mut BytesMut) -> IOCallbackResult<(usize, VirtioNetHdr)> {
        match self.0.recv_gso(buf).await {
            IOCallbackResult::Ok((n, hdr)) => {
                // Note: payload bytes (post-virtio-strip), not raw kernel
                // bytes — see metrics::tun_to_client doc.
                metrics::tun_to_client(n);
                IOCallbackResult::Ok((n, hdr))
            }
            IOCallbackResult::WouldBlock => IOCallbackResult::WouldBlock,
            IOCallbackResult::Err(e) => IOCallbackResult::Err(e),
        }
    }
}

impl InsideIOSendCallback<ConnectionState> for Tun {
    fn send(&self, mut buf: BytesMut, state: &mut ConnectionState) -> IOCallbackResult<usize> {
        let Some(client_ip) = state.internal_ip else {
            metrics::tun_rejected_packet_no_client_ip();
            // Ip address not found, dropping the packet
            return IOCallbackResult::Ok(buf.len());
        };

        ipv4_update_source(buf.as_mut(), client_ip);
        metrics::tun_from_client(buf.len());
        self.0.try_send(buf)
    }

    fn mtu(&self) -> usize {
        self.0.mtu()
    }

    fn if_index(&self) -> std::io::Result<u32> {
        self.0.if_index()
    }

    fn name(&self) -> std::io::Result<String> {
        self.0.name()
    }
}

impl InsideIO for Tun {}
