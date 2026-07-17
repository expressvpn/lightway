#[cfg(feature = "io-uring")]
use std::time::Duration;
use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use pnet_packet::ipv4::Ipv4Packet;

use lightway_app_utils::{Tun as AppUtilsTun, TunConfig};
#[cfg(linux)]
use lightway_core::VirtioNetHdr;
#[cfg(linux)]
use lightway_core::gro::{GroAppend, TcpGroBatch};
#[cfg(linux)]
use lightway_core::gso::VIRTIO_NET_HDR_GSO_NONE;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
    ipv4_update_destination, ipv4_update_source,
};

#[cfg(linux)]
use crate::io::inside::InsideIORecvGso;
use crate::{ConnectionState, io::inside::InsideIORecv};

/// State of the GRO coalescing window opened by
/// [`InsideIORecv::gro_open`] and closed by [`InsideIORecv::gro_flush`].
#[cfg(linux)]
#[derive(Default)]
struct GroWindow {
    open: bool,
    batch: TcpGroBatch,
}

pub struct Tun {
    tun: AppUtilsTun,
    ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    #[cfg(linux)]
    gro: std::sync::Mutex<GroWindow>,
}

impl Tun {
    pub async fn new(tun: &TunConfig, ip: Ipv4Addr, dns_ip: Ipv4Addr) -> Result<Self> {
        let tun = AppUtilsTun::direct(tun).await?;
        Ok(Tun {
            tun,
            ip,
            dns_ip,
            #[cfg(linux)]
            gro: std::sync::Mutex::new(GroWindow::default()),
        })
    }

    #[cfg(feature = "io-uring")]
    pub async fn new_with_iouring(
        tun: &TunConfig,
        ip: Ipv4Addr,
        dns_ip: Ipv4Addr,
        iouring_ring_size: usize,
        iouring_sqpoll_idle_time: Duration,
    ) -> Result<Self> {
        let tun = AppUtilsTun::iouring(tun, iouring_ring_size, iouring_sqpoll_idle_time).await?;
        Ok(Tun {
            tun,
            ip,
            dns_ip,
            #[cfg(linux)]
            gro: std::sync::Mutex::new(GroWindow::default()),
        })
    }

    pub fn if_index(&self) -> std::io::Result<u32> {
        self.tun.if_index()
    }

    fn name(&self) -> std::io::Result<String> {
        self.tun.name()
    }

    /// Write any pending coalesced batch to the TUN. Failures are
    /// logged and dropped (datagram semantics) — the sends whose
    /// packets were absorbed into the batch already reported success.
    #[cfg(linux)]
    fn flush_batch(&self, batch: &mut TcpGroBatch) {
        let Some((pkt, hdr)) = batch.take() else {
            return;
        };
        // A single-segment batch comes back as the original packet
        // bytes with a default header — a plain write suffices.
        let result = if hdr.flags == 0 && hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE {
            self.tun.try_send(pkt)
        } else {
            self.tun.try_send_gso(pkt, &hdr)
        };
        match result {
            IOCallbackResult::Ok(_) => {}
            IOCallbackResult::WouldBlock => {
                tracing::warn!("Dropping coalesced GRO batch: TUN would block");
            }
            IOCallbackResult::Err(err) => {
                tracing::warn!("Dropping coalesced GRO batch: {err}");
            }
        }
    }

    /// Route a packet through the GRO coalescer. Returns `Ok(len)`
    /// whenever the batch consumed the packet — core treats that as
    /// sent.
    #[cfg(linux)]
    fn coalesce_send(&self, batch: &mut TcpGroBatch, buf: BytesMut) -> IOCallbackResult<usize> {
        let len = buf.len();
        match batch.append(&buf) {
            GroAppend::Coalesced => IOCallbackResult::Ok(len),
            GroAppend::CoalescedFlush => {
                self.flush_batch(batch);
                IOCallbackResult::Ok(len)
            }
            GroAppend::Incompatible => {
                // The pending batch must reach the TUN before this
                // packet to preserve delivery order.
                self.flush_batch(batch);
                // Re-offer once — with the batch now empty it may
                // start a fresh one.
                match batch.append(&buf) {
                    GroAppend::Coalesced => IOCallbackResult::Ok(len),
                    GroAppend::CoalescedFlush => {
                        self.flush_batch(batch);
                        IOCallbackResult::Ok(len)
                    }
                    GroAppend::Incompatible => self.tun.try_send(buf),
                }
            }
        }
    }
}

#[async_trait]
impl<ExtAppState: Send + Sync> InsideIORecv<ExtAppState> for Tun {
    async fn recv_buf(&self, buf: &mut BytesMut) -> IOCallbackResult<usize> {
        self.tun.recv_buf(buf).await
    }

    /// Api to send packet in the tunnel
    fn try_send(&self, mut pkt: BytesMut, ip_config: Option<InsideIpConfig>) -> Result<usize> {
        let pkt_len = pkt.len();
        // Update destination IP from server provided inside ip to TUN device ip
        ipv4_update_destination(pkt.as_mut(), self.ip);

        // Update source IP from server DNS ip to TUN DNS ip
        if let Some(ip_config) = ip_config {
            let packet = Ipv4Packet::new(pkt.as_ref());
            if let Some(packet) = packet
                && packet.get_source() == ip_config.dns_ip
            {
                ipv4_update_source(pkt.as_mut(), self.dns_ip);
            };
        }

        self.tun.try_send(pkt);
        Ok(pkt_len)
    }

    fn mtu(&self) -> usize {
        self.tun.mtu()
    }

    #[cfg(linux)]
    fn as_gso(self: Arc<Self>) -> Option<Arc<dyn InsideIORecvGso<ExtAppState>>> {
        if self.tun.supports_gso() {
            Some(self)
        } else {
            None
        }
    }

    #[cfg(linux)]
    fn gro_open(&self) {
        if !self.tun.supports_gso() {
            return;
        }
        self.gro.lock().unwrap().open = true;
    }

    #[cfg(linux)]
    fn gro_flush(&self) {
        let mut gro = self.gro.lock().unwrap();
        let GroWindow { open, batch } = &mut *gro;
        self.flush_batch(batch);
        *open = false;
    }

    fn into_io_send_callback(
        self: Arc<Self>,
    ) -> InsideIOSendCallbackArg<ConnectionState<ExtAppState>> {
        self
    }
}

#[cfg(linux)]
#[async_trait]
impl<ExtAppState: Send + Sync> InsideIORecvGso<ExtAppState> for Tun {
    async fn recv_gso(&self, buf: &mut BytesMut) -> IOCallbackResult<(usize, VirtioNetHdr)> {
        self.tun.recv_gso(buf).await
    }
}

impl<ExtAppState: Send + Sync> InsideIOSendCallback<ConnectionState<ExtAppState>> for Tun {
    fn send(
        &self,
        mut buf: BytesMut,
        state: &mut ConnectionState<ExtAppState>,
    ) -> IOCallbackResult<usize> {
        // Update destination IP from server provided inside ip to TUN device ip
        ipv4_update_destination(buf.as_mut(), self.ip);

        // Update source IP from server DNS ip to TUN DNS ip
        if let Some(ip_config) = state.ip_config {
            let packet = Ipv4Packet::new(buf.as_ref());
            if let Some(packet) = packet
                && packet.get_source() == ip_config.dns_ip
            {
                ipv4_update_source(buf.as_mut(), self.dns_ip);
            };
        }

        // Inside an open GRO window, TCP segments are coalesced into
        // TSO superpackets instead of written individually.
        #[cfg(linux)]
        {
            let mut gro = self.gro.lock().unwrap();
            if gro.open {
                return self.coalesce_send(&mut gro.batch, buf);
            }
        }

        self.tun.try_send(buf)
    }

    fn mtu(&self) -> usize {
        self.tun.mtu()
    }

    fn if_index(&self) -> std::io::Result<u32> {
        self.if_index()
    }

    fn name(&self) -> std::io::Result<String> {
        self.name()
    }
}
