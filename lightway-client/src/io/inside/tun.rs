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
use lightway_core::gro::TcpGroTable;
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
    ipv4_update_destination, ipv4_update_source,
};

#[cfg(linux)]
use crate::io::inside::InsideIORecvGso;
use crate::{ConnectionState, io::inside::InsideIORecv};

pub struct Tun {
    tun: AppUtilsTun,
    ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
    /// Whether a GRO coalescing window is open (see
    /// [`InsideIORecv::gro_open`]/[`InsideIORecv::gro_flush`]). Kept
    /// outside the table mutex so the per-packet send path pays only a
    /// relaxed load when offload is disabled. Opens, sends and flushes
    /// all happen on the outside IO task, so no stronger ordering is
    /// needed.
    #[cfg(linux)]
    gro_open: std::sync::atomic::AtomicBool,
    #[cfg(linux)]
    gro_table: std::sync::Mutex<TcpGroTable>,
}

impl Tun {
    pub async fn new(tun: &TunConfig, ip: Ipv4Addr, dns_ip: Ipv4Addr) -> Result<Self> {
        let tun = AppUtilsTun::direct(tun).await?;
        Ok(Self::from_app_utils_tun(tun, ip, dns_ip))
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
        Ok(Self::from_app_utils_tun(tun, ip, dns_ip))
    }

    fn from_app_utils_tun(tun: AppUtilsTun, ip: Ipv4Addr, dns_ip: Ipv4Addr) -> Self {
        Tun {
            tun,
            ip,
            dns_ip,
            #[cfg(linux)]
            gro_open: std::sync::atomic::AtomicBool::new(false),
            #[cfg(linux)]
            gro_table: std::sync::Mutex::new(TcpGroTable::new()),
        }
    }

    pub fn if_index(&self) -> std::io::Result<u32> {
        self.tun.if_index()
    }

    fn name(&self) -> std::io::Result<String> {
        self.tun.name()
    }

    /// Write one coalesced superpacket to the TUN. Failures are
    /// logged and dropped (datagram semantics) — the sends whose
    /// packets were absorbed into it already reported success.
    ///
    /// A single-segment batch comes back with a default header, which
    /// `try_send_gso` writes as the zeroed prefix a plain vnet-hdr
    /// write uses — no special-casing needed.
    #[cfg(linux)]
    fn write_super(&self, pkt: BytesMut, hdr: VirtioNetHdr) {
        match self.tun.try_send_gso(pkt, &hdr) {
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
    /// whenever the table consumed the packet — core treats that as
    /// sent.
    #[cfg(linux)]
    fn coalesce_send(&self, table: &mut TcpGroTable, buf: BytesMut) -> IOCallbackResult<usize> {
        let len = buf.len();
        let result = table.append(&buf);
        // Any flushed superpackets must reach the TUN before this
        // packet to preserve within-flow delivery order.
        for (pkt, hdr) in result.flushes {
            self.write_super(pkt, hdr);
        }
        if result.consumed {
            IOCallbackResult::Ok(len)
        } else {
            self.tun.try_send(buf)
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
        self.gro_open
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    #[cfg(linux)]
    fn gro_flush(&self) {
        self.gro_open
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let mut table = self.gro_table.lock().unwrap();
        for (pkt, hdr) in table.drain() {
            self.write_super(pkt, hdr);
        }
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
        // TSO superpackets instead of written individually. The
        // relaxed load keeps non-offload configs off the table mutex.
        #[cfg(linux)]
        if self.gro_open.load(std::sync::atomic::Ordering::Relaxed) {
            let mut table = self.gro_table.lock().unwrap();
            return self.coalesce_send(&mut table, buf);
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
