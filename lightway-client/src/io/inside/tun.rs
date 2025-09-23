#[cfg(feature = "io-uring")]
use std::time::Duration;
use std::{net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;
use pnet_packet::ipv4::Ipv4Packet;

use lightway_app_utils::{Tun as AppUtilsTun, TunConfig};
use lightway_core::{
    IOCallbackResult, InsideIOSendCallback, InsideIOSendCallbackArg, InsideIpConfig,
    ipv4_update_destination, ipv4_update_source,
};

use crate::{
    ConnectionState,
    io::inside::{InsideIO, InsideIORecv},
};

pub struct Tun {
    tun: AppUtilsTun,
    ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
}

impl Tun {
    pub async fn new(tun: &TunConfig, ip: Ipv4Addr, dns_ip: Ipv4Addr) -> Result<Self> {
        let tun = AppUtilsTun::direct(tun).await?;
        Ok(Tun { tun, ip, dns_ip })
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
        Ok(Tun { tun, ip, dns_ip })
    }

    pub fn if_index(&self) -> std::io::Result<u32> {
        self.tun.if_index()
    }
}

#[async_trait]
impl<ExtAppState: Send + Sync> InsideIORecv<ExtAppState> for Tun {
    async fn recv_buf(&self) -> IOCallbackResult<BytesMut> {
        self.tun.recv_buf().await
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

    fn into_io_send_callback(
        self: Arc<Self>,
    ) -> InsideIOSendCallbackArg<ConnectionState<ExtAppState>> {
        self
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

        self.tun.try_send(buf)
    }

    fn mtu(&self) -> usize {
        self.tun.mtu()
    }

    fn if_index(&self) -> std::io::Result<u32> {
        self.if_index()
    }
}

impl<ExtAppState: Send + Sync> InsideIO<ConnectionState<ExtAppState>> for Tun {
    #[cfg(windows)]
    fn set_dns_servers(&self, dns_servers: &[IpAddr]) -> std::io::Result<()> {
        Ok(())
    }
    #[cfg(windows)]
    fn clear_dns_servers(&self) -> std::io::Result<()> {
        Ok(())
    }
}
