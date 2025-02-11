use std::net::Ipv4Addr;
#[cfg(feature = "io-uring")]
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use bytes::BytesMut;

use lightway_app_utils::TunConfig;
use lightway_core::{IOCallbackResult, InsideIOSendCallback, InsideIpConfig};

use crate::{io::inside::InsideIO, ConnectionState};

#[allow(dead_code)]
pub struct Tun {
    ip: Ipv4Addr,
    dns_ip: Ipv4Addr,
}

impl Tun {
    pub async fn new(
        _tun: TunConfig,
        ip: Ipv4Addr,
        dns_ip: Ipv4Addr,
        #[cfg(feature = "io-uring")] _iouring: Option<(usize, Duration)>,
    ) -> Result<Self> {
        Ok(Tun { ip, dns_ip })
    }
}

#[async_trait]
impl InsideIO for Tun {
    async fn recv_buf(&self) -> IOCallbackResult<BytesMut> {
        futures::future::pending::<()>().await;
        IOCallbackResult::WouldBlock
    }

    /// Api to send packet in the tunnel
    fn try_send(&self, pkt: BytesMut, _ip_config: Option<InsideIpConfig>) -> Result<usize> {
        Ok(pkt.len())
    }
}

impl<T: Send + Sync> InsideIOSendCallback<ConnectionState<T>> for Tun {
    fn send(&self, buf: BytesMut, _state: &mut ConnectionState<T>) -> IOCallbackResult<usize> {
        IOCallbackResult::Ok(buf.len())
    }

    fn mtu(&self) -> usize {
        1350
    }
}
