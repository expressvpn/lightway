use crate::dns_manager::{DnsManagerError, DnsSetup};
use std::net::IpAddr;

#[derive(Default)]
pub struct DnsManager {
    tun: Arc<Tun>,
}

impl DnsManager {
    pub fn new(tun: Arc<Tun>) -> Self {
        Self { tun }
    }
}

impl DnsSetup for DnsManager {
    fn set_dns(&mut self, _dns_server: IpAddr) -> Result<(), DnsManagerError> {
        Ok(())
    }
    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        Ok(())
    }
}
