use std::net::IpAddr;

use crate::dns_manager::{DnsManagerError, DnsSetup};

#[derive(Default)]
pub struct DnsManager {}

impl DnsSetup for DnsManager {
    fn set_dns(&mut self, _dns_server: IpAddr) -> Result<(), DnsManagerError> {
        Ok(())
    }
    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        Ok(())
    }
}
