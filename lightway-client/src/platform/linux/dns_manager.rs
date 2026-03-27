mod direct_file;

use std::net::IpAddr;

use crate::dns_manager::{DnsManagerError, DnsSetup};

/// Trait implemented by each DNS backend.
pub(super) trait DnsBackend {
    fn set(&self, dns_server: IpAddr) -> Result<(), DnsManagerError>;
    fn reset(&self) -> Result<(), DnsManagerError>;
}

pub struct DnsManager {
    backend: Box<dyn DnsBackend>,
    setup: bool,
}

impl DnsManager {
    pub fn new(_ifindex: u32) -> Self {
        Self {
            backend: Box::new(direct_file::DirectFile),
            setup: false,
        }
    }
}

impl Default for DnsManager {
    fn default() -> Self {
        Self::new(0)
    }
}

impl DnsSetup for DnsManager {
    fn set_dns(&mut self, dns_server: IpAddr) -> Result<(), DnsManagerError> {
        if self.setup {
            return Err(DnsManagerError::DnsAlreadyConfigured);
        }
        self.backend.set(dns_server)?;
        self.setup = true;
        Ok(())
    }

    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        if self.setup {
            self.backend.reset()?;
        }
        self.setup = false;
        Ok(())
    }
}

impl Drop for DnsManager {
    fn drop(&mut self) {
        if let Err(e) = self.reset_dns() {
            tracing::warn!("Failed to reset DNS configuration during cleanup: {e:?}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));

    impl DnsManager {
        fn for_test_already_setup() -> Self {
            Self {
                backend: Box::new(direct_file::DirectFile),
                setup: true,
            }
        }
    }

    #[test]
    fn test_dns_already_configured_error() {
        let mut dns_manager = DnsManager::for_test_already_setup();
        let result = dns_manager.set_dns(TEST_IP);
        assert!(matches!(result, Err(DnsManagerError::DnsAlreadyConfigured)));
    }
}
