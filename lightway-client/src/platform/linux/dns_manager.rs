mod direct_file;
mod resolvectl;

use std::fs;
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
    pub fn new(ifindex: u32) -> Self {
        Self {
            backend: detect_backend(ifindex),
            setup: false,
        }
    }
}

fn binary_in_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .map(|paths| std::env::split_paths(&paths).any(|dir| dir.join(name).is_file()))
        .unwrap_or(false)
}

/// Resolve the network interface name from its kernel index via `/sys/class/net`.
fn ifname_from_index(ifindex: u32) -> Option<String> {
    let net_dir = fs::read_dir("/sys/class/net").ok()?;
    for entry in net_dir.flatten() {
        let index_path = entry.path().join("ifindex");
        if let Ok(content) = fs::read_to_string(&index_path)
            && content.trim().parse::<u32>().ok() == Some(ifindex) {
                return Some(entry.file_name().to_string_lossy().into_owned());
            }
    }
    None
}

/// Returns `true` when systemd-resolved is actively running.
///
/// `/run/systemd/resolve/stub-resolv.conf` is written by systemd-resolved only
/// while it is running. Because `/run` is tmpfs it is never stale across reboots,
/// making it a reliable liveness indicator without spawning a process or requiring
/// a D-Bus connection.
fn systemd_resolved_running() -> bool {
    std::path::Path::new("/run/systemd/resolve/stub-resolv.conf").exists()
}

fn detect_backend(ifindex: u32) -> Box<dyn DnsBackend> {
    if let Some(iface_name) = ifname_from_index(ifindex)
        && binary_in_path("resolvectl") && systemd_resolved_running() {
            tracing::debug!("Using resolvectl DNS backend for interface {iface_name}");
            return Box::new(resolvectl::Resolvectl { iface_name });
        }
    tracing::debug!("Using direct /etc/resolv.conf DNS backend");
    Box::new(direct_file::DirectFile)
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
