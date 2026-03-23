use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

/// DNS configuration mode
#[derive(
    Debug, Clone, Copy, JsonSchema, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum DnsConfigMode {
    #[default]
    Default,
    NoExec,
}
#[derive(Error, Debug)]
pub enum DnsManagerError {
    #[error("Unable to find primary service ID")]
    #[cfg(macos)]
    PrimaryServiceNotFound,
    #[error("Failed to set DNS configuration: {0}")]
    #[cfg(desktop)]
    FailedToSetDnsConfig(String),
    #[error("Failed to remove DNS configuration")]
    #[cfg(macos)]
    FailedToRemoveDnsConfig,
    #[error("DNS cache flush failed: {0}")]
    #[cfg(macos)]
    CacheFlushFailed(String),
    #[error("macOS version detection failed: {0}")]
    #[cfg(macos)]
    VersionDetectionFailed(String),
    #[error("Invalid system data type")]
    #[cfg(macos)]
    InvalidSystemData,
    #[error("Unable to find backup to restore resolv.conf")]
    #[cfg(linux)]
    NoResolvConfBackup,
    #[error("Failed to restore DNS configuration: {0}")]
    #[cfg(linux)]
    FailedToRestoreDnsConfig(String),
    #[error("DNS has already been configured")]
    #[cfg(linux)]
    DnsAlreadyConfigured,
}

pub trait DnsSetup {
    /// Set system DNS to the specified server
    fn set_dns(&mut self, dns_server: IpAddr) -> Result<(), DnsManagerError>;
    /// Clear system DNS configuration
    fn reset_dns(&mut self) -> Result<(), DnsManagerError>;
}
#[derive(Default)]
pub struct DnsManager {
    #[cfg(linux)]
    dns_manager: super::platform::linux::dns_manager::DnsManager,
    #[cfg(macos)]
    dns_manager: super::platform::macos::dns_manager::DnsManager,
    #[cfg(windows)]
    dns_manager: super::platform::windows::dns_manager::DnsManager,
}

impl DnsManager {
    /// Create a DNS manager using `ifindex` on Linux to select the best backend.
    ///
    /// On Linux, auto-detection order:
    /// 1. `resolvectl` (systemd-resolved) — preferred on modern distros
    /// 2. `resolvconf` (openresolv)
    /// 3. Direct `/etc/resolv.conf` manipulation (fallback)
    #[cfg(linux)]
    pub fn new(ifindex: u32) -> Self {
        Self {
            dns_manager: super::platform::linux::dns_manager::DnsManager::new(ifindex),
        }
    }

    #[cfg(not(linux))]
    pub fn new(_ifindex: u32) -> Self {
        Self::default()
    }
}

impl DnsSetup for DnsManager {
    fn set_dns(&mut self, dns_server: IpAddr) -> Result<(), DnsManagerError> {
        self.dns_manager.set_dns(dns_server)
    }

    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        self.dns_manager.reset_dns()
    }
}

impl Drop for DnsManager {
    fn drop(&mut self) {
        if let Err(e) = self.reset_dns() {
            warn!("Failed to reset DNS during cleanup: {}", e);
        }
    }
}
