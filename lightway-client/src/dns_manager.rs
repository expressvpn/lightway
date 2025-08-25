use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;

/// DNS configuration mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsConfigMode {
    #[default]
    Default,
    NoExec,
}
#[derive(Error, Debug)]
pub enum DnsManagerError {
    #[error("Unable to find primary service ID")]
    PrimaryServiceNotFound,
    #[error("Failed to set DNS configuration")]
    FailedToSetDnsConfig,
    #[error("Failed to remove DNS configuration")]
    FailedToRemoveDnsConfig,
    #[error("DNS cache flush failed: {0}")]
    CacheFlushFailed(String),
    #[error("macOS version detection failed: {0}")]
    VersionDetectionFailed(String),
    #[error("Invalid system data type")]
    InvalidSystemData,
}

pub trait DnsSetup {
    /// Set system DNS to the specified server
    fn set_dns(&mut self, dns_server: &str) -> Result<(), DnsManagerError>;
    /// Clear system DNS configuration
    fn reset_dns(&mut self) -> Result<(), DnsManagerError>;
}
#[derive(Default)]
pub struct DnsManager {
    #[cfg(target_os = "linux")]
    dns_manager: super::platform::linux::dns_manager::DnsManager,
    #[cfg(target_os = "macos")]
    dns_manager: super::platform::macos::dns_manager::DnsManager,
    #[cfg(target_os = "windows")]
    dns_manager: super::platform::windows::dns_manager::DnsManager,
}

impl DnsSetup for DnsManager {
    fn set_dns(&mut self, dns_server: &str) -> Result<(), DnsManagerError> {
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
