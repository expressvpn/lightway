use std::net::IpAddr;
use std::process::Command;

use crate::dns_manager::DnsManagerError;

use super::DnsBackend;

/// systemd-resolved backend, configured via the `resolvectl` CLI.
pub(super) struct Resolvectl {
    pub(super) iface_name: String,
}

impl DnsBackend for Resolvectl {
    fn set(&self, dns_server: IpAddr) -> Result<(), DnsManagerError> {
        run(
            Command::new("resolvectl").args(["dns", &self.iface_name, &dns_server.to_string()]),
            "resolvectl dns",
        )?;
        // ~. routes all DNS queries through this interface
        run(
            Command::new("resolvectl").args(["domain", &self.iface_name, "~."]),
            "resolvectl domain",
        )
    }

    fn reset(&self) -> Result<(), DnsManagerError> {
        let status = Command::new("resolvectl")
            .args(["revert", &self.iface_name])
            .status()
            .map_err(|e| DnsManagerError::FailedToRestoreDnsConfig(e.to_string()))?;
        if !status.success() {
            return Err(DnsManagerError::FailedToRestoreDnsConfig(format!(
                "resolvectl revert exited with {status}"
            )));
        }
        Ok(())
    }
}

fn run(cmd: &mut Command, label: &str) -> Result<(), DnsManagerError> {
    let status = cmd
        .status()
        .map_err(|e| DnsManagerError::FailedToSetDnsConfig(e.to_string()))?;
    if !status.success() {
        return Err(DnsManagerError::FailedToSetDnsConfig(format!(
            "{label} exited with {status}"
        )));
    }
    Ok(())
}
