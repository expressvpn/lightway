use crate::dns_manager::{DnsManagerError, DnsSetup};
use std::net::IpAddr;
use std::process::Command;

const NRPT_DNS: &[&str] = &["8.8.8.8", "1.1.1.1"];

pub struct DnsManager {
    setup: bool,
}

impl Default for DnsManager {
    fn default() -> Self {
        Self { setup: false }
    }
}

impl DnsManager {
    pub fn with_if_index(_if_index: u32) -> Self {
        Self::default()
    }

    fn flush_dns_cache() {
        let _ = Command::new("ipconfig").arg("/flushdns").output();
    }

    /// Add an NRPT (Name Resolution Policy Table) rule that forces all DNS
    /// queries through public resolvers routed via the VPN tunnel. This
    /// overrides Windows Smart Multi-Homed Name Resolution which otherwise
    /// queries all interfaces in parallel, allowing ISP DNS poisoning to win.
    fn add_nrpt_rule() -> Result<(), DnsManagerError> {
        let servers = NRPT_DNS
            .iter()
            .map(|s| format!("'{s}'"))
            .collect::<Vec<_>>()
            .join(",");
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Add-DnsClientNrptRule -Namespace '.' -NameServers {servers}"),
            ])
            .output()
            .map_err(|e| DnsManagerError::FailedToSetDnsConfig(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DnsManagerError::FailedToSetDnsConfig(format!(
                "NRPT rule creation failed: {stderr}"
            )));
        }
        Ok(())
    }

    fn remove_nrpt_rule() {
        let first = NRPT_DNS[0];
        let cmd = format!(
            "Get-DnsClientNrptRule | Where-Object {{ $_.NameServers -contains '{first}' }} | Remove-DnsClientNrptRule -Force"
        );
        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output();
    }
}

impl DnsSetup for DnsManager {
    fn set_dns(&mut self, _dns_server: IpAddr) -> Result<(), DnsManagerError> {
        Self::add_nrpt_rule()?;
        Self::flush_dns_cache();
        self.setup = true;
        Ok(())
    }

    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        if self.setup {
            Self::remove_nrpt_rule();
            Self::flush_dns_cache();
            self.setup = false;
        }
        Ok(())
    }
}
