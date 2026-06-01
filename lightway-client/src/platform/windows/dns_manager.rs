use crate::dns_manager::{DnsManagerError, DnsSetup};
use std::net::IpAddr;
use std::process::Command;

#[derive(Default)]
pub struct DnsManager {
    setup: bool,
}

/// Windows implementation of DnsManeger is based on
/// NRPT (Name Resolution Policy Table) rules that force all DNS
/// queries through configured resolver.
/// This overrides Windows Smart Multi-Homed Name Resolution which otherwise
/// queries all interfaces in parallel, allowing ISP DNS poisoning to win.
impl DnsManager {
    fn flush_dns_cache() {
        let _ = Command::new("ipconfig").arg("/flushdns").output();
    }

    fn add_nrpt_rule(dns_server: IpAddr) -> Result<(), DnsManagerError> {
        let server = format!("'{dns_server}'");
        let cmd = format!("Add-DnsClientNrptRule -Comment 'lightway-dns' -Namespace '.' -NameServers {server}");

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
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

    fn remove_nrpt_rule() -> Result<(), DnsManagerError> {
        let cmd = "Get-DnsClientNrptRule | Where-Object -Property Comment -eq 'lightway-dns' | Remove-DnsClientNrptRule -Force";

        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()
            .map_err(|e| DnsManagerError::FailedToRemoveDnsConfig(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DnsManagerError::FailedToRemoveDnsConfig(format!(
                "NRPT rule removal failed: {stderr}"
            )));
        }
        Ok(())
    }
}

impl DnsSetup for DnsManager {
    fn set_dns(&mut self, dns_server: IpAddr) -> Result<(), DnsManagerError> {
        if self.setup {
            return Err(DnsManagerError::DnsAlreadyConfigured);
        }
        Self::add_nrpt_rule(dns_server)?;
        Self::flush_dns_cache();
        self.setup = true;
        Ok(())
    }
    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        Self::remove_nrpt_rule()?;
        Self::flush_dns_cache();
        self.setup = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn get_configured_nrpt_server() -> Option<String> {
        let cmd = "Get-DnsClientNrptRule | Where-Object -Property Comment -eq 'lightway-dns' | Format-List -Property 'NameServers'";
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let server = stdout
            .splitn(2, ':')
            .nth(1)
            .map(|s| s.trim().to_string());

        return server;
    }

    fn has_configured_nrpt() -> bool {
        let cmd = "Get-DnsClientNrptRule | Where-Object -Property Comment -eq 'lightway-dns'";
        let output = Command::new("powershell")
            .args(["-NoProfile", "-Command", &cmd])
            .output()
            .unwrap();

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        !stdout.is_empty()
    }

    #[test]
    fn test_dns_set_and_cleanup() {
        const TEST_ADDRESS: &str = "192.0.2.1";

        // Verify NRPT is not initially present
        assert!(!has_configured_nrpt(), "NRPT already configured");

        // Set DNS and verify it's applied
        let mut dns_manager = crate::dns_manager::DnsManager::default();
        dns_manager.set_dns(TEST_ADDRESS.parse().unwrap()).unwrap();

        assert!(has_configured_nrpt(), "NRPT not configured");
        let server = get_configured_nrpt_server();
        assert!(server.is_some());
        assert!(server.unwrap() == TEST_ADDRESS);

        // Reset NRPT and verify it is removed
        dns_manager.reset_dns().unwrap();
        assert!(!has_configured_nrpt(), "NRPT still configured");
    }
}
