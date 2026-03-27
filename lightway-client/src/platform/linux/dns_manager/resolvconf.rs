use std::io::Write as _;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::dns_manager::DnsManagerError;

use super::DnsBackend;

/// openresolv/resolvconf backend, configured via the `resolvconf` CLI.
///
/// Uses exclusive mode (`-x`) on openresolv to ensure the VPN DNS server takes
/// full priority. Falls back to metric 0 (`-m 0`) on Debian's resolvconf, which
/// does not support `-x`.
pub(super) struct Resolvconf {
    iface_name: String,
    /// `true` when the installed `resolvconf` is openresolv (supports `-x`).
    exclusive: bool,
}

impl Resolvconf {
    pub(super) fn new(iface_name: String) -> Self {
        Self {
            exclusive: is_openresolv(),
            iface_name,
        }
    }
}

/// Returns `true` when the installed resolvconf is openresolv.
///
/// `/etc/resolvconf.conf` is installed exclusively by openresolv — Debian's
/// resolvconf uses `/etc/resolvconf/` instead and does not create this file.
fn is_openresolv() -> bool {
    std::path::Path::new("/etc/resolvconf.conf").exists()
}

impl DnsBackend for Resolvconf {
    fn set(&self, dns_server: IpAddr) -> Result<(), DnsManagerError> {
        let content = format!("nameserver {dns_server}\nsearch lightway\n");

        // -x (exclusive): when registered, resolvconf ignores all other sources.
        // -m 0 (metric 0): fall back on implementations that don't support -x;
        //   nameservers from all metric-0 sources are merged in slot-name order.
        let mode_args: &[&str] = if self.exclusive {
            &["-x"]
        } else {
            &["-m", "0"]
        };

        let mut child = Command::new("resolvconf")
            .arg("-a")
            .arg(&self.iface_name)
            .args(mode_args)
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| DnsManagerError::FailedToSetDnsConfig(e.to_string()))?;

        if let Some(stdin) = child.stdin.as_mut() {
            stdin
                .write_all(content.as_bytes())
                .map_err(|e| DnsManagerError::FailedToSetDnsConfig(e.to_string()))?;
        }

        let status = child
            .wait()
            .map_err(|e| DnsManagerError::FailedToSetDnsConfig(e.to_string()))?;
        if !status.success() {
            return Err(DnsManagerError::FailedToSetDnsConfig(format!(
                "resolvconf -a exited with {status}"
            )));
        }
        Ok(())
    }

    fn reset(&self) -> Result<(), DnsManagerError> {
        let status = Command::new("resolvconf")
            .args(["-d", &self.iface_name])
            .status()
            .map_err(|e| DnsManagerError::FailedToRestoreDnsConfig(e.to_string()))?;
        if !status.success() {
            return Err(DnsManagerError::FailedToRestoreDnsConfig(format!(
                "resolvconf -d exited with {status}"
            )));
        }
        Ok(())
    }
}
