use crate::dns_manager::{DnsManagerError, DnsSetup};
use objc2_core_foundation::{CFArray, CFDictionary, CFRetained, CFString, CFType};
use objc2_system_configuration::{
    SCDynamicStore, kSCDynamicStorePropNetPrimaryService, kSCPropNetDNSSearchDomains,
    kSCPropNetDNSServerAddresses,
};
use std::net::IpAddr;
use std::process::Command;

const DEFAULT_SEARCH_DOMAIN: &str = "expressvpn";
const DEFAULT_DNS_CONFIG_NAME: &str = "lightway-dns-config";
const IPV4_STATE_PATH: &str = "State:/Network/Global/IPv4";

pub struct DnsManager {
    service_id: Option<CFRetained<CFString>>,
    store: CFRetained<SCDynamicStore>,
}

impl Default for DnsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsManager {
    #[allow(unsafe_code)]
    pub fn new() -> Self {
        let name = CFString::from_str(DEFAULT_DNS_CONFIG_NAME);
        // SAFETY: We're passing None for the callback and null_mut for the context,
        // which is valid when we don't need asynchronous notifications
        let store = unsafe {
            SCDynamicStore::new(None, &name, None, std::ptr::null_mut())
                .expect("Failed to create SCDynamicStore")
        };
        Self {
            service_id: None,
            store,
        }
    }

    /// Get the DNS configuration path for a service ID
    fn get_primary_service_path(service_id: &CFString) -> CFRetained<CFString> {
        CFString::from_str(&format!("Setup:/Network/Service/{service_id}/DNS"))
    }

    /// Get the primary service ID from the system configuration
    #[allow(unsafe_code)]
    fn get_primary_service_id(&self) -> Result<CFRetained<CFString>, DnsManagerError> {
        let ipv4_path = CFString::from_str(IPV4_STATE_PATH);

        // Get the dictionary from the dynamic store
        let value = SCDynamicStore::value(Some(&self.store), &ipv4_path)
            .ok_or(DnsManagerError::PrimaryServiceNotFound)?;

        // Try to downcast to CFDictionary
        let dictionary_opaque: &CFDictionary = value
            .downcast_ref::<CFDictionary>()
            .ok_or(DnsManagerError::PrimaryServiceNotFound)?;

        // SAFETY: We need to cast the dictionary to the proper type. This is safe because we know
        // the dictionary contains CFString keys and CFType values from the system configuration store.
        let dictionary: &CFDictionary<CFString, CFType> =
            unsafe { dictionary_opaque.cast_unchecked() };

        // Get the primary service value using the constant key
        // SAFETY: Accessing extern static defined by the SystemConfiguration framework
        let service_value = dictionary
            .get(unsafe { kSCDynamicStorePropNetPrimaryService })
            .ok_or(DnsManagerError::PrimaryServiceNotFound)?;

        // Verify it's a CFString by trying to downcast
        service_value
            .downcast_ref::<CFString>()
            .ok_or(DnsManagerError::InvalidSystemData)
            .map(|s| CFString::from_str(&s.to_string()))
    }

    /// Get DNS configuration dictionary for system configuration
    #[allow(unsafe_code)]
    fn get_dns_dictionary(
        &self,
        addresses: &[CFRetained<CFString>],
        search_domains: &[CFRetained<CFString>],
    ) -> CFRetained<CFDictionary<CFString, CFType>> {
        let mut keys = Vec::new();
        let mut values: Vec<CFRetained<CFType>> = Vec::new();

        // Add DNS server addresses
        // SAFETY: Accessing extern static defined by the SystemConfiguration framework
        let dns_key_str = unsafe { kSCPropNetDNSServerAddresses.to_string() };
        keys.push(CFString::from_str(&dns_key_str));

        let address_refs: Vec<&CFString> = addresses.iter().map(|s| &**s).collect();
        let dns_array = CFArray::from_objects(&address_refs);
        // Convert CFArray to CFType using AsRef and retain it
        let cf_type: &CFType = dns_array.as_ref();
        // SAFETY: Retaining a valid CFType reference for storage in the dictionary
        values.push(unsafe { CFRetained::retain(cf_type.into()) });

        // Add search domains if provided
        if !search_domains.is_empty() {
            // SAFETY: Accessing extern static defined by the SystemConfiguration framework
            let search_key_str = unsafe { kSCPropNetDNSSearchDomains.to_string() };
            keys.push(CFString::from_str(&search_key_str));

            let domain_refs: Vec<&CFString> = search_domains.iter().map(|s| &**s).collect();
            let search_array = CFArray::from_objects(&domain_refs);
            // Convert CFArray to CFType using AsRef and retain it
            let cf_type: &CFType = search_array.as_ref();
            // SAFETY: Retaining a valid CFType reference for storage in the dictionary
            values.push(unsafe { CFRetained::retain(cf_type.into()) });
        }

        let key_refs: Vec<&CFString> = keys.iter().map(|k| &**k).collect();
        let value_refs: Vec<&CFType> = values.iter().map(|v| &**v).collect();

        CFDictionary::from_slices(&key_refs, &value_refs)
    }

    /// Flush DNS cache based on macOS version
    fn flush_dns_cache(&self) -> Result<(), DnsManagerError> {
        let output = Command::new("/usr/bin/sw_vers")
            .arg("-productVersion")
            .output()
            .map_err(|e| DnsManagerError::VersionDetectionFailed(e.to_string()))?;

        let version = String::from_utf8(output.stdout)
            .map_err(|e| DnsManagerError::VersionDetectionFailed(e.to_string()))?;

        let result = if version.starts_with("10.10") {
            Command::new("/usr/bin/discoveryutil")
                .arg("mdnsflushcache")
                .status()
        } else {
            Command::new("/usr/bin/killall")
                .args(["-HUP", "mDNSResponder"])
                .status()
        };

        match result {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(DnsManagerError::CacheFlushFailed(format!(
                "Command failed with exit code: {}",
                status.code().unwrap_or(-1)
            ))),
            Err(e) => Err(DnsManagerError::CacheFlushFailed(e.to_string())),
        }
    }
}

impl DnsSetup for DnsManager {
    #[allow(unsafe_code)]
    fn set_dns(&mut self, dns_server: IpAddr) -> Result<(), DnsManagerError> {
        let primary_service_id = self.get_primary_service_id()?;
        let primary_service_path = Self::get_primary_service_path(&primary_service_id);

        // Store the service ID for cleanup
        self.service_id = Some(primary_service_id);

        // Create DNS configuration dictionary with default search domain
        let dns_addresses = vec![CFString::from_str(&dns_server.to_string())];
        let search_domains = vec![CFString::from_str(DEFAULT_SEARCH_DOMAIN)];
        let dns_dictionary = self.get_dns_dictionary(&dns_addresses, &search_domains);

        // SAFETY: We're setting a valid dictionary to a valid path in the system configuration store
        let success = unsafe {
            SCDynamicStore::set_value(
                Some(&self.store),
                &primary_service_path,
                dns_dictionary.as_ref(),
            )
        };

        if !success {
            return Err(DnsManagerError::FailedToSetDnsConfig(
                "Failed to set DNS Dictionary".to_string(),
            ));
        }

        self.flush_dns_cache()?;
        Ok(())
    }

    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        if let Some(service_id) = &self.service_id {
            let primary_service_path = Self::get_primary_service_path(service_id);

            if !SCDynamicStore::remove_value(Some(&self.store), &primary_service_path) {
                return Err(DnsManagerError::FailedToRemoveDnsConfig);
            }
            self.service_id = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // RFC5737 test address
    const TEST_ADDRESS: &str = "192.0.2.1";

    fn get_dns_config() -> String {
        let output = Command::new("sudo")
            .args(["scutil", "--dns"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    #[ignore = "Requires macOS and system permissions"]
    fn test_privileged_dns_set_and_cleanup() {
        let initial_dns = get_dns_config();

        // Verify test DNS is not initially present
        assert!(!initial_dns.contains(TEST_ADDRESS));
        {
            // Set DNS and verify it's changed
            let mut dns_manager = crate::dns_manager::DnsManager::default();
            dns_manager.set_dns(TEST_ADDRESS.parse().unwrap()).unwrap();

            let modified_dns = get_dns_config();

            assert!(modified_dns.contains(TEST_ADDRESS));
        } // Drop happens here

        std::thread::sleep(std::time::Duration::from_millis(250));

        // Verify DNS is restored
        let final_dns = get_dns_config();

        assert!(!final_dns.contains(TEST_ADDRESS));
    }
}
