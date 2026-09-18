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
/// Global network state entries naming the primary service of each address
/// family. Either can be absent on a single-stack network; on a dual-stack
/// one they usually name the same service.
const GLOBAL_STATE_PATHS: [&str; 2] = ["State:/Network/Global/IPv4", "State:/Network/Global/IPv6"];

pub struct DnsManager {
    /// Services whose DNS configuration [`DnsSetup::set_dns`] has overridden
    /// and [`DnsSetup::reset_dns`] will restore.
    service_ids: Vec<CFRetained<CFString>>,
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
            service_ids: Vec::new(),
            store,
        }
    }

    /// Get the DNS configuration path for a service ID
    fn get_primary_service_path(service_id: &CFString) -> CFRetained<CFString> {
        CFString::from_str(&format!("Setup:/Network/Service/{service_id}/DNS"))
    }

    /// Get the primary service IDs from the system configuration: one per
    /// address family that currently has a default route, de-duplicated.
    fn get_primary_service_ids(&self) -> Result<Vec<CFRetained<CFString>>, DnsManagerError> {
        let entries: Vec<_> = GLOBAL_STATE_PATHS
            .iter()
            .map(|path| SCDynamicStore::value(Some(&self.store), &CFString::from_str(path)))
            .collect();
        primary_service_ids(
            entries
                .iter()
                .map(|entry| entry.as_deref().map(AsRef::<CFType>::as_ref)),
        )
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

/// Collect the distinct `PrimaryService` IDs named by the given global network
/// state entries, in first-seen order.
///
/// Entries that are absent, are not dictionaries or lack the key are skipped;
/// an entry whose `PrimaryService` is not a string is a system data error.
#[allow(unsafe_code)]
fn primary_service_ids<'a>(
    entries: impl IntoIterator<Item = Option<&'a CFType>>,
) -> Result<Vec<CFRetained<CFString>>, DnsManagerError> {
    let mut ids: Vec<CFRetained<CFString>> = Vec::new();
    for entry in entries.into_iter().flatten() {
        let Some(dictionary_opaque) = entry.downcast_ref::<CFDictionary>() else {
            continue;
        };
        // SAFETY: System configuration store dictionaries have CFString keys
        // and CFType values.
        let dictionary: &CFDictionary<CFString, CFType> =
            unsafe { dictionary_opaque.cast_unchecked() };

        // SAFETY: Accessing extern static defined by the SystemConfiguration framework
        let Some(service_value) = dictionary.get(unsafe { kSCDynamicStorePropNetPrimaryService })
        else {
            continue;
        };
        let service_id = service_value
            .downcast_ref::<CFString>()
            .ok_or(DnsManagerError::InvalidSystemData)?;
        if !ids.iter().any(|id| **id == *service_id) {
            ids.push(CFString::from_str(&service_id.to_string()));
        }
    }

    if ids.is_empty() {
        return Err(DnsManagerError::PrimaryServiceNotFound);
    }
    Ok(ids)
}

impl DnsSetup for DnsManager {
    #[allow(unsafe_code)]
    fn set_dns(&mut self, dns_server: IpAddr) -> Result<(), DnsManagerError> {
        let service_ids = self.get_primary_service_ids()?;

        // Create DNS configuration dictionary with default search domain
        let dns_addresses = vec![CFString::from_str(&dns_server.to_string())];
        let search_domains = vec![CFString::from_str(DEFAULT_SEARCH_DOMAIN)];
        let dns_dictionary = self.get_dns_dictionary(&dns_addresses, &search_domains);

        for service_id in service_ids {
            let service_path = Self::get_primary_service_path(&service_id);

            // SAFETY: We're setting a valid dictionary to a valid path in the system configuration store
            let success = unsafe {
                SCDynamicStore::set_value(Some(&self.store), &service_path, dns_dictionary.as_ref())
            };

            if !success {
                // Services configured before this one stay recorded for reset_dns.
                return Err(DnsManagerError::FailedToSetDnsConfig(format!(
                    "Failed to set DNS Dictionary for service {}",
                    *service_id
                )));
            }

            // Store the service ID for cleanup
            self.service_ids.push(service_id);
        }

        self.flush_dns_cache()?;
        Ok(())
    }

    fn reset_dns(&mut self) -> Result<(), DnsManagerError> {
        let mut failed = Vec::new();
        for service_id in std::mem::take(&mut self.service_ids) {
            let service_path = Self::get_primary_service_path(&service_id);
            if !SCDynamicStore::remove_value(Some(&self.store), &service_path) {
                failed.push(service_id);
            }
        }

        if failed.is_empty() {
            return Ok(());
        }
        let failed_ids = failed
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        // Keep the services still configured so a later reset can retry them.
        self.service_ids = failed;
        Err(DnsManagerError::FailedToRemoveDnsConfig(failed_ids))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    // RFC5737 test address
    const TEST_ADDRESS: &str = "192.0.2.1";

    /// Upcast a CoreFoundation object to `CFType`, as the dynamic store
    /// hands entries back.
    fn cf<T: AsRef<CFType>>(value: &T) -> &CFType {
        value.as_ref()
    }

    #[allow(unsafe_code)]
    fn primary_service_key() -> &'static CFString {
        // SAFETY: Accessing extern static defined by the SystemConfiguration framework
        unsafe { kSCDynamicStorePropNetPrimaryService }
    }

    /// A `State:/Network/Global/IPv[46]`-shaped entry naming `service_id`.
    fn global_entry(service_id: &str) -> CFRetained<CFDictionary<CFString, CFType>> {
        let id = CFString::from_str(service_id);
        CFDictionary::from_slices(&[primary_service_key()], &[cf(&*id)])
    }

    fn ids_to_strings(ids: &[CFRetained<CFString>]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    #[test]
    fn primary_service_ids_errors_when_no_entry_names_a_service() {
        let result = primary_service_ids([None, None]);
        assert!(matches!(
            result,
            Err(DnsManagerError::PrimaryServiceNotFound)
        ));
    }

    #[test]
    fn primary_service_ids_skips_entries_without_primary_service() {
        let without_key = CFDictionary::<CFString, CFType>::from_slices(&[], &[]);
        let v6 = global_entry("SERVICE-A");
        let ids = primary_service_ids([Some(cf(&*without_key)), Some(cf(&*v6))]).unwrap();
        assert_eq!(ids_to_strings(&ids), ["SERVICE-A"]);
    }

    #[test]
    fn primary_service_ids_ignores_non_dictionary_entries() {
        let junk = CFString::from_str("not a dictionary");
        let result = primary_service_ids([Some(cf(&*junk))]);
        assert!(matches!(
            result,
            Err(DnsManagerError::PrimaryServiceNotFound)
        ));
    }

    #[test]
    fn primary_service_ids_dedups_a_shared_service() {
        let v4 = global_entry("SERVICE-A");
        let v6 = global_entry("SERVICE-A");
        let ids = primary_service_ids([Some(cf(&*v4)), Some(cf(&*v6))]).unwrap();
        assert_eq!(ids_to_strings(&ids), ["SERVICE-A"]);
    }

    #[test]
    fn primary_service_ids_keeps_distinct_services_in_order() {
        let v4 = global_entry("SERVICE-A");
        let v6 = global_entry("SERVICE-B");
        let ids = primary_service_ids([Some(cf(&*v4)), Some(cf(&*v6))]).unwrap();
        assert_eq!(ids_to_strings(&ids), ["SERVICE-A", "SERVICE-B"]);
    }

    #[test]
    fn primary_service_ids_rejects_non_string_service() {
        let not_a_string = CFArray::<CFString>::from_objects(&[]);
        let entry = CFDictionary::from_slices(&[primary_service_key()], &[cf(&*not_a_string)]);
        let result = primary_service_ids([Some(cf(&*entry))]);
        assert!(matches!(result, Err(DnsManagerError::InvalidSystemData)));
    }

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
