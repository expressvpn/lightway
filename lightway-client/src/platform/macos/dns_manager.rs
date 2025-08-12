use crate::dns_manager::{DnsManagerError, DnsSetup};
use core_foundation::{
    array::CFArray,
    base::{CFGetTypeID, CFTypeRef, TCFType, ToVoid},
    dictionary::CFDictionary,
    propertylist::CFPropertyList,
    string::{CFString, CFStringGetTypeID, CFStringRef},
};
use std::process::Command;
use system_configuration::{
    dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder},
    sys::schema_definitions::{
        kSCDynamicStorePropNetPrimaryService, kSCPropNetDNSSearchDomains,
        kSCPropNetDNSServerAddresses,
    },
};

const DEFAULT_SEARCH_DOMAIN: &str = "expressvpn";
const DEFAULT_DNS_CONFIG_NAME: &str = "lightway-dns-config";
const IPV4_STATE_PATH: &str = "State:/Network/Global/IPv4";

pub struct DnsManager {
    service_id: Option<CFString>,
    store: SCDynamicStore,
}

impl Default for DnsManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsManager {
    pub fn new() -> Self {
        let store = SCDynamicStoreBuilder::new(DEFAULT_DNS_CONFIG_NAME).build();
        Self {
            service_id: None,
            store,
        }
    }
    /// Get the DNS configuration path for a service ID
    fn get_primary_service_path(service_id: &CFString) -> String {
        format!("Setup:/Network/Service/{service_id}/DNS")
    }

    /// Helper to safely wrap Apple framework constants and add to pairs
    /// SAFETY: This is safe when key is a valid Apple framework constant
    /// e.g.
    ///     - kSCPropNetDNSServerAddresses
    ///     - kSCPropNetDNSSearchDomains
    #[allow(unsafe_code)]
    fn add_config_entry<T: TCFType>(pairs: &mut Vec<(CFString, T)>, key: CFStringRef, value: T) {
        // SAFETY: Guaranteed valid for Apple framework constants
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        pairs.push((key, value));
    }
    /// Get the primary service ID from the system configuration
    #[allow(unsafe_code)]
    fn get_primary_service_id(&self) -> Result<CFString, DnsManagerError> {
        let dictionary = self
            .store
            .get(IPV4_STATE_PATH)
            .and_then(CFPropertyList::downcast_into::<CFDictionary>)
            .ok_or(DnsManagerError::PrimaryServiceNotFound)?;

        let ptr_to_id_in_dictionary = dictionary
            .find(
                // SAFETY: Apple framework constant, guaranteed valid
                unsafe { kSCDynamicStorePropNetPrimaryService }.to_void(),
            )
            .ok_or(DnsManagerError::PrimaryServiceNotFound)?;

        // SAFETY: ptr_to_id_in_dictionary is a valid CFTypeRef from CFDictionary.find(),
        // which guarantees the pointer is non-null and points to a valid Core Foundation object
        let cf_type_id = unsafe { CFGetTypeID(*ptr_to_id_in_dictionary as CFTypeRef) };
        // SAFETY: CFStringGetTypeID() is a Core Foundation constant getter
        let string_type_id = unsafe { CFStringGetTypeID() };
        if cf_type_id != string_type_id {
            return Err(DnsManagerError::InvalidSystemData);
        }
        // SAFETY: We've verified above that ptr_to_id_in_dictionary points to a CFString object.
        // The cast to CFStringRef is safe because we confirmed the type ID matches CFString.
        // wrap_under_get_rule is safe because it properly manages the reference count of the CFString.
        // In addition, Apple documentation states that one should expect a CFString
        // https://developer.apple.com/documentation/systemconfiguration/kscdynamicstorepropnetprimaryservice-swift.var
        Ok(unsafe { CFString::wrap_under_get_rule(*ptr_to_id_in_dictionary as CFStringRef) })
    }

    /// Get DNS configuration dictionary for system configuration
    #[allow(unsafe_code)]
    fn get_dns_dictionary(
        &self,
        addresses: &[CFString],
        search_domains: &[CFString],
    ) -> CFDictionary {
        let mut pairs = Vec::new();

        // Add DNS server addresses
        Self::add_config_entry(
            &mut pairs,
            // SAFETY: Guaranteed valid for Apple framework constants
            unsafe { kSCPropNetDNSServerAddresses },
            CFArray::from_CFTypes(addresses),
        );

        // Add search domains if provided
        if !search_domains.is_empty() {
            Self::add_config_entry(
                &mut pairs,
                // SAFETY: Guaranteed valid for Apple framework constants
                unsafe { kSCPropNetDNSSearchDomains },
                CFArray::from_CFTypes(search_domains),
            );
        }

        let dns_config = CFDictionary::from_CFType_pairs(&pairs);

        // SAFETY: dns_config is a valid CFDictionary created from valid CFString/CFArray pairs above.
        // as_concrete_TypeRef() returns the valid underlying CFDictionaryRef pointer.
        // wrap_under_get_rule here bumps the reference count to prevent use-after-free
        unsafe { CFDictionary::wrap_under_get_rule(dns_config.as_concrete_TypeRef()) }
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
    fn set_dns(&mut self, dns_server: &str) -> Result<(), DnsManagerError> {
        let primary_service_id = self.get_primary_service_id()?;

        let primary_service_path = Self::get_primary_service_path(&primary_service_id);
        self.service_id = Some(primary_service_id);

        // Create DNS configuration dictionary with default search domain
        let dns_dictionary = self.get_dns_dictionary(
            &[CFString::new(dns_server)],
            &[CFString::new(DEFAULT_SEARCH_DOMAIN)],
        );

        if !self
            .store
            .set(primary_service_path.as_str(), dns_dictionary)
        {
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

            if !self.store.remove(primary_service_path.as_str()) {
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
            dns_manager.set_dns(TEST_ADDRESS).unwrap();

            let modified_dns = get_dns_config();

            assert!(modified_dns.contains(TEST_ADDRESS));
        } // Drop happens here

        std::thread::sleep(std::time::Duration::from_millis(250));

        // Verify DNS is restored
        let final_dns = get_dns_config();

        assert!(!final_dns.contains(TEST_ADDRESS));
    }
}
