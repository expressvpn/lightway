use thiserror::Error;
use windows_sys::Win32::NetworkManagement::IpHelper::{GetIpInterfaceEntry, MIB_IPINTERFACE_ROW};

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("InterfaceNotConnected")]
    InterfaceNotConnected,
    #[error("Interface not found")]
    InterfaceNotFound,
}

pub fn get_interface_metric(if_index: u32) -> Result<u32, PlatformError> {
    use std::mem;
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    // Initialize the IP interface row structure
    #[allow(unsafe_code)]
    // SAFETY: TODO
    let mut ip_interface_row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
    ip_interface_row.Family = AF_INET as u16; // IPv4
    ip_interface_row.InterfaceIndex = if_index;

    // Get the actual IP interface entry which contains the routing metric
    #[allow(unsafe_code)]
    // SAFETY: TODO
    let result = unsafe { GetIpInterfaceEntry(&mut ip_interface_row) };

    if result != 0 {
        tracing::warn!(
            "Failed to get IP interface entry for index {}: error {}. Using fallback metric calculation.",
            if_index,
            result
        );

        return Err(PlatformError::InterfaceNotFound);
    }

    // Windows sometimes returns routes which are not connected
    // Ignore those routes
    if !ip_interface_row.Connected {
        tracing::warn!("Interface {} not connected", if_index);
        return Err(PlatformError::InterfaceNotConnected);
    }

    Ok(ip_interface_row.Metric)
}
