#![allow(unsafe_code)]
use anyhow::Result;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, error};

use super::relevant_addrs;
use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE, NO_ERROR, WAIT_OBJECT_0, WAIT_TIMEOUT},
    NetworkManagement::IpHelper::{
        FreeMibTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW,
        MIB_UNICASTIPADDRESS_TABLE, NotifyAddrChange,
    },
    Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC},
    System::IO::OVERLAPPED,
    System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
};

/// Read the current system-wide unicast IP addresses via `GetUnicastIpAddressTable`.
///
/// Returns an empty vector on failure; callers treat that as "no relevant
/// addresses", which is safe because a genuine change will still differ from
/// the previous non-empty snapshot.
fn current_unicast_addrs() -> Vec<IpAddr> {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
    // SAFETY: GetUnicastIpAddressTable allocates the table and writes the
    // pointer through `table`; we free it with FreeMibTable below.
    let ret = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
    if ret != NO_ERROR || table.is_null() {
        return Vec::new();
    }

    // SAFETY: `table` is non-null and stays valid until the matching FreeMibTable.
    let count = unsafe { (*table).NumEntries } as usize;
    // SAFETY: `Table` is the flexible-array member of the valid `table`; form a
    // pointer to its first row without creating an intermediate reference.
    let first = unsafe { std::ptr::addr_of!((*table).Table) } as *const MIB_UNICASTIPADDRESS_ROW;
    // SAFETY: `first` points to `count` contiguous, initialised rows owned by the
    // live table.
    let rows = unsafe { std::slice::from_raw_parts(first, count) };

    let mut out = Vec::new();
    for row in rows {
        // SAFETY: `si_family` is valid to read for any SOCKADDR_INET.
        let family = unsafe { row.Address.si_family };
        if family == AF_INET {
            // SAFETY: family == AF_INET, so the Ipv4 variant is active.
            let v4 = unsafe { row.Address.Ipv4 };
            // SAFETY: S_addr is the active union member; it is in network byte
            // order, so its in-memory bytes are the address octets.
            let octets = unsafe { v4.sin_addr.S_un.S_addr }.to_ne_bytes();
            out.push(IpAddr::V4(Ipv4Addr::from(octets)));
        } else if family == AF_INET6 {
            // SAFETY: family == AF_INET6, so the Ipv6 variant is active.
            let v6 = unsafe { row.Address.Ipv6 };
            // SAFETY: the unioned in6-addr bytes are always valid to read.
            let bytes = unsafe { v6.sin6_addr.u.Byte };
            out.push(IpAddr::V6(Ipv6Addr::from(bytes)));
        }
    }
    // SAFETY: `table` was allocated by GetUnicastIpAddressTable and is freed once.
    unsafe { FreeMibTable(table as *const core::ffi::c_void) };
    out
}

/// Represents an address change detected by the monitor.
///
/// The Windows `NotifyAddrChange` API does not report the specific kind of
/// change, so a single generic event is emitted for any address change.
#[derive(Debug, Clone, PartialEq)]
pub enum AddrChangeEvent {
    /// An address configuration changed
    AddressChanged,
}

/// Async stream for monitoring Windows address changes
pub struct AsyncAddrListener {
    receiver: mpsc::UnboundedReceiver<AddrChangeEvent>,
    _join_handle: tokio::task::JoinHandle<()>,
    shutdown: Arc<AtomicBool>,
}

impl AsyncAddrListener {
    /// Creates a new AsyncAddrListener for monitoring address changes.
    ///
    /// `ignore` lists local addresses (the tunnel's own address) whose
    /// appearance/disappearance must not be reported as a network change.
    pub fn new(ignore: Vec<IpAddr>) -> Result<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        let join_handle = tokio::task::spawn_blocking(move || {
            if let Err(e) = Self::monitor_address_changes(sender, shutdown_clone, ignore) {
                error!("Address monitoring task failed: {}", e);
            }
        });

        Ok(Self {
            receiver,
            _join_handle: join_handle,
            shutdown,
        })
    }

    /// Internal function to monitor address changes using Windows API
    fn monitor_address_changes(
        sender: mpsc::UnboundedSender<AddrChangeEvent>,
        shutdown: Arc<AtomicBool>,
        ignore: Vec<IpAddr>,
    ) -> Result<()> {
        // RAII wrapper for Windows event handle
        struct EventHandle(HANDLE);

        impl EventHandle {
            fn new() -> Result<Self> {
                // SAFETY: CreateEventW is called with valid parameters:
                // - lpEventAttributes: null (default security descriptor)
                // - bManualReset: 1 (manual reset event)
                // - bInitialState: 0 (initially non-signaled)
                // - lpName: null (unnamed event)
                let handle = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null()) };
                if handle.is_null() {
                    return Err(anyhow::anyhow!(
                        "Failed to create event for address change notification"
                    ));
                }
                Ok(EventHandle(handle))
            }

            fn get(&self) -> HANDLE {
                self.0
            }
        }

        impl Drop for EventHandle {
            fn drop(&mut self) {
                if !self.0.is_null() {
                    // SAFETY: self.0 is a valid handle that was created by CreateEventW
                    // and has not been closed yet (checked by is_null())
                    unsafe {
                        windows_sys::Win32::Foundation::CloseHandle(self.0);
                    }
                }
            }
        }

        // Create event handle once for the entire monitoring session
        let event_handle = EventHandle::new()?;

        // Baseline snapshot of the relevant (non-tunnel, non-noise) addresses.
        // `NotifyAddrChange` reports any address change without detail — including
        // the client's own TUN interface coming up — so we only signal when this
        // filtered set actually changes between notifications.
        let mut prev: BTreeSet<IpAddr> = relevant_addrs(current_unicast_addrs(), &ignore);

        loop {
            // Check if we should shutdown
            if shutdown.load(Ordering::Relaxed) {
                debug!("Address monitoring shutdown requested");
                break;
            }

            let monitoring_result =
                Self::perform_single_monitor_cycle(event_handle.get(), shutdown.clone());

            match monitoring_result {
                Ok(()) => {
                    let now = relevant_addrs(current_unicast_addrs(), &ignore);
                    if now == prev {
                        // Change was confined to ignored/tunnel addresses or
                        // noise — not a real path change, so don't signal.
                        debug!("Address change ignored (no relevant address delta)");
                        continue;
                    }
                    prev = now;

                    tracing::info!("Address change detected!");
                    // Send notification - we use a general event since Windows API
                    // doesn't provide specific details about the type of change
                    if sender.send(AddrChangeEvent::AddressChanged).is_err() {
                        tracing::info!("Receiver dropped, stopping address monitoring");
                        break;
                    }

                    // Small delay to prevent flooding if multiple rapid changes occur
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => {
                    error!("Address monitoring cycle failed: {}", e);
                    // Brief delay before retrying to prevent tight loop
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
            }
        }

        debug!("Address monitoring task finished");
        Ok(())
    }

    /// Performs a single monitoring cycle with proper resource cleanup
    fn perform_single_monitor_cycle(event_handle: HANDLE, shutdown: Arc<AtomicBool>) -> Result<()> {
        // RAII wrapper for notification cleanup
        struct NotificationContext {
            handle: HANDLE,
            overlapped: windows_sys::Win32::System::IO::OVERLAPPED,
        }

        impl NotificationContext {
            fn new(event_handle: HANDLE) -> Self {
                // SAFETY: OVERLAPPED is a Plain Old Data (POD) structure that can be safely zero-initialized
                let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
                overlapped.hEvent = event_handle;

                Self {
                    handle: INVALID_HANDLE_VALUE,
                    overlapped,
                }
            }

            fn start_notification(&mut self) -> Result<()> {
                // SAFETY: NotifyAddrChange is called with:
                // - handle: mutable reference to HANDLE (will be set by the function)
                // - overlapped: reference to properly initialized OVERLAPPED structure
                let result = unsafe { NotifyAddrChange(&mut self.handle, &self.overlapped) };

                if result != 0 && result != 997 {
                    // ERROR_IO_PENDING = 997
                    return Err(anyhow::anyhow!(
                        "NotifyAddrChange failed with error: {}",
                        result
                    ));
                }

                Ok(())
            }
        }

        impl Drop for NotificationContext {
            fn drop(&mut self) {
                if self.handle != INVALID_HANDLE_VALUE {
                    // SAFETY: CancelIPChangeNotify is called with a reference to the overlapped structure
                    // that was used to start the notification. The handle is valid (not INVALID_HANDLE_VALUE)
                    unsafe {
                        windows_sys::Win32::NetworkManagement::IpHelper::CancelIPChangeNotify(
                            &self.overlapped,
                        );
                    }
                }
            }
        }

        // Create notification context with automatic cleanup
        let mut notification_ctx = NotificationContext::new(event_handle);

        // Start the notification
        notification_ctx.start_notification()?;

        debug!("Waiting for address change notification...");

        // Wait for the event to be signaled with a timeout to prevent hanging
        // Use 1 second timeout to periodically check shutdown flag
        const TIMEOUT_MS: u32 = 1000;

        loop {
            // Check shutdown flag before each wait
            if shutdown.load(Ordering::Relaxed) {
                debug!("Address monitoring cycle interrupted by shutdown");
                return Err(anyhow::anyhow!("Monitoring interrupted by shutdown"));
            }

            // SAFETY: WaitForSingleObject is called with a valid event handle and timeout value
            let wait_result = unsafe { WaitForSingleObject(event_handle, TIMEOUT_MS) };

            match wait_result {
                WAIT_OBJECT_0 => {
                    // Address change detected
                    // SAFETY: ResetEvent is called with a valid event handle that was signaled
                    unsafe { ResetEvent(event_handle) };
                    return Ok(());
                }
                WAIT_TIMEOUT => {
                    // Timeout occurred - this is normal, check shutdown and continue
                    // This allows the thread to check periodically if it should exit
                    continue;
                }
                _ => {
                    return Err(anyhow::anyhow!(
                        "Wait for address change event failed: {}",
                        wait_result
                    ));
                }
            }
        }
    }

    /// Get the next address change event
    pub async fn recv(&mut self) -> Option<AddrChangeEvent> {
        self.receiver.recv().await
    }
}

impl Drop for AsyncAddrListener {
    fn drop(&mut self) {
        // Signal the monitoring thread to shutdown
        self.shutdown.store(true, Ordering::Relaxed);
        debug!("AsyncAddrListener dropping, shutdown signal sent");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_addr_listener_creation() {
        // Test that we can create the listener without panic
        let result = AsyncAddrListener::new(vec![]);
        assert!(result.is_ok());
    }
}
