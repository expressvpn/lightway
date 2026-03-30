#![allow(unsafe_code)]
use anyhow::Result;
use futures::Stream;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tracing::{debug, error};

use windows_sys::Win32::{
    Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT},
    NetworkManagement::IpHelper::NotifyAddrChange,
    System::IO::OVERLAPPED,
    System::Threading::{CreateEventW, ResetEvent, WaitForSingleObject},
};

/// Represents different types of address changes that can be monitored
#[derive(Debug, Clone, PartialEq)]
pub enum AddrChangeEvent {
    /// An address was added to an interface
    AddressAdded,
    /// An address was removed from an interface
    AddressRemoved,
    /// An address configuration changed
    AddressChanged,
    /// Network interface state changed (up/down)
    InterfaceStateChanged,
}

/// Async stream for monitoring Windows address changes
pub struct AsyncAddrListener {
    receiver: mpsc::UnboundedReceiver<AddrChangeEvent>,
    _join_handle: tokio::task::JoinHandle<()>,
    shutdown: Arc<AtomicBool>,
}

impl AsyncAddrListener {
    /// Creates a new AsyncAddrListener for monitoring address changes
    pub fn new() -> Result<Self> {
        let (sender, receiver) = mpsc::unbounded_channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = shutdown.clone();

        let join_handle = tokio::task::spawn_blocking(move || {
            if let Err(e) = Self::monitor_address_changes(sender, shutdown_clone) {
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

impl Stream for AsyncAddrListener {
    type Item = AddrChangeEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_recv(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn test_addr_listener_creation() {
        // Test that we can create the listener without panic
        let result = AsyncAddrListener::new();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_addr_listener_as_stream() {
        let listener = AsyncAddrListener::new().unwrap();
        let stream = listener.take(1); // Take only 1 event for test

        // This test would hang waiting for actual address changes, so we just verify
        // that we can create the stream without error
        // To properly test, you'd need to trigger an address change during the test
        drop(stream);
    }
}
