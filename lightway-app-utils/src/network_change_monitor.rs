//! Reusable network-change monitor.
//!
//! Spawns the platform route/address listeners and republishes their events as a coalescing
//! [`tokio::sync::watch`] signal. Consumers can [`subscribe`](NetworkChangeMonitor::subscribe) to
//! network changes

#[cfg(windows)]
mod addr_monitor;

use anyhow::Result;
use route_manager::{AsyncRouteListener, RouteChange};
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[cfg(windows)]
use addr_monitor::AsyncAddrListener;

/// Monitors network changes (route and, on Windows, address changes) and
/// publishes a notification each time one is detected.
pub struct NetworkChangeMonitor {
    rx: watch::Receiver<()>,
    task: JoinHandle<()>,
}

impl NetworkChangeMonitor {
    /// Spawn the monitor. The route/address listeners are created inside the
    /// spawned task.
    pub fn spawn() -> Result<Self> {
        let (tx, rx) = watch::channel(());

        let task = tokio::spawn(async move {
            let mut route_listener = match AsyncRouteListener::new() {
                Ok(listener) => listener,
                Err(e) => {
                    tracing::error!("Failed to create AsyncRouteListener: {}", e);
                    return;
                }
            };

            // On Windows, also create address change listener as a fallback
            // since Windows doesn't always publish route changes on network down
            #[cfg(windows)]
            let mut addr_listener = match AsyncAddrListener::new() {
                Ok(listener) => {
                    tracing::info!("Started address change monitoring (Windows)...");
                    Some(listener)
                }
                Err(e) => {
                    tracing::warn!("Failed to create AsyncAddrListener: {}", e);
                    None
                }
            };

            #[cfg(not(windows))]
            let (_sender, addr_listener) = tokio::sync::mpsc::unbounded_channel::<()>();
            #[cfg(not(windows))]
            let mut addr_listener = Some(addr_listener);

            tracing::info!("Started monitoring route/intf...");
            loop {
                tokio::select! {
                   route_result = route_listener.listen() => {
                       match route_result {
                           Ok(route_change) => {
                               tracing::debug!("Route change detected: {:?}", route_change);
                               let (RouteChange::Add(route)
                               | RouteChange::Delete(route)
                               | RouteChange::Change(route)) = &route_change;
                               if route.prefix() == 0
                                   && route.gateway().is_some_and(|gw| !gw.is_unspecified())
                                   && tx.send(()).is_err() {
                                   tracing::debug!("No network change receivers left, stopping monitor");
                                   break;
                               }
                           }
                           Err(e) => {
                               // Continue monitoring even on transient errors
                               tracing::debug!("Error listening for route changes: {}", e);
                               tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                           }
                       }
                   }

                   // On address/intf changes, notify too. This helps catch
                   // network transitions that don't trigger route changes.
                   _ = async {
                       if let Some(listener) = &mut addr_listener {
                           listener.recv().await
                       } else {
                           std::future::pending().await
                       }
                   } => {
                       tracing::debug!("Address change detected");
                       if tx.send(()).is_err() {
                           tracing::debug!("No network change receivers left, stopping monitor");
                           break;
                       }
                   }
                }
            }
        });

        Ok(Self { rx, task })
    }

    /// Get a receiver that fires whenever a network change is detected.
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.rx.clone()
    }
}

impl Drop for NetworkChangeMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}
