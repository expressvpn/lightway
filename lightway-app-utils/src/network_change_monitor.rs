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
    ///
    /// `ignore_ips` lists local addresses (the tunnel's own address) that must
    /// not be treated as network changes. On Windows the address listener uses
    /// it to filter out the client's own TUN interface coming up; on other
    /// platforms it is unused.
    pub fn spawn(ignore_ips: Vec<std::net::IpAddr>) -> Result<Self> {
        let (tx, rx) = watch::channel(());

        let task = tokio::spawn(async move {
            #[cfg(not(windows))]
            let _ = ignore_ips;

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
            let mut addr_listener = match AsyncAddrListener::new(ignore_ips) {
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

/// Reduce the system's unicast addresses to those whose appearance or
/// disappearance constitutes a real network change.
///
/// Loopback, link-local and unspecified addresses are configuration noise.
/// `ignore` carries the local tunnel address(es) so the VPN's own interface
/// coming up — which the Windows `NotifyAddrChange` API reports just like any
/// other address change — is not mistaken for a path change. Comparing
/// successive snapshots of this set lets the monitor signal only on genuine
/// changes.
#[cfg(any(windows, test))]
pub(crate) fn relevant_addrs(
    addrs: impl IntoIterator<Item = std::net::IpAddr>,
    ignore: &[std::net::IpAddr],
) -> std::collections::BTreeSet<std::net::IpAddr> {
    addrs
        .into_iter()
        .filter(|ip| {
            !ip.is_loopback() && !ip.is_unspecified() && !is_link_local(ip) && !ignore.contains(ip)
        })
        .collect()
}

#[cfg(any(windows, test))]
fn is_link_local(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_link_local(),
        // Ipv6Addr::is_unicast_link_local is unstable; match fe80::/10 directly.
        std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn tunnel_bringup_is_not_a_network_change() {
        let tun = ip("100.64.0.6");
        let nic = ip("192.168.1.5");
        // Before the tunnel comes up only the physical NIC is present; after
        // bring-up the system also reports the tunnel's own address. With the
        // tunnel address ignored, both snapshots must be identical so the
        // monitor does not mistake its own interface for a path change.
        let before = relevant_addrs([nic], &[tun]);
        let after = relevant_addrs([nic, tun], &[tun]);
        assert_eq!(before, after);
    }

    #[test]
    fn physical_address_change_is_detected() {
        let tun = ip("100.64.0.6");
        let wifi = ip("192.168.1.5");
        let eth = ip("10.0.0.5");
        let before = relevant_addrs([wifi, tun], &[tun]);
        let after = relevant_addrs([eth, tun], &[tun]);
        assert_ne!(before, after);
    }

    #[test]
    fn noise_addresses_are_filtered() {
        let loopback = ip("127.0.0.1");
        let link_local = ip("169.254.1.1");
        let v6_link_local = ip("fe80::1");
        let nic = ip("192.168.1.5");
        assert_eq!(
            relevant_addrs([loopback, link_local, v6_link_local, nic], &[]),
            BTreeSet::from([nic])
        );
    }
}
