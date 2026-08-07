//! Reusable network-change monitor.
//!
//! Spawns the platform route/address listeners and republishes their events as
//! two coalescing [`tokio::sync::watch`] signals: *routes* (an applicable
//! default route changed — the trigger for route-table fixups) and
//! *transitions* (the machine moved networks: on macOS an address change and
//! an applicable route *arrival* — add or change, not delete — within a short
//! window; on Windows any detected change, since route changes are not always
//! published there; never fired on platforms without an address listener).

#[cfg(windows)]
mod addr_monitor;

use anyhow::Result;
use route_manager::{AsyncRouteListener, Route, RouteChange};
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[cfg(windows)]
use addr_monitor::AsyncAddrListener;

#[cfg(any(macos, test))]
use std::time::{Duration, Instant};

/// Generous pairing window: joining a network can assign the address seconds
/// before the default route is installed.
#[cfg(macos)]
const TRANSITION_WINDOW: Duration = Duration::from_secs(15);

/// Minimum spacing between transitions, collapsing event bursts into one.
#[cfg(macos)]
const TRANSITION_COOLDOWN: Duration = Duration::from_secs(3);

/// Monitors network changes and publishes route and transition notifications.
pub struct NetworkChangeMonitor {
    route_rx: watch::Receiver<()>,
    transition_rx: watch::Receiver<()>,
    task: JoinHandle<()>,
}

impl NetworkChangeMonitor {
    /// Spawn the monitor. The route/address listeners are created inside the
    /// spawned task.
    ///
    /// `ignore_ips` lists local addresses (the tunnel's own address) that must
    /// not be treated as network changes. The address listeners use it to
    /// filter out the client's own TUN interface coming up; on platforms
    /// without an address listener it is unused.
    pub fn spawn(ignore_ips: Vec<std::net::IpAddr>) -> Result<Self> {
        let (route_tx, route_rx) = watch::channel(());
        let (transition_tx, transition_rx) = watch::channel(());

        let task = tokio::spawn(async move {
            #[cfg(not(any(windows, macos)))]
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

            #[cfg(macos)]
            let mut addr_listener = Some(spawn_macos_addr_listener(ignore_ips));

            #[cfg(not(any(windows, macos)))]
            let (_sender, addr_listener) = tokio::sync::mpsc::unbounded_channel::<()>();
            #[cfg(not(any(windows, macos)))]
            let mut addr_listener = Some(addr_listener);

            #[cfg(macos)]
            let mut detector = TransitionDetector::new(TRANSITION_WINDOW, TRANSITION_COOLDOWN);

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
                               if is_applicable_route(route) {
                                   let _ = route_tx.send(());
                                   // Only a route *arriving* arms a transition:
                                   // a machine moving networks is signalled by
                                   // the new default route showing up, while
                                   // the old one vanishing (the down-leg of a
                                   // roam) leaves nothing to probe yet.
                                   #[cfg(macos)]
                                   if !matches!(route_change, RouteChange::Delete(_))
                                       && detector.on_route(Instant::now())
                                   {
                                       tracing::info!("Network transition detected");
                                       let _ = transition_tx.send(());
                                   }
                                   #[cfg(windows)]
                                   let _ = transition_tx.send(());
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
                   addr_event = async {
                       if let Some(listener) = &mut addr_listener {
                           listener.recv().await
                       } else {
                           std::future::pending().await
                       }
                   } => {
                       match addr_event {
                           Some(_) => {
                               tracing::debug!("Address change detected");
                               #[cfg(macos)]
                               if detector.on_addr(Instant::now()) {
                                   tracing::info!("Network transition detected");
                                   let _ = transition_tx.send(());
                               }
                               #[cfg(windows)]
                               {
                                   let _ = route_tx.send(());
                                   let _ = transition_tx.send(());
                               }
                           }
                           None => {
                               // Source ended; park it rather than spinning.
                               tracing::debug!("Address listener stopped");
                               addr_listener = None;
                           }
                       }
                   }
                }

                if route_tx.is_closed() && transition_tx.is_closed() {
                    tracing::debug!("No network change receivers left, stopping monitor");
                    break;
                }
            }
        });

        Ok(Self {
            route_rx,
            transition_rx,
            task,
        })
    }

    /// Get a receiver that fires whenever an applicable route changed.
    pub fn subscribe_routes(&self) -> watch::Receiver<()> {
        self.route_rx.clone()
    }

    /// Get a receiver that fires on a network transition (see module docs for
    /// the per-platform semantics).
    pub fn subscribe_transitions(&self) -> watch::Receiver<()> {
        self.transition_rx.clone()
    }
}

impl Drop for NetworkChangeMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A real default-route event: prefix 0 with a proper gateway, excluding
/// macOS interface-scoped defaults (a non-primary service's churn is not a
/// path change).
fn is_applicable_route(route: &Route) -> bool {
    // `Route::if_scope` only exists on macOS.
    #[cfg(macos)]
    if route.if_scope() {
        return false;
    }
    route.prefix() == 0 && route.gateway().is_some_and(|gw| !gw.is_unspecified())
}

/// Bridge netwatcher's interface updates to a unit-event channel, diffing our
/// own snapshot of the relevant address set rather than trusting the update's
/// diff (which can be empty, e.g. on address reordering).
#[cfg(macos)]
fn spawn_macos_addr_listener(
    ignore_ips: Vec<std::net::IpAddr>,
) -> tokio::sync::mpsc::UnboundedReceiver<()> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut watcher =
            match netwatcher::watch_interfaces_async::<netwatcher::async_adapter::Tokio>() {
                Ok(w) => {
                    tracing::info!("Started address change monitoring (macOS)...");
                    w
                }
                Err(e) => {
                    tracing::warn!("Failed to start macOS address listener: {e}");
                    return;
                }
            };

        // The first `changed()` yields the initial snapshot; it only seeds.
        let mut prev: Option<std::collections::BTreeSet<std::net::IpAddr>> = None;
        loop {
            let update = watcher.changed().await;
            let now = relevant_addrs(
                update
                    .interfaces
                    .values()
                    .flat_map(|iface| iface.ips.iter().map(|record| record.ip)),
                &ignore_ips,
            );
            let is_change = prev.as_ref().is_some_and(|p| *p != now);
            prev = Some(now);
            if is_change && tx.send(()).is_err() {
                // Monitor dropped; returning drops the watcher.
                break;
            }
        }
    });
    rx
}

/// Detects a network transition: an address change and an applicable route
/// arrival (in either order) within `window` of each other, rate-limited by
/// `cooldown`. An emitted pair is consumed. The caller filters route deletes
/// out before feeding `on_route`.
#[cfg(any(macos, test))]
struct TransitionDetector {
    window: Duration,
    cooldown: Duration,
    last_addr: Option<Instant>,
    last_route: Option<Instant>,
    last_emit: Option<Instant>,
}

#[cfg(any(macos, test))]
impl TransitionDetector {
    fn new(window: Duration, cooldown: Duration) -> Self {
        Self {
            window,
            cooldown,
            last_addr: None,
            last_route: None,
            last_emit: None,
        }
    }

    /// Returns true when the event at `now` completes a transition.
    fn on_addr(&mut self, now: Instant) -> bool {
        self.last_addr = Some(now);
        self.try_emit(now)
    }

    /// Returns true when the event at `now` completes a transition.
    fn on_route(&mut self, now: Instant) -> bool {
        self.last_route = Some(now);
        self.try_emit(now)
    }

    fn try_emit(&mut self, now: Instant) -> bool {
        let (Some(addr), Some(route)) = (self.last_addr, self.last_route) else {
            return false;
        };
        let paired =
            now.duration_since(addr) <= self.window && now.duration_since(route) <= self.window;
        let cooled = self
            .last_emit
            .is_none_or(|e| now.duration_since(e) >= self.cooldown);
        if paired && cooled {
            // Consume the pair.
            self.last_addr = None;
            self.last_route = None;
            self.last_emit = Some(now);
            true
        } else {
            false
        }
    }
}

/// Reduce the system's unicast addresses to those whose appearance or
/// disappearance constitutes a real network change.
///
/// Loopback, link-local and unspecified addresses are configuration noise.
/// `ignore` carries the local tunnel address(es) so the VPN's own interface
/// coming up — which the platform address listeners report just like any
/// other address change — is not mistaken for a path change. Comparing
/// successive snapshots of this set lets the monitor signal only on genuine
/// changes.
#[cfg(any(windows, macos, test))]
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

#[cfg(any(windows, macos, test))]
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

    const WINDOW: Duration = Duration::from_secs(15);
    const COOLDOWN: Duration = Duration::from_secs(3);

    fn detector() -> (TransitionDetector, Instant) {
        (TransitionDetector::new(WINDOW, COOLDOWN), Instant::now())
    }

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn route_churn_alone_is_not_a_transition() {
        let (mut d, t0) = detector();
        assert!(!d.on_route(at(t0, 0)));
        assert!(!d.on_route(at(t0, 1)));
        assert!(!d.on_route(at(t0, 30)));
    }

    #[test]
    fn addr_change_alone_is_not_a_transition() {
        let (mut d, t0) = detector();
        assert!(!d.on_addr(at(t0, 0)));
        assert!(!d.on_addr(at(t0, 20)));
    }

    #[test]
    fn addr_then_route_within_window_is_a_transition() {
        let (mut d, t0) = detector();
        // Join sequence: DHCP address first, default route seconds later.
        assert!(!d.on_addr(at(t0, 0)));
        assert!(d.on_route(at(t0, 5)));
    }

    #[test]
    fn route_then_addr_within_window_is_a_transition() {
        let (mut d, t0) = detector();
        // Leave sequence: route-delete and addr-delete land together.
        assert!(!d.on_route(at(t0, 0)));
        assert!(d.on_addr(at(t0, 1)));
    }

    #[test]
    fn stale_pair_outside_window_is_not_a_transition() {
        let (mut d, t0) = detector();
        assert!(!d.on_addr(at(t0, 0)));
        // Route arrives after the address evidence expired ...
        assert!(!d.on_route(at(t0, 20)));
        // ... but fresh address evidence pairs with the still-recent route.
        assert!(d.on_addr(at(t0, 21)));
    }

    #[test]
    fn emitted_pair_is_consumed() {
        let (mut d, t0) = detector();
        assert!(!d.on_addr(at(t0, 0)));
        assert!(d.on_route(at(t0, 1)));
        // Burst continues: single legs alone must not re-fire.
        assert!(!d.on_route(at(t0, 2)));
        assert!(!d.on_addr(at(t0, 30)));
    }

    #[test]
    fn cooldown_suppresses_back_to_back_transitions() {
        let (mut d, t0) = detector();
        assert!(!d.on_addr(at(t0, 0)));
        assert!(d.on_route(at(t0, 1)));
        // A full new pair within the cooldown stays suppressed ...
        assert!(!d.on_addr(at(t0, 2)));
        assert!(!d.on_route(at(t0, 3)));
        // ... and emits once the cooldown has passed (evidence still fresh).
        assert!(d.on_addr(at(t0, 5)));
    }
}
