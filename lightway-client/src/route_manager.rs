use anyhow::Result;
use route_manager::{AsyncRouteManager, Route, RouteManager as SyncRouteManager};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{trace, warn};

#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;

#[cfg(windows)]
use crate::platform::windows::utils;

// LAN networks for RouteMode::Lan
const LAN_NETWORKS: [(IpAddr, u8); 5] = [
    (
        // RFC 1918 Class C private
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        16,
    ),
    (
        // RFC 1918 Class B private
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
        12,
    ),
    (
        // RFC 1918 Class A private,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        8,
    ),
    (
        // RFC 3927 link-local
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        16,
    ),
    (
        // RFC 5771 multicast
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        24,
    ),
];

// Tunnel routes for high priority default routing
const TUNNEL_ROUTES: [(IpAddr, u8); 2] = [
    (
        // First half default route (0.0.0.0/1)
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        1,
    ),
    (
        // Second half default route (128.0.0.0/1)
        IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        1,
    ),
];

// IPv6 sink routes: both halves of the IPv6 space, sent to a blackhole so the
// traffic cannot bypass the tunnel (see `ipv6_sink_routes`)
const IPV6_SINK_ROUTES: [(IpAddr, u8); 2] = [
    (
        // First half (::/1)
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        1,
    ),
    (
        // Second half (8000::/1)
        IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
        1,
    ),
];

// RFC 4193 unique local addresses, kept out of the IPv6 sink in RouteMode::Lan
const IPV6_LAN_NETWORK: (IpAddr, u8) = (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7);

#[derive(
    Debug, PartialEq, Copy, Clone, clap::ValueEnum, JsonSchema, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum RouteMode {
    #[default]
    Default,
    Lan,
    NoExec,
}

#[derive(Error, Debug)]
pub enum RoutingTableError {
    #[error("AsyncRoutingManager error {0}")]
    AsyncRoutingManagerError(std::io::Error),
    #[error("Failed to Add {0}: {1}")]
    AddRouteError(Route, std::io::Error),
    #[error("Default interface not found: {0}")]
    DefaultInterfaceNotFound(std::io::Error),
    #[error("Default route not found")]
    DefaultRouteNotFound,
    #[error("Interface index not found")]
    InterfaceIndexNotFound,
    #[error("Interface gateway not found")]
    InterfaceGatewayNotFound,
    #[error(
        "Insufficient permissions to modify routing table. Run with administrator/root privileges."
    )]
    InsufficientPermissions,
    #[error("RoutingManager error {0}")]
    RoutingManagerError(std::io::Error),
    #[error("Server route already exists, try modifying it instead")]
    ServerRouteAlreadyExists,
}

/// Returns the host prefix length for an IP address
/// (32 bits for IPv4, 128 bits for IPv6)
fn host_prefix_len(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => Ipv4Addr::BITS as u8,
        IpAddr::V6(_) => Ipv6Addr::BITS as u8,
    }
}

/// Checks if two IP addresses are from the same address family
/// (both IPv4 or both IPv6)
fn same_ip_family(ip1: &IpAddr, ip2: &IpAddr) -> bool {
    matches!(
        (ip1, ip2),
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
    )
}

/// Whether a routing table entry is the host's default route: an
/// unspecified destination with prefix 0.
///
/// The destination test is not redundant with the prefix: `route_manager`
/// reports prefix 0 for a route whose netmask it could not read.
///
/// macOS also keeps an interface-scoped default route (`RTF_IFSCOPE`) for
/// every interface, utun included, which the kernel only uses for sockets
/// bound to that interface. Unbound traffic never takes them.
fn is_host_default_route(route: &Route) -> bool {
    if route.prefix() != 0 || !route.destination().is_unspecified() {
        return false;
    }
    #[cfg(macos)]
    if route.if_scope() {
        return false;
    }
    true
}

/// Routes that steer all IPv6 traffic into a blackhole, because the tunnel
/// carries IPv4 only.
///
/// On macOS they are gateway routes via `::1`: the kernel binds them to the
/// loopback interface and discards the looped-back packets, since their
/// destination is not local and forwarding is off. (An interface route on
/// the TUN is refused with ENETUNREACH because the TUN has no IPv6 address.)
/// On Linux they are device routes on `lo`, discarded the same way. On
/// Windows the TUN adapter carries a link-local address, so they are
/// interface routes on the TUN and the inside path drops what arrives.
///
/// Link-local (fe80::/10) and multicast (ff00::/8) keep their more specific
/// on-link routes on all three platforms, and when the outside connection is
/// IPv6 the /128 server route wins over these /1 halves.
fn ipv6_sink_routes(#[cfg(windows)] tun_index: u32) -> Vec<Route> {
    IPV6_SINK_ROUTES
        .iter()
        .map(|&(network, prefix)| {
            let route = Route::new(network, prefix);
            #[cfg(macos)]
            let route = route.with_gateway(IpAddr::V6(Ipv6Addr::LOCALHOST));
            #[cfg(linux)]
            let route = route.with_if_name("lo".to_string());
            #[cfg(windows)]
            let route = route.with_if_index(tun_index).with_metric(0);
            route
        })
        .collect()
}

/// Whether `err` says the host has no IPv6 address family at all (Linux
/// booted with `ipv6.disable=1`, Windows with the IPv6 stack disabled).
fn ipv6_unsupported_error(err: &std::io::Error) -> bool {
    #[cfg(unix)]
    let unsupported = libc::EAFNOSUPPORT;
    #[cfg(windows)]
    let unsupported = windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT;
    err.raw_os_error() == Some(unsupported)
}

/// Decide from an IPv6 socket probe whether the sink has anything to do.
/// Only a missing address family says no; any other failure keeps the sink
/// on, so a transient error cannot quietly switch it off.
fn ipv6_available_from_probe(probe: Result<(), std::io::Error>) -> bool {
    match probe {
        Ok(()) => true,
        Err(err) if ipv6_unsupported_error(&err) => false,
        Err(err) => {
            tracing::debug!("IPv6 socket probe failed, assuming IPv6 is available: {err}");
            true
        }
    }
}

/// Probe the host for an IPv6 stack by opening, and dropping, an IPv6
/// datagram socket. Unprivileged, and independent of current connectivity,
/// which can change while connected.
fn host_has_ipv6() -> bool {
    let probe = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None).map(drop);
    ipv6_available_from_probe(probe)
}

pub struct RouteManager {
    inner: Option<RouteManagerInner>,
    task: Option<JoinHandle<()>>,
}

struct RouteManagerInner {
    routing_mode: RouteMode,
    block_ipv6: bool,
    route_manager: SyncRouteManager,
    route_manager_async: AsyncRouteManager,
    server_ip: IpAddr,
    tun_index: u32,
    tun_peer_ip: IpAddr,
    tun_dns_ip: IpAddr,
    vpn_routes: Vec<Route>,
    lan_routes: Vec<Route>,
    server_route: Option<Route>,
}

impl RouteManager {
    pub fn new(
        routing_mode: RouteMode,
        block_ipv6: bool,
        server_ip: IpAddr,
        tun_index: u32,
        tun_peer_ip: IpAddr,
        tun_dns_ip: IpAddr,
    ) -> Result<Self, RoutingTableError> {
        let inner = Some(RouteManagerInner::new(
            routing_mode,
            block_ipv6,
            server_ip,
            tun_index,
            tun_peer_ip,
            tun_dns_ip,
        )?);
        Ok(Self { inner, task: None })
    }

    /// Install the routes required to use the tunnel (NoExec installs
    /// nothing) and hand back the per-event updater. The task that takes
    /// ownership of the updater should be registered with [`Self::set_task`]
    /// so [`Self::stop`] can abort it and await route cleanup.
    pub async fn start(&mut self) -> Result<RouteUpdater, RoutingTableError> {
        let Some(mut inner) = self.inner.take() else {
            return Err(RoutingTableError::InsufficientPermissions);
        };

        inner.install_routes().await?;
        Ok(RouteUpdater { inner })
    }

    /// Register the task owning the [`RouteUpdater`] returned by
    /// [`Self::start`].
    pub fn set_task(&mut self, task: JoinHandle<()>) {
        self.task = Some(task);
    }

    pub async fn stop(&mut self) -> Result<(), RoutingTableError> {
        if let Some(task) = self.task.take() {
            task.abort();

            // Wait till the task finishes to clear routes
            let _ = task.await;
        }

        Ok(())
    }
}

/// Owns the routes installed by [`RouteManager::start`]; dropping it removes
/// them. Exposes the per-network-event maintenance step.
pub struct RouteUpdater {
    inner: RouteManagerInner,
}

impl RouteUpdater {
    /// Refresh the server route if the default route changed (a no-op in
    /// NoExec mode). Returns whether the server route was actually replaced.
    pub async fn check_and_update_server_route(&mut self) -> Result<bool, RoutingTableError> {
        if self.inner.routing_mode == RouteMode::NoExec {
            return Ok(false);
        }
        self.inner.check_and_update_server_route().await
    }
}

impl RouteManagerInner {
    fn new(
        routing_mode: RouteMode,
        block_ipv6: bool,
        server_ip: IpAddr,
        tun_index: u32,
        tun_peer_ip: IpAddr,
        tun_dns_ip: IpAddr,
    ) -> Result<Self, RoutingTableError> {
        let route_manager =
            SyncRouteManager::new().map_err(RoutingTableError::RoutingManagerError)?;
        let route_manager_async =
            AsyncRouteManager::new().map_err(RoutingTableError::AsyncRoutingManagerError)?;
        Ok(Self {
            routing_mode,
            block_ipv6,
            route_manager,
            route_manager_async,
            server_ip,
            tun_index,
            tun_peer_ip,
            tun_dns_ip,
            vpn_routes: Vec::with_capacity(TUNNEL_ROUTES.len() + IPV6_SINK_ROUTES.len() + 1),
            lan_routes: Vec::with_capacity(LAN_NETWORKS.len() + 1),
            server_route: None,
        })
    }

    #[cfg(macos)]
    fn get_route_metric(_route: &Route) -> u32 {
        0
    }

    #[cfg(any(windows, linux))]
    fn get_route_metric(route: &Route) -> u32 {
        let route_metric = route.metric().unwrap_or(0);

        // On Windows, get interface metric and add it to route metric
        #[cfg(windows)]
        let route_metric = {
            let interface_metric = if let Some(if_index) = route.if_index() {
                utils::get_interface_metric(if_index).unwrap_or(u32::MAX)
            } else {
                u32::MAX
            };
            route_metric.saturating_add(interface_metric)
        };
        route_metric
    }

    /// Identifies 0.0.0.0 route with least metric if applicable
    /// Or the first found 0.0.0.0 route.
    /// (Route metrics is applicable only in windows and linux Os)
    fn find_best_default_route(&mut self, server_ip: &IpAddr) -> Result<Route, RoutingTableError> {
        tracing::trace!("Finding best default route for server IP: {}", server_ip);

        let routes = self
            .route_manager
            .list()
            .map_err(RoutingTableError::DefaultInterfaceNotFound)?;

        let mut best_route: Option<Route> = None;

        for route in routes {
            // Skip IPv6 routes if we're looking for IPv4, and vice versa
            if server_ip.is_ipv4() != route.destination().is_ipv4() {
                continue;
            }

            // Not the host's default route, skip
            if !is_host_default_route(&route) {
                continue;
            }

            tracing::trace!(
                "Checking route: dest={}, prefix={}, gateway={:?}, if_index={:?}, metric={:?}",
                route.destination(),
                route.prefix(),
                route.gateway(),
                route.if_index(),
                Self::get_route_metric(&route),
            );

            // For windows, linux, use metric to choose best default route
            #[cfg(any(linux, windows))]
            {
                let route_metric = Self::get_route_metric(&route);
                let best_metric = best_route
                    .as_ref()
                    .map(Self::get_route_metric)
                    .unwrap_or(u32::MAX);

                match route_metric.cmp(&best_metric) {
                    std::cmp::Ordering::Less => {
                        tracing::trace!("New best route found with better route metric");
                        best_route = Some(route);
                    }
                    std::cmp::Ordering::Equal => {
                        if let Some(server_route) = self.server_route.as_ref()
                            && *server_route == route
                        {
                            tracing::trace!("Same route metric, but choosing previous best route");
                            best_route = Some(route);
                        }
                    }
                    std::cmp::Ordering::Greater => {
                        tracing::trace!("Route route metric is not better than current best");
                    }
                };
            }
            // For other platforms, choose the first route available
            #[cfg(not(any(linux, windows)))]
            {
                tracing::trace!("Using first available default route");
                best_route = Some(route);
                break;
            }
        }

        match &best_route {
            Some(route) => {
                tracing::trace!("Best {} selected", route);
            }
            None => {
                tracing::trace!("No suitable route found");
            }
        }

        best_route.ok_or(RoutingTableError::DefaultRouteNotFound)
    }

    /// Identifies route used to reach a particular ip
    fn find_route(&mut self, server_ip: &IpAddr) -> Result<Route, RoutingTableError> {
        self.route_manager
            .find_route(server_ip)
            .map_err(RoutingTableError::DefaultInterfaceNotFound)?
            .ok_or(RoutingTableError::DefaultRouteNotFound)
    }

    /// Identifies default interface by finding the route to be used to access server_ip
    /// Returns the interface index and optional gateway. Gateway is None for direct routes
    /// (common in Docker containers and direct network connections).
    fn find_default_interface_index_and_gateway(
        &mut self,
        server_ip: &IpAddr,
    ) -> Result<(u32, Option<IpAddr>), RoutingTableError> {
        let default_route = self.find_route(server_ip)?;
        let default_interface_index = default_route
            .if_index()
            .ok_or(RoutingTableError::InterfaceIndexNotFound)?;
        // Gateway is optional - None for direct routes (e.g., in containers)
        let default_interface_gateway = default_route.gateway();
        Ok((default_interface_index, default_interface_gateway))
    }

    /// Adds Route
    async fn add_route(&mut self, route: &Route) -> Result<(), RoutingTableError> {
        match self.route_manager_async.add(route).await {
            Ok(()) => {
                tracing::info!("Added {route}");
                Ok(())
            }
            Err(e) => {
                if self.is_route_exists_error(&e) {
                    // Ignore error if route already exists and
                    // keep the existing route
                    Ok(())
                } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                    Err(RoutingTableError::InsufficientPermissions)
                } else {
                    Err(RoutingTableError::AddRouteError(route.clone(), e))
                }
            }
        }
    }

    fn is_route_exists_error(&self, error: &std::io::Error) -> bool {
        match error.raw_os_error() {
            #[cfg(any(target_os = "linux", target_os = "macos",))]
            Some(libc::EEXIST) => true,
            #[cfg(windows)]
            Some(code) => code == ERROR_OBJECT_ALREADY_EXISTS as i32,
            _ => false,
        }
    }

    /// Adds Routes and stores it
    async fn add_route_vpn(&mut self, route: Route) -> Result<(), RoutingTableError> {
        self.add_route(&route).await?;
        self.vpn_routes.push(route);
        Ok(())
    }

    /// Adds Server Route and stores it
    async fn add_route_server(&mut self, route: Route) -> Result<(), RoutingTableError> {
        if self.server_route.is_some() {
            return Err(RoutingTableError::ServerRouteAlreadyExists);
        }
        self.add_route(&route).await?;
        self.server_route = Some(route);
        Ok(())
    }

    /// Adds LAN Route and stores it
    async fn add_route_lan(&mut self, route: Route) -> Result<(), RoutingTableError> {
        self.add_route(&route).await?;
        self.lan_routes.push(route);
        Ok(())
    }

    /// Clean up for program unwind
    fn cleanup_sync(&mut self) {
        for route in &self.vpn_routes {
            if let Err(e) = self.route_manager.delete(route) {
                warn!(
                    "Failed to delete VPN route during drop: {}, error: {}",
                    route, e
                );
            }
        }

        for route in &self.lan_routes {
            if let Err(e) = self.route_manager.delete(route) {
                warn!(
                    "Failed to delete LAN route during drop: {}, error: {}",
                    route, e
                );
            }
        }

        if let Some(route) = &self.server_route
            && let Err(e) = self.route_manager.delete(route)
        {
            warn!(
                "Failed to delete server route during drop: {}, error: {}",
                route, e
            );
        }
        trace!("Inner route manager cleaned up");
    }

    async fn install_routes(&mut self) -> Result<(), RoutingTableError> {
        if self.routing_mode == RouteMode::NoExec {
            return Ok(());
        }

        let server_ip = self.server_ip;

        // Setting up VPN Server Routes
        let (default_interface_index, default_interface_gateway) =
            self.find_default_interface_index_and_gateway(&server_ip)?;

        // Create server route with optional gateway - handles both direct routes (containers)
        // and routed networks (host systems with gateways)
        let prefix = host_prefix_len(&server_ip);
        let server_route = Route::new(server_ip, prefix).with_if_index(default_interface_index);
        let server_route = match default_interface_gateway {
            Some(gateway) => server_route.with_gateway(gateway),
            None => server_route,
        };

        #[cfg(windows)]
        let server_route = server_route.with_metric(0);

        self.add_route_server(server_route).await?;

        if self.routing_mode == RouteMode::Lan {
            for (network, prefix) in LAN_NETWORKS {
                let mut lan_route =
                    Route::new(network, prefix).with_if_index(default_interface_index);
                // Only use gateway if it matches the route's address family
                if let Some(gw) = default_interface_gateway
                    && same_ip_family(&network, &gw)
                {
                    lan_route = lan_route.with_gateway(gw);
                }
                #[cfg(windows)]
                let lan_route = lan_route.with_metric(0);
                self.add_route_lan(lan_route).await?;
            }
        }

        // Add standard tunnel routes (high priority default routing)
        for (network, prefix) in TUNNEL_ROUTES {
            let tunnel_route = Route::new(network, prefix)
                .with_gateway(self.tun_peer_ip)
                .with_if_index(self.tun_index);

            #[cfg(windows)]
            let tunnel_route = tunnel_route.with_metric(0);

            self.add_route_vpn(tunnel_route).await?;
        }

        // Add DNS route separately since it's not a constant
        let dns_route = Route::new(self.tun_dns_ip, host_prefix_len(&self.tun_dns_ip))
            .with_gateway(self.tun_peer_ip)
            .with_if_index(self.tun_index);
        #[cfg(windows)]
        let dns_route = dns_route.with_metric(0);

        self.add_route_vpn(dns_route).await?;

        if self.block_ipv6 {
            self.install_ipv6_sink().await?;
        } else {
            warn!("IPv6 traffic is not routed through the tunnel");
        }
        Ok(())
    }

    /// Route all IPv6 traffic into a blackhole (see [`ipv6_sink_routes`]).
    /// In [`RouteMode::Lan`] unique local addresses keep following the
    /// current IPv6 default route so LAN IPv6 still works.
    async fn install_ipv6_sink(&mut self) -> Result<(), RoutingTableError> {
        if !host_has_ipv6() {
            tracing::info!("IPv6 is unavailable on this host; nothing to discard");
            return Ok(());
        }
        #[cfg(windows)]
        if !utils::interface_has_ipv6(self.tun_index) {
            warn!(
                "IPv6 is not bound to the tunnel adapter; IPv6 traffic is not routed through the tunnel"
            );
            return Ok(());
        }

        if self.routing_mode == RouteMode::Lan {
            self.install_ipv6_lan_route().await;
        }

        for sink_route in ipv6_sink_routes(
            #[cfg(windows)]
            self.tun_index,
        ) {
            self.add_route_vpn(sink_route).await?;
        }

        tracing::info!("IPv6 traffic is discarded while connected");
        Ok(())
    }

    /// Keep fc00::/7 on the interface (and gateway) of the current IPv6
    /// default route. Best effort: without an IPv6 default route there is no
    /// IPv6 LAN to keep, and a failure here must not stop the connection.
    async fn install_ipv6_lan_route(&mut self) {
        let (network, prefix) = IPV6_LAN_NETWORK;

        let default_route = match self.find_best_default_route(&network) {
            Ok(route) => route,
            Err(e) => {
                tracing::debug!("No IPv6 default route, not adding an IPv6 LAN route: {e}");
                return;
            }
        };
        let Some(if_index) = default_route.if_index() else {
            tracing::debug!("IPv6 default route has no interface, not adding an IPv6 LAN route");
            return;
        };

        let mut lan_route = Route::new(network, prefix).with_if_index(if_index);
        // Only use gateway if it matches the route's address family
        if let Some(gw) = default_route.gateway()
            && same_ip_family(&network, &gw)
        {
            lan_route = lan_route.with_gateway(gw);
        }
        #[cfg(windows)]
        let lan_route = lan_route.with_metric(0);

        if let Err(e) = self.add_route_lan(lan_route).await {
            warn!("Failed to add IPv6 LAN route, LAN IPv6 is routed into the tunnel: {e}");
        }
    }

    /// Check if server route needs updating due to network changes. Returns
    /// whether the server route was actually replaced.
    async fn check_and_update_server_route(&mut self) -> Result<bool, RoutingTableError> {
        // Find the current default route to the server
        let server_ip = self.server_ip;
        let current_route = self.find_best_default_route(&server_ip)?;
        let current_gateway = current_route.gateway();
        let current_if_index = current_route.if_index();

        if let Some(server_route) = &self.server_route {
            let server_gateway = server_route.gateway();
            let server_if_index = server_route.if_index();

            // Check if the route to the server has changed
            if server_gateway != current_gateway || server_if_index != current_if_index {
                tracing::debug!(
                    "Default route changed - old (interface, gateway): ({:?}, {:?}), new (interface, gateway): ({:?}, {:?})",
                    server_gateway,
                    server_if_index,
                    current_gateway,
                    current_if_index
                );

                // Update server route with new gateway/interface
                if let Some(old_route) = self.server_route.take() {
                    // Remove old route
                    let _ = self.route_manager_async.delete(&old_route).await;
                }

                // Add new route with current gateway and interface
                let prefix = host_prefix_len(&self.server_ip);
                let mut new_server_route = Route::new(self.server_ip, prefix);
                if let Some(if_index) = current_if_index {
                    new_server_route = new_server_route.with_if_index(if_index);
                }
                if let Some(gateway) = current_gateway {
                    new_server_route = new_server_route.with_gateway(gateway);
                }
                #[cfg(windows)]
                let new_server_route = new_server_route.with_metric(0);

                self.add_route_server(new_server_route).await?;

                tracing::info!("Updated server route for network change");
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl Drop for RouteManagerInner {
    fn drop(&mut self) {
        self.cleanup_sync();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use test_case::test_case;
    use tokio;
    use tun_rs::{AsyncDevice, DeviceBuilder};

    const EXTERNAL_IP_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    const EXTERNAL_IP_V6: IpAddr =
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888));
    const TEST_TARGET_IP1: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));
    const TEST_TARGET_IP2: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 2));
    const TEST_TARGET_IP3: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 3));

    const TUN_LOCAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 49, 0, 1));
    const TUN_PEER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 49, 0, 2));
    const TUN_DNS_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));
    const ROUTE_TEST_IP1: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    const ROUTE_TEST_IP2: IpAddr = IpAddr::V4(Ipv4Addr::new(200, 1, 1, 1));

    /// Helper to create test routes with gateway lookup
    fn create_test_routes_with_gateway(
        route_manager: &mut RouteManagerInner,
    ) -> (Route, Route, Route, IpAddr) {
        let default_route = route_manager.find_route(&EXTERNAL_IP_V4).unwrap();
        let gateway_ip = default_route.gateway().unwrap();

        let route1 =
            Route::new(TEST_TARGET_IP1, host_prefix_len(&TEST_TARGET_IP1)).with_gateway(gateway_ip);
        let route2 =
            Route::new(TEST_TARGET_IP2, host_prefix_len(&TEST_TARGET_IP2)).with_gateway(gateway_ip);
        let route3 =
            Route::new(TEST_TARGET_IP3, host_prefix_len(&TEST_TARGET_IP3)).with_gateway(gateway_ip);

        (route1, route2, route3, gateway_ip)
    }

    /// Whether `route`, as listed by the system, is the installed form of
    /// the sink route `expected`: same destination and the platform's
    /// blackhole target (loopback gateway, loopback device or TUN index).
    fn sink_route_installed(route: &Route, expected: &Route) -> bool {
        if route.destination() != expected.destination() || route.prefix() != expected.prefix() {
            return false;
        }
        #[cfg(macos)]
        return route.gateway() == expected.gateway();
        #[cfg(linux)]
        return route.if_name() == expected.if_name();
        #[cfg(windows)]
        return route.if_index() == expected.if_index();
    }

    /// Whether every IPv6 sink route is present in `routes`
    fn ipv6_sink_routes_in_system(routes: &[Route], #[cfg(windows)] tun_index: u32) -> bool {
        ipv6_sink_routes(
            #[cfg(windows)]
            tun_index,
        )
        .iter()
        .all(|expected| routes.iter().any(|r| sink_route_installed(r, expected)))
    }

    /// Whether any IPv6 sink route is present in `routes`
    fn any_ipv6_sink_route_in_system(routes: &[Route], #[cfg(windows)] tun_index: u32) -> bool {
        ipv6_sink_routes(
            #[cfg(windows)]
            tun_index,
        )
        .iter()
        .any(|expected| routes.iter().any(|r| sink_route_installed(r, expected)))
    }

    /// Compares two routes for equality based on destination, prefix, gateway, and interface
    fn routes_equal(route1: &Route, route2: &Route) -> bool {
        route1.destination() == route2.destination()
            && route1.prefix() == route2.prefix()
            && route1.gateway() == route2.gateway()
            && route1.if_index() == route2.if_index()
    }

    /// Creates a test setup with RouteRestorer, TUN device, and RouteManagerInner
    /// Returns tuple where RouteRestorer is dropped last for proper cleanup
    async fn create_test_setup(
        route_mode: RouteMode,
        server_ip: IpAddr,
    ) -> Result<(RouteRestorer, AsyncDevice, RouteManagerInner), Box<dyn std::error::Error>> {
        // Capture initial state FIRST
        let restorer = RouteRestorer::new();

        // Create TUN device (tunnel remains IPv4)
        let tun_device = DeviceBuilder::new()
            .ipv4(
                match TUN_LOCAL_IP {
                    IpAddr::V4(ipv4) => ipv4,
                    IpAddr::V6(_) => return Err("IPv6 not supported for test".into()),
                },
                24,
                None,
            )
            .enable(true)
            .build_async()?;

        // Add 50ms sleep to allow TUN device to be fully initialized
        // NOTE: This sometimes adds an additional route after the tests have stored the initial route
        //       which may lead to inaccurate tests. 50ms is eternity and enough to stabilise this.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let tun_index = tun_device.if_index()?;

        // For IPv6 server testing, ensure a usable mock default IPv6 route exists
        // This allows find_route to work even if the system doesn't have IPv6 configured
        if server_ip.is_ipv6() {
            let mut route_manager = SyncRouteManager::new()?;
            let routes = route_manager.list()?;

            // Check if any IPv6 default route exists with a non-link-local gateway
            // Link-local gateways (fe80::/10) can't route global IPv6 traffic
            let has_usable_ipv6_default = routes
                .iter()
                .filter(|r| r.destination().is_ipv6() && r.prefix() == 0)
                .any(|r| {
                    matches!(r.gateway(), Some(IpAddr::V6(gw))
                        // Check if gateway is NOT link-local (fe80::/10)
                        // Link-local addresses have first 10 bits as 1111111010
                        if (gw.segments()[0] & 0xffc0) != 0xfe80)
                });

            if !has_usable_ipv6_default {
                // Find loopback interface index
                // Loopback is typically index 1 on most systems, but we'll search for it
                let loopback_index = route_manager
                    .list()?
                    .iter()
                    .find(|r| {
                        // Look for loopback by finding route to ::1
                        r.destination() == IpAddr::V6(Ipv6Addr::LOCALHOST)
                    })
                    .and_then(|r| r.if_index())
                    .unwrap_or(1); // Default to 1 if not found (standard loopback index)

                // Add a mock IPv6 default route via loopback interface
                // Use ::1 (IPv6 loopback) as the gateway
                // This will be cleaned up by RouteRestorer
                let mock_ipv6_default = Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                    .with_if_index(loopback_index)
                    .with_gateway(IpAddr::V6(Ipv6Addr::LOCALHOST));

                let _ = route_manager.add(&mock_ipv6_default);
            }
        }

        // Create RouteManagerInner directly for testing
        let route_manager = RouteManagerInner::new(
            route_mode,
            true,
            server_ip,
            tun_index,
            TUN_PEER_IP,
            TUN_DNS_IP,
        )?;

        // Return tuple - RouteManagerInner will be dropped first, then TUN device, RouteRestorer last
        Ok((restorer, tun_device, route_manager))
    }

    /// Test wrapper around RouteManager for cleanup purposes
    struct RouteRestorer {
        initial_routes: Vec<Route>,
    }

    impl RouteRestorer {
        fn new() -> Self {
            let mut route_manager = SyncRouteManager::new().unwrap();
            let initial_routes = route_manager.list().unwrap();
            Self { initial_routes }
        }
    }

    impl Drop for RouteRestorer {
        /// Restores the system routing table to match the target routes
        /// Removes routes that shouldn't be there and adds routes that should be there
        fn drop(&mut self) {
            let mut route_manager = SyncRouteManager::new().unwrap();
            let current_routes = route_manager.list().unwrap_or_default();

            // Remove routes that are in current but not in target
            for current_route in &current_routes {
                let should_keep = self
                    .initial_routes
                    .iter()
                    .any(|target_route| routes_equal(current_route, target_route));

                if !should_keep {
                    let _ = route_manager.delete(current_route);
                }
            }

            // Add routes that are in target but not in current
            for target_route in self.initial_routes.iter() {
                let already_exists = current_routes
                    .iter()
                    .any(|current_route| routes_equal(current_route, target_route));

                if !already_exists {
                    let _ = route_manager.add(target_route);
                }
            }
        }
    }

    #[derive(Debug)]
    enum RouteAddMethod {
        Standard,
        Server,
        Lan,
    }

    #[test]
    fn test_is_host_default_route() {
        assert!(is_host_default_route(&Route::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0
        )));
        assert!(is_host_default_route(&Route::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            0
        )));
        // Not a default route
        assert!(!is_host_default_route(&Route::new(
            IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
            1
        )));
        // A netmask the route crate could not read leaves the destination behind
        assert!(!is_host_default_route(&Route::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            0
        )));
        // macOS: the interface-scoped copy of a default route only serves
        // sockets bound to that interface
        #[cfg(macos)]
        assert!(!is_host_default_route(
            &Route::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
                .with_if_index(1)
                .with_if_scope(true)
        ));
    }

    #[test]
    fn test_ipv6_sink_routes() {
        let routes = ipv6_sink_routes(
            #[cfg(windows)]
            7,
        );
        let expected = [
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)),
        ];
        assert_eq!(routes.len(), expected.len());
        for (route, network) in routes.iter().zip(expected) {
            assert_eq!(route.destination(), network);
            assert_eq!(route.prefix(), 1);
            // macOS: a gateway route via loopback; an interface route on the
            // TUN is refused because the TUN has no IPv6 address
            #[cfg(macos)]
            {
                assert_eq!(route.gateway(), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
                assert_eq!(route.if_index(), None);
            }
            // Linux: a device route on loopback
            #[cfg(linux)]
            {
                assert_eq!(route.if_name().map(String::as_str), Some("lo"));
                assert_eq!(route.gateway(), None);
            }
            // Windows: an interface route on the TUN, which has a link-local
            #[cfg(windows)]
            {
                assert_eq!(route.if_index(), Some(7));
                assert_eq!(route.gateway(), None);
                assert_eq!(route.metric(), Some(0));
            }
        }
    }

    #[test_case(EXTERNAL_IP_V6 ; "global unicast")]
    #[test_case(IpAddr::V6(Ipv6Addr::LOCALHOST) ; "loopback")]
    #[test_case(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)) ; "link local")]
    #[test_case(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)) ; "multicast")]
    #[test_case(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)) ; "unique local")]
    #[test_case(IpAddr::V6(Ipv6Addr::new(0x7fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)) ; "top of lower half")]
    #[test_case(IpAddr::V6(Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff)) ; "top of upper half")]
    fn test_ipv6_sink_routes_cover_exactly_one_half(addr: IpAddr) {
        let covering = ipv6_sink_routes(
            #[cfg(windows)]
            1,
        )
        .iter()
        .filter(|route| route.contains(&addr))
        .count();
        assert_eq!(covering, 1);
    }

    #[test]
    fn test_ipv6_unsupported_error_matches_address_family_error() {
        #[cfg(unix)]
        let unsupported = std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT);
        #[cfg(windows)]
        let unsupported = std::io::Error::from_raw_os_error(
            windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT,
        );
        assert!(ipv6_unsupported_error(&unsupported));
    }

    #[test]
    fn test_ipv6_unsupported_error_ignores_other_errors() {
        #[cfg(unix)]
        let other = std::io::Error::from_raw_os_error(libc::EEXIST);
        #[cfg(windows)]
        let other = std::io::Error::from_raw_os_error(ERROR_OBJECT_ALREADY_EXISTS as i32);
        assert!(!ipv6_unsupported_error(&other));
        assert!(!ipv6_unsupported_error(&std::io::Error::other(
            "no OS error code"
        )));
    }

    #[test]
    fn test_ipv6_available_only_denied_by_address_family_error() {
        #[cfg(unix)]
        let unsupported = std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT);
        #[cfg(windows)]
        let unsupported = std::io::Error::from_raw_os_error(
            windows_sys::Win32::Networking::WinSock::WSAEAFNOSUPPORT,
        );
        // A socket came up: IPv6 is there
        assert!(ipv6_available_from_probe(Ok(())));
        // The address family is missing: nothing to sink
        assert!(!ipv6_available_from_probe(Err(unsupported)));
        // Any other failure must not switch the sink off
        assert!(ipv6_available_from_probe(Err(std::io::Error::other(
            "transient"
        ))));
    }

    #[test]
    fn test_ipv6_sink_routes_ignore_ipv4() {
        assert!(
            ipv6_sink_routes(
                #[cfg(windows)]
                1
            )
            .iter()
            .all(|route| !route.contains(&EXTERNAL_IP_V4))
        );
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[ignore = "May falsely fail during development due to local route settings"]
    #[serial_test::serial(route_manager)]
    async fn test_privileged_new_route_manager(route_mode: RouteMode) {
        let (_restorer, _tun_device, route_manager) =
            create_test_setup(route_mode, EXTERNAL_IP_V4).await.unwrap();
        assert_eq!(route_manager.routing_mode, route_mode);
        assert_eq!(route_manager.vpn_routes.len(), 0);
        assert_eq!(route_manager.lan_routes.len(), 0);
        assert!(route_manager.server_route.is_none());
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_cleanup_sync(route_mode: RouteMode) {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(route_mode, EXTERNAL_IP_V4).await.unwrap();

        // Get initial route count from the system
        let initial_count = route_manager.route_manager.list().unwrap().len();

        // Create test routes using shared fixtures
        let (vpn_route, lan_route, server_route, _gateway_ip) =
            create_test_routes_with_gateway(&mut route_manager);

        // Add routes directly to the sync route manager and store them
        route_manager.route_manager.add(&vpn_route).unwrap();
        route_manager.vpn_routes.push(vpn_route.clone());

        route_manager.route_manager.add(&lan_route).unwrap();
        route_manager.lan_routes.push(lan_route.clone());

        route_manager.route_manager.add(&server_route).unwrap();
        route_manager.server_route = Some(server_route.clone());

        // Verify routes were added to the system
        let routes_after_add = route_manager.route_manager.list().unwrap();
        let routes_added = routes_after_add.len() - initial_count;
        assert_eq!(routes_added, 3);

        // Verify internal state
        assert_eq!(route_manager.vpn_routes.len(), 1);
        assert_eq!(route_manager.lan_routes.len(), 1);
        assert!(route_manager.server_route.is_some());

        // Test cleanup_sync
        route_manager.cleanup_sync();

        // Verify routes were removed from the system
        let routes_after_cleanup = route_manager.route_manager.list().unwrap();
        let final_count = routes_after_cleanup.len();
        assert_eq!(final_count, initial_count);

        // Verify internal state is unchanged (cleanup_sync doesn't modify internal vectors)
        assert_eq!(route_manager.vpn_routes.len(), 1);
        assert_eq!(route_manager.lan_routes.len(), 1);
        assert!(route_manager.server_route.is_some());
    }

    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May affect system routing"]
    async fn test_privileged_is_route_exists_error_real() {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(RouteMode::Default, EXTERNAL_IP_V4)
                .await
                .unwrap();

        // Create test routes using shared fixtures
        let (route, _, _, _) = create_test_routes_with_gateway(&mut route_manager);

        // Add the route first time - should succeed
        route_manager.add_route(&route).await.unwrap();

        // Try to add the same route again - should get "route exists" error
        let result2 = route_manager.route_manager_async.add(&route).await;
        match result2 {
            Err(e) => {
                assert!(route_manager.is_route_exists_error(&e));
            }
            Ok(_) => panic!(),
        }
    }

    #[test_case(RouteAddMethod::Standard)]
    #[test_case(RouteAddMethod::Server)]
    #[test_case(RouteAddMethod::Lan)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_add_single_route(add_method: RouteAddMethod) {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(RouteMode::Default, EXTERNAL_IP_V4)
                .await
                .unwrap();

        // Create test route using shared fixtures
        let (route1, _route2, _route3, _gateway_ip) =
            create_test_routes_with_gateway(&mut route_manager);

        // Test adding route using the specified method
        match add_method {
            RouteAddMethod::Standard => route_manager.add_route_vpn(route1.clone()).await.unwrap(),
            RouteAddMethod::Server => route_manager
                .add_route_server(route1.clone())
                .await
                .unwrap(),
            RouteAddMethod::Lan => route_manager.add_route_lan(route1.clone()).await.unwrap(),
        };
        let routes_after_add1 = route_manager.route_manager.list().unwrap();

        // Verify the route is present in the system
        let route_found = routes_after_add1
            .iter()
            .any(|r| r.destination() == route1.destination() && r.gateway() == route1.gateway());

        assert!(route_found);
    }

    #[test_case(RouteMode::NoExec)]
    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_initialize_route_manager(route_mode: RouteMode) {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(route_mode, EXTERNAL_IP_V4).await.unwrap();

        // Get tun_index from the route_manager (it's already set during creation)
        let tun_index = route_manager.tun_index;

        // Test install routes using shared fixtures
        route_manager.install_routes().await.unwrap();

        // Get system routes after initialization
        let routes_after_init = route_manager.route_manager.list().unwrap();

        // Verify routes are present in system
        if [RouteMode::Default, RouteMode::Lan].contains(&route_mode) {
            let server_route_found = routes_after_init
                .iter()
                .any(|r| r.destination() == EXTERNAL_IP_V4 && r.prefix() == Ipv4Addr::BITS as u8);
            assert!(server_route_found);

            for (network, prefix) in TUNNEL_ROUTES {
                // Verify route is present in system
                let route_in_system = routes_after_init.iter().any(|r| {
                    r.destination() == network
                        && r.prefix() == prefix
                        && r.gateway() == Some(TUN_PEER_IP)
                        && r.if_index() == Some(tun_index)
                });
                assert!(route_in_system);
            }

            let dns_route_in_system = routes_after_init.iter().any(|r| {
                r.destination() == TUN_DNS_IP
                    && r.prefix() == Ipv4Addr::BITS as u8
                    && r.gateway() == Some(TUN_PEER_IP)
                    && r.if_index() == Some(tun_index)
            });
            assert!(dns_route_in_system);
        }

        // Verify LAN routes are present in system
        if route_mode == RouteMode::Lan {
            let (default_index, default_gateway) = route_manager
                .find_default_interface_index_and_gateway(&EXTERNAL_IP_V4)
                .unwrap();

            for (network, prefix) in LAN_NETWORKS {
                let lan_route_in_system = routes_after_init.iter().any(|r| {
                    r.destination() == network
                        && r.prefix() == prefix
                        && (r.gateway() == default_gateway || r.if_index() == Some(default_index))
                });
                assert!(lan_route_in_system);
            }

            // The IPv6 LAN route follows the IPv6 default route, if there is one
            let (ula_network, ula_prefix) = IPV6_LAN_NETWORK;
            let ipv6_default = route_manager.find_best_default_route(&ula_network);
            let ula_route = route_manager
                .lan_routes
                .iter()
                .find(|r| r.destination() == ula_network && r.prefix() == ula_prefix);
            match ipv6_default {
                Ok(ipv6_default) => {
                    let ula_route = ula_route.expect("IPv6 LAN route recorded");
                    assert_eq!(ula_route.if_index(), ipv6_default.if_index());
                    let ula_route_in_system = routes_after_init.iter().any(|r| {
                        r.destination() == ula_network
                            && r.prefix() == ula_prefix
                            && r.if_index() == ipv6_default.if_index()
                    });
                    assert!(ula_route_in_system);
                }
                Err(_) => assert!(ula_route.is_none()),
            }
        }

        // Verify the IPv6 sink routes are present in system and removed on cleanup
        if [RouteMode::Default, RouteMode::Lan].contains(&route_mode) {
            assert!(ipv6_sink_routes_in_system(
                &routes_after_init,
                #[cfg(windows)]
                tun_index
            ));

            route_manager.cleanup_sync();
            let routes_after_cleanup = route_manager.route_manager.list().unwrap();
            assert!(!any_ipv6_sink_route_in_system(
                &routes_after_cleanup,
                #[cfg(windows)]
                tun_index
            ));
        } else {
            assert!(!any_ipv6_sink_route_in_system(
                &routes_after_init,
                #[cfg(windows)]
                tun_index
            ));
        }
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_initialize_route_manager_without_ipv6_sink(route_mode: RouteMode) {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(route_mode, EXTERNAL_IP_V4).await.unwrap();
        route_manager.block_ipv6 = false;

        let tun_index = route_manager.tun_index;

        route_manager.install_routes().await.unwrap();

        let routes_after_init = route_manager.route_manager.list().unwrap();

        // IPv4 tunnel routes are installed as usual
        for (network, prefix) in TUNNEL_ROUTES {
            let route_in_system = routes_after_init.iter().any(|r| {
                r.destination() == network
                    && r.prefix() == prefix
                    && r.gateway() == Some(TUN_PEER_IP)
                    && r.if_index() == Some(tun_index)
            });
            assert!(route_in_system);
        }

        // Nothing IPv6 is touched
        assert!(!any_ipv6_sink_route_in_system(
            &routes_after_init,
            #[cfg(windows)]
            tun_index
        ));
        assert!(
            route_manager
                .vpn_routes
                .iter()
                .all(|r| r.destination().is_ipv4())
        );
        assert!(
            route_manager
                .lan_routes
                .iter()
                .all(|r| r.destination().is_ipv4())
        );
    }

    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_find_server_route(route_mode: RouteMode) {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(route_mode, EXTERNAL_IP_V4).await.unwrap();

        // Get tun_index from the route_manager (it's already set during creation)
        let tun_index = route_manager.tun_index;

        // Create test routes using tunnel route constants
        let route1 = Route::new(TUNNEL_ROUTES[0].0, TUNNEL_ROUTES[0].1)
            .with_gateway(TUN_PEER_IP)
            .with_if_index(tun_index);
        let route2 = Route::new(TUNNEL_ROUTES[1].0, TUNNEL_ROUTES[1].1)
            .with_gateway(TUN_PEER_IP)
            .with_if_index(tun_index);

        // Add routes (assuming add_route works based on previous test)
        route_manager.add_route_vpn(route1.clone()).await.unwrap();

        // Test find_server_route for test_ip1 using shared fixtures
        let found_route1 = route_manager.find_route(&ROUTE_TEST_IP1).unwrap();
        assert_eq!(found_route1.gateway(), route1.gateway());

        route_manager.add_route_vpn(route2.clone()).await.unwrap();

        // Test find_server_route for test_ip1 after adding route2
        let found_route1 = route_manager.find_route(&ROUTE_TEST_IP1).unwrap();
        assert_eq!(found_route1.gateway(), route1.gateway());

        let found_route2 = route_manager.find_route(&ROUTE_TEST_IP2).unwrap();
        assert_eq!(found_route2.gateway(), route2.gateway());
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_route_manager_start_stop(route_mode: RouteMode) {
        let mut route_manager =
            RouteManager::new(route_mode, true, EXTERNAL_IP_V4, 0, TUN_PEER_IP, TUN_DNS_IP)
                .unwrap();

        // Test that we can start the route manager
        let start_result = route_manager.start().await;
        if route_mode == RouteMode::NoExec {
            // NoExec mode should succeed but not actually do anything
            assert!(start_result.is_ok());
        } else {
            // Other modes may require privileges, so we just check it doesn't panic
            let _ = start_result;
        }

        // Test that we can stop the route manager
        let stop_result = route_manager.stop().await;
        assert!(stop_result.is_ok());

        // Test that stopping again is safe
        let stop_again_result = route_manager.stop().await;
        assert!(stop_again_result.is_ok());
    }

    #[tokio::test]
    async fn test_stop_aborts_task_and_awaits_updater_drop() {
        struct DropFlag(std::sync::Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        }

        let mut route_manager = RouteManager::new(
            RouteMode::NoExec,
            true,
            EXTERNAL_IP_V4,
            0,
            TUN_PEER_IP,
            TUN_DNS_IP,
        )
        .unwrap();
        let updater = route_manager.start().await.unwrap();

        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = DropFlag(dropped.clone());
        route_manager.set_task(tokio::spawn(async move {
            let (_updater, _flag) = (updater, flag);
            std::future::pending::<()>().await;
        }));

        route_manager.stop().await.unwrap();

        // stop() must have awaited the aborted task, so the updater (and with
        // it the installed routes) is gone by the time it returns.
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test_case(RouteMode::Default, true)]
    #[test_case(RouteMode::Default, false)]
    #[test_case(RouteMode::Lan, true)]
    #[test_case(RouteMode::Lan, false)]
    #[tokio::test]
    async fn test_route_manager_inner_structure(route_mode: RouteMode, block_ipv6: bool) {
        // Test that RouteManagerInner can be created directly
        let inner_result = RouteManagerInner::new(
            route_mode,
            block_ipv6,
            EXTERNAL_IP_V4,
            0,
            TUN_PEER_IP,
            TUN_DNS_IP,
        );
        assert!(inner_result.is_ok());

        let inner = inner_result.unwrap();
        assert_eq!(inner.routing_mode, route_mode);
        assert_eq!(inner.block_ipv6, block_ipv6);
        assert_eq!(inner.server_ip, EXTERNAL_IP_V4);
        assert_eq!(inner.tun_index, 0);
        assert_eq!(inner.tun_peer_ip, TUN_PEER_IP);
        assert_eq!(inner.tun_dns_ip, TUN_DNS_IP);
        assert_eq!(inner.vpn_routes.len(), 0);
        assert_eq!(inner.lan_routes.len(), 0);
        assert!(inner.server_route.is_none());
    }

    #[tokio::test]
    async fn test_route_manager_double_start_error() {
        let mut route_manager = RouteManager::new(
            RouteMode::NoExec,
            true,
            EXTERNAL_IP_V4,
            0,
            TUN_PEER_IP,
            TUN_DNS_IP,
        )
        .unwrap();

        // First start should succeed
        assert!(route_manager.start().await.is_ok());

        // Second start should fail since inner is already taken
        let second_start_result = route_manager.start().await;
        assert!(matches!(
            second_start_result,
            Err(RoutingTableError::InsufficientPermissions)
        ));
    }

    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "Requires network privileges and may affect system routing"]
    async fn test_privileged_route_monitoring_server_route_update() {
        let (_restorer, _tun_device, mut inner) =
            create_test_setup(RouteMode::Default, EXTERNAL_IP_V4)
                .await
                .unwrap();

        // Install initial routes
        inner.install_routes().await.unwrap();

        // Verify server route was created
        assert!(inner.server_route.is_some());
        let initial_server_route = inner.server_route.as_ref().unwrap().clone();

        // Test check_and_update_server_route when no change is needed
        let result = inner.check_and_update_server_route().await;
        assert!(matches!(result, Ok(false)));

        // Server route should remain unchanged
        assert!(inner.server_route.is_some());
        let unchanged_route = inner.server_route.as_ref().unwrap();
        assert_eq!(
            initial_server_route.destination(),
            unchanged_route.destination()
        );
        assert_eq!(initial_server_route.prefix(), unchanged_route.prefix());
    }

    #[tokio::test]
    async fn test_route_manager_start_with_noexec_mode() {
        // Don't create a TUN device for NoExec mode; it needs no privileges
        let mut route_manager = RouteManager::new(
            RouteMode::NoExec,
            true,
            EXTERNAL_IP_V4,
            1,
            TUN_PEER_IP,
            TUN_DNS_IP,
        )
        .unwrap();

        // NoExec installs nothing and the per-event step is a no-op
        let mut updater = route_manager.start().await.unwrap();
        assert!(updater.check_and_update_server_route().await.is_ok());
        assert!(updater.inner.server_route.is_none());
    }

    #[tokio::test]
    async fn test_ipv6_server_route_manager_creation() {
        // Test that RouteManagerInner can be created with IPv6 server
        let inner = RouteManagerInner::new(
            RouteMode::Default,
            true,
            EXTERNAL_IP_V6,
            1,
            TUN_PEER_IP,
            TUN_DNS_IP,
        );
        assert!(inner.is_ok());

        let inner = inner.unwrap();
        assert_eq!(inner.server_ip, EXTERNAL_IP_V6);
        assert!(inner.server_ip.is_ipv6());
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "Requires IPv6 routing support in test environment"]
    async fn test_privileged_ipv6_server_initialize_route_manager(route_mode: RouteMode) {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(route_mode, EXTERNAL_IP_V6).await.unwrap();

        // Get tun_index from the route_manager (it's already set during creation)
        let tun_index = route_manager.tun_index;

        // Test install routes using IPv6 server
        route_manager.install_routes().await.unwrap();

        // Get system routes after initialization
        let routes_after_init = route_manager.route_manager.list().unwrap();

        // Verify routes are present in system
        if [RouteMode::Default, RouteMode::Lan].contains(&route_mode) {
            // Server route should use /128 prefix for IPv6
            let server_route_found = routes_after_init
                .iter()
                .any(|r| r.destination() == EXTERNAL_IP_V6 && r.prefix() == Ipv6Addr::BITS as u8);
            assert!(
                server_route_found,
                "IPv6 server route with /128 prefix not found"
            );

            // Tunnel routes remain IPv4
            for (network, prefix) in TUNNEL_ROUTES {
                let route_in_system = routes_after_init.iter().any(|r| {
                    r.destination() == network
                        && r.prefix() == prefix
                        && r.gateway() == Some(TUN_PEER_IP)
                        && r.if_index() == Some(tun_index)
                });
                assert!(
                    route_in_system,
                    "IPv4 tunnel route not found for {:?}",
                    network
                );
            }

            // DNS route remains IPv4
            let dns_route_in_system = routes_after_init.iter().any(|r| {
                r.destination() == TUN_DNS_IP
                    && r.prefix() == Ipv4Addr::BITS as u8
                    && r.gateway() == Some(TUN_PEER_IP)
                    && r.if_index() == Some(tun_index)
            });
            assert!(dns_route_in_system, "IPv4 DNS route not found");

            // The IPv6 sink coexists with the /128 server route, which wins
            // for the server itself
            assert!(
                ipv6_sink_routes_in_system(
                    &routes_after_init,
                    #[cfg(windows)]
                    tun_index
                ),
                "IPv6 sink routes not found"
            );
            let server_route = route_manager.find_route(&EXTERNAL_IP_V6).unwrap();
            assert_eq!(server_route.prefix(), Ipv6Addr::BITS as u8);
            assert_ne!(server_route.if_index(), Some(tun_index));
        }
    }

    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "Requires IPv6 routing support in test environment"]
    async fn test_privileged_ipv6_server_route_update() {
        let (_restorer, _tun_device, mut inner) =
            create_test_setup(RouteMode::Default, EXTERNAL_IP_V6)
                .await
                .unwrap();

        // Install initial routes
        inner.install_routes().await.unwrap();

        // Verify server route was created with /128 prefix
        assert!(inner.server_route.is_some());
        let initial_server_route = inner.server_route.as_ref().unwrap().clone();
        assert_eq!(initial_server_route.destination(), EXTERNAL_IP_V6);
        assert_eq!(initial_server_route.prefix(), Ipv6Addr::BITS as u8);

        // Test check_and_update_server_route when no change is needed
        let result = inner.check_and_update_server_route().await;
        assert!(matches!(result, Ok(false)));

        // Server route should remain unchanged
        assert!(inner.server_route.is_some());
        let unchanged_route = inner.server_route.as_ref().unwrap();
        assert_eq!(
            initial_server_route.destination(),
            unchanged_route.destination()
        );
        assert_eq!(initial_server_route.prefix(), unchanged_route.prefix());
        assert_eq!(
            unchanged_route.prefix(),
            Ipv6Addr::BITS as u8,
            "IPv6 route should maintain /128 prefix"
        );
    }
}
