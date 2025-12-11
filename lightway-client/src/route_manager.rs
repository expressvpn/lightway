use anyhow::Result;
use route_manager::{
    AsyncRouteListener, AsyncRouteManager, Route, RouteManager as SyncRouteManager,
};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use tokio::task::JoinHandle;
use tracing::{trace, warn};

#[cfg(windows)]
use windows_sys::Win32::Foundation::ERROR_OBJECT_ALREADY_EXISTS;

#[cfg(windows)]
use crate::platform::windows::addr_monitor::AsyncAddrListener;
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

#[derive(Debug, PartialEq, Copy, Clone, clap::ValueEnum, Serialize, Deserialize, Default)]
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
    #[error("Failed to Add Route {0}")]
    AddRouteError(std::io::Error),
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

pub struct RouteManager {
    inner: Option<RouteManagerInner>,
    task: Option<JoinHandle<()>>,
}

struct RouteManagerInner {
    routing_mode: RouteMode,
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
        server_ip: IpAddr,
        tun_index: u32,
        tun_peer_ip: IpAddr,
        tun_dns_ip: IpAddr,
    ) -> Result<Self, RoutingTableError> {
        let inner = Some(RouteManagerInner::new(
            routing_mode,
            server_ip,
            tun_index,
            tun_peer_ip,
            tun_dns_ip,
        )?);
        Ok(Self { inner, task: None })
    }

    pub async fn start(&mut self) -> Result<(), RoutingTableError> {
        let Some(inner) = self.inner.take() else {
            return Err(RoutingTableError::InsufficientPermissions);
        };

        self.task = inner.start().await?;
        Ok(())
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

impl RouteManagerInner {
    fn new(
        routing_mode: RouteMode,
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
            route_manager,
            route_manager_async,
            server_ip,
            tun_index,
            tun_peer_ip,
            tun_dns_ip,
            vpn_routes: Vec::with_capacity(TUNNEL_ROUTES.len() + 1),
            lan_routes: Vec::with_capacity(LAN_NETWORKS.len()),
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

            // Not a default route, skip
            if route.prefix() != 0 {
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
        Ok(self
            .route_manager
            .find_route(server_ip)
            .map_err(RoutingTableError::DefaultInterfaceNotFound)?
            .unwrap())
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
                    Err(RoutingTableError::AddRouteError(e))
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
        let server_route = Route::new(server_ip, 32).with_if_index(default_interface_index);
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
                if let Some(gw) = default_interface_gateway {
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
        let dns_route = Route::new(self.tun_dns_ip, 32)
            .with_gateway(self.tun_peer_ip)
            .with_if_index(self.tun_index);
        #[cfg(windows)]
        let dns_route = dns_route.with_metric(0);

        self.add_route_vpn(dns_route).await?;
        Ok(())
    }

    /// Install routes required to use tunnel and start monitoring route changes
    /// to update the routes if needed (mostly during connection floating)
    async fn start(mut self) -> Result<Option<JoinHandle<()>>, RoutingTableError> {
        if self.routing_mode == RouteMode::NoExec {
            return Ok(None);
        }

        // Install all th required routes
        self.install_routes().await?;

        // Spawn async task to monitor route changes using AsyncRouteListener
        let monitor_task = tokio::spawn(async move {
            // Create AsyncRouteListener
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
            // Listen for changes in a loop
            loop {
                tokio::select! {
                   // Handle route changes
                   route_result = route_listener.listen() => {
                       match route_result {
                           Ok(route_change) => {
                               tracing::debug!("Route change detected: {:?}", route_change);
                               match route_change {
                                   route_manager::RouteChange::Add(route)
                                   | route_manager::RouteChange::Delete(route)
                                   | route_manager::RouteChange::Change(route) => {
                                       // skip Ipv6 route updates
                                       if route.destination().is_ipv6() {
                                           continue;
                                       };
                                       // Update only the /0 prefix route i.e default route
                                       if route.prefix() != 0 {
                                           continue;
                                       }
                                       if route.gateway().is_none_or(|a| a.is_unspecified()) {
                                           continue;
                                       }
                                       if let Err(e) = self.check_and_update_server_route().await {
                                           tracing::warn!("Updating server route failed: {:?}", e);
                                       }
                                   }
                               }
                           }
                       Err(e) => {
                           // Continue monitoring even on transient errors
                           tracing::debug!("Error listening for route changes: {}", e);
                           tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                       }
                   }}

                   // On address/intf changes, check and update server route
                   // This helps catch network transitions that don't trigger route changes
                   _ = async {
                       if let Some(listener) = &mut addr_listener {
                           listener.recv().await
                       } else {
                           std::future::pending().await
                       }
                   } => {
                       tracing::debug!("Address change detected");
                       if let Err(e) = self.check_and_update_server_route().await {
                           tracing::warn!("Updating server route after address change failed: {:?}", e);
                       }
                   }
                }
            }
        });

        Ok(Some(monitor_task))
    }

    /// Check if server route needs updating due to network changes
    async fn check_and_update_server_route(&mut self) -> Result<(), RoutingTableError> {
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
                let mut new_server_route = Route::new(self.server_ip, 32);
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
            }
        }

        Ok(())
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
    use std::net::{IpAddr, Ipv4Addr};
    use test_case::test_case;
    use tokio;
    use tun_rs::{AsyncDevice, DeviceBuilder};

    const EXTERNAL_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
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
        let default_route = route_manager.find_route(&EXTERNAL_IP).unwrap();
        let gateway_ip = default_route.gateway().unwrap();

        let route1 = Route::new(TEST_TARGET_IP1, 32).with_gateway(gateway_ip);
        let route2 = Route::new(TEST_TARGET_IP2, 32).with_gateway(gateway_ip);
        let route3 = Route::new(TEST_TARGET_IP3, 32).with_gateway(gateway_ip);

        (route1, route2, route3, gateway_ip)
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
    ) -> Result<(RouteRestorer, AsyncDevice, RouteManagerInner), Box<dyn std::error::Error>> {
        // Capture initial state FIRST
        let restorer = RouteRestorer::new();

        // Create TUN device
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
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        let tun_index = tun_device.if_index()?;

        // Create RouteManagerInner directly for testing
        let route_manager =
            RouteManagerInner::new(route_mode, EXTERNAL_IP, tun_index, TUN_PEER_IP, TUN_DNS_IP)?;

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

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_new_route_manager(route_mode: RouteMode) {
        let (_restorer, _tun_device, route_manager) = create_test_setup(route_mode).await.unwrap();
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
            create_test_setup(route_mode).await.unwrap();

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
            create_test_setup(RouteMode::Default).await.unwrap();

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
            create_test_setup(RouteMode::Default).await.unwrap();

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
            create_test_setup(route_mode).await.unwrap();

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
                .any(|r| r.destination() == EXTERNAL_IP && r.prefix() == 32);
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
                    && r.prefix() == 32
                    && r.gateway() == Some(TUN_PEER_IP)
                    && r.if_index() == Some(tun_index)
            });
            assert!(dns_route_in_system);
        }

        // Verify LAN routes are present in system
        if route_mode == RouteMode::Lan {
            let (default_index, default_gateway) = route_manager
                .find_default_interface_index_and_gateway(&EXTERNAL_IP)
                .unwrap();

            for (network, prefix) in LAN_NETWORKS {
                let lan_route_in_system = routes_after_init.iter().any(|r| {
                    r.destination() == network
                        && r.prefix() == prefix
                        && (r.gateway() == default_gateway || r.if_index() == Some(default_index))
                });
                assert!(lan_route_in_system);
            }
        }
    }

    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_find_server_route(route_mode: RouteMode) {
        let (_restorer, _tun_device, mut route_manager) =
            create_test_setup(route_mode).await.unwrap();

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
            RouteManager::new(route_mode, EXTERNAL_IP, 0, TUN_PEER_IP, TUN_DNS_IP).unwrap();

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

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[tokio::test]
    async fn test_route_manager_inner_structure(route_mode: RouteMode) {
        // Test that RouteManagerInner can be created directly
        let inner_result =
            RouteManagerInner::new(route_mode, EXTERNAL_IP, 0, TUN_PEER_IP, TUN_DNS_IP);
        assert!(inner_result.is_ok());

        let inner = inner_result.unwrap();
        assert_eq!(inner.routing_mode, route_mode);
        assert_eq!(inner.server_ip, EXTERNAL_IP);
        assert_eq!(inner.tun_index, 0);
        assert_eq!(inner.tun_peer_ip, TUN_PEER_IP);
        assert_eq!(inner.tun_dns_ip, TUN_DNS_IP);
        assert_eq!(inner.vpn_routes.len(), 0);
        assert_eq!(inner.lan_routes.len(), 0);
        assert!(inner.server_route.is_none());
    }

    #[tokio::test]
    async fn test_route_manager_double_start_error() {
        let mut route_manager =
            RouteManager::new(RouteMode::NoExec, EXTERNAL_IP, 0, TUN_PEER_IP, TUN_DNS_IP).unwrap();

        // First start should succeed
        assert!(route_manager.start().await.is_ok());

        // Second start should fail since inner is already taken
        let second_start_result = route_manager.start().await;
        assert!(second_start_result.is_err());
        assert!(matches!(
            second_start_result.unwrap_err(),
            RoutingTableError::InsufficientPermissions
        ));
    }

    #[tokio::test]
    #[serial_test::serial(route_manager)]
    #[ignore = "Requires network privileges and may affect system routing"]
    async fn test_privileged_route_monitoring_server_route_update() {
        let (_restorer, _tun_device, mut inner) =
            create_test_setup(RouteMode::Default).await.unwrap();

        // Install initial routes
        inner.install_routes().await.unwrap();

        // Verify server route was created
        assert!(inner.server_route.is_some());
        let initial_server_route = inner.server_route.as_ref().unwrap().clone();

        // Test check_and_update_server_route when no change is needed
        let result = inner.check_and_update_server_route().await;
        assert!(result.is_ok());

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
        // Don't create TUN device for NoExec mode, just test RouteManagerInner directly
        let inner =
            RouteManagerInner::new(RouteMode::NoExec, EXTERNAL_IP, 1, TUN_PEER_IP, TUN_DNS_IP)
                .unwrap();

        // NoExec mode should return None (no monitoring task)
        let monitor_task = inner.start().await;
        assert!(monitor_task.is_ok());
        assert!(monitor_task.unwrap().is_none());
    }
}
