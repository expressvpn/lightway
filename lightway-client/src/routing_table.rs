use anyhow::Result;
use route_manager::{AsyncRouteManager, Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use tracing::warn;

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

pub struct RoutingTable {
    routing_mode: RouteMode,
    route_manager: RouteManager,
    route_manager_async: AsyncRouteManager,
    vpn_routes: Vec<Route>,
    lan_routes: Vec<Route>,
    server_route: Option<Route>,
}

impl RoutingTable {
    pub fn new(routing_mode: RouteMode) -> Result<Self, RoutingTableError> {
        let route_manager = RouteManager::new().map_err(RoutingTableError::RoutingManagerError)?;
        let route_manager_async =
            AsyncRouteManager::new().map_err(RoutingTableError::AsyncRoutingManagerError)?;
        Ok(Self {
            routing_mode,
            route_manager,
            route_manager_async,
            vpn_routes: Vec::with_capacity(TUNNEL_ROUTES.len() + 1),
            lan_routes: Vec::with_capacity(LAN_NETWORKS.len()),
            server_route: None,
        })
    }

    pub async fn cleanup(&mut self) {
        self.cleanup_normal_routes().await;
        self.cleanup_lan_routes().await;
        self.cleanup_server_routes().await;
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
            Ok(()) => Ok(()),
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
            _ => false,
        }
    }

    /// Adds Routes and stores it
    pub async fn add_route_vpn(&mut self, route: Route) -> Result<(), RoutingTableError> {
        self.add_route(&route).await?;
        self.vpn_routes.push(route);
        Ok(())
    }

    /// Adds Server Route and stores it
    pub async fn add_route_server(&mut self, route: Route) -> Result<(), RoutingTableError> {
        if self.server_route.is_some() {
            return Err(RoutingTableError::ServerRouteAlreadyExists);
        }
        self.add_route(&route).await?;
        self.server_route = Some(route);
        Ok(())
    }

    /// Adds LAN Route and stores it
    pub async fn add_route_lan(&mut self, route: Route) -> Result<(), RoutingTableError> {
        self.add_route(&route).await?;
        self.lan_routes.push(route);
        Ok(())
    }

    /// Adds standard LAN routes (RFC 1918 private networks + link-local + multicast)
    /// with optional gateway. Gateway is None for direct routes (e.g., in Docker containers)
    pub async fn add_standard_lan_routes(
        &mut self,
        interface_index: u32,
        gateway: Option<IpAddr>,
    ) -> Result<(), RoutingTableError> {
        for (network, prefix) in LAN_NETWORKS {
            let mut lan_route = Route::new(network, prefix).with_if_index(interface_index);
            if let Some(gw) = gateway {
                lan_route = lan_route.with_gateway(gw);
            }
            self.add_route_lan(lan_route).await?;
        }
        Ok(())
    }

    /// Adds standard tunnel routes (high priority default routing)
    pub async fn add_standard_tunnel_routes(
        &mut self,
        interface_index: u32,
        gateway: IpAddr,
    ) -> Result<(), RoutingTableError> {
        for (network, prefix) in TUNNEL_ROUTES {
            let tunnel_route = Route::new(network, prefix)
                .with_gateway(gateway)
                .with_if_index(interface_index);

            self.add_route_vpn(tunnel_route).await?;
        }
        Ok(())
    }

    /// Cleans up LAN routes
    pub async fn cleanup_lan_routes(&mut self) {
        for r in self.lan_routes.drain(..) {
            self.route_manager_async
                .delete(&r)
                .await
                .unwrap_or_else(|e| {
                    warn!("Failed to delete LAN route: {r}, error: {e}");
                })
        }
    }

    /// Cleans up server routes
    pub async fn cleanup_server_routes(&mut self) {
        if let Some(r) = &self.server_route {
            self.route_manager_async
                .delete(r)
                .await
                .unwrap_or_else(|e| {
                    warn!("Failed to delete server route: {r}, error: {e}");
                })
        }
        self.server_route = None;
    }

    /// Cleans up normal routes
    pub async fn cleanup_normal_routes(&mut self) {
        for r in self.vpn_routes.drain(..) {
            self.route_manager_async
                .delete(&r)
                .await
                .unwrap_or_else(|e| {
                    warn!("Failed to delete route: {r}, error: {e}");
                })
        }
    }

    /// Clean up for program unwind
    pub fn cleanup_sync(&mut self) {
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
    }
    pub async fn initialize_routing_table(
        &mut self,
        server_ip: &IpAddr,
        tun_index: u32,
        tun_peer_ip: &IpAddr,
        tun_dns_ip: &IpAddr,
    ) -> Result<()> {
        if self.routing_mode == RouteMode::NoExec {
            return Ok(());
        }

        // Setting up VPN Server Routes
        let (default_interface_index, default_interface_gateway) =
            self.find_default_interface_index_and_gateway(server_ip)?;

        // Create server route with optional gateway - handles both direct routes (containers)
        // and routed networks (host systems with gateways)
        let server_route = Route::new(*server_ip, 32).with_if_index(default_interface_index);
        let server_route = match default_interface_gateway {
            Some(gateway) => server_route.with_gateway(gateway),
            None => server_route,
        };

        self.add_route_server(server_route).await?;

        if self.routing_mode == RouteMode::Lan {
            self.add_standard_lan_routes(default_interface_index, default_interface_gateway)
                .await?;
        }

        // Add standard tunnel routes (high priority default routing)
        self.add_standard_tunnel_routes(tun_index, *tun_peer_ip)
            .await?;

        // Add DNS route separately since it's not a constant
        let dns_route = Route::new(*tun_dns_ip, 32)
            .with_gateway(*tun_peer_ip)
            .with_if_index(tun_index);

        self.add_route_vpn(dns_route).await?;
        Ok(())
    }
}

impl Drop for RoutingTable {
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
        routing_table: &mut RoutingTable,
    ) -> (Route, Route, Route, IpAddr) {
        let default_route = routing_table.find_route(&EXTERNAL_IP).unwrap();
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

    /// Creates a test setup with RouteRestorer and RoutingTable
    /// Returns tuple where RouteRestorer is dropped last for proper cleanup
    fn create_test_setup(route_mode: RouteMode) -> (RouteRestorer, RoutingTable) {
        // Capture initial state FIRST
        let restorer = RouteRestorer::new();

        // Then create RoutingTable
        let routing_table = RoutingTable::new(route_mode).unwrap();

        // Return tuple - RoutingTable will be dropped first, RouteRestorer last
        (restorer, routing_table)
    }

    /// Test wrapper around RouteManager for cleanup purposes
    struct RouteRestorer {
        initial_routes: Vec<Route>,
    }

    impl RouteRestorer {
        fn new() -> Self {
            let mut route_manager = RouteManager::new().unwrap();
            let initial_routes = route_manager.list().unwrap();
            Self { initial_routes }
        }
    }

    impl Drop for RouteRestorer {
        /// Restores the system routing table to match the target routes
        /// Removes routes that shouldn't be there and adds routes that should be there
        fn drop(&mut self) {
            let mut route_manager = RouteManager::new().unwrap();
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

    async fn create_test_tun(
        local_ip: IpAddr,
    ) -> Result<(AsyncDevice, u32), Box<dyn std::error::Error>> {
        let tun_device = DeviceBuilder::new()
            .ipv4(
                match local_ip {
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

        let if_index = tun_device.if_index()?;

        Ok((tun_device, if_index))
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
    #[ignore = "May falsely fail during development due to local route settings"]
    fn test_privileged_new_routing_table(route_mode: RouteMode) {
        let (_restorer, routing_table) = create_test_setup(route_mode);
        assert_eq!(routing_table.routing_mode, route_mode);
        assert_eq!(routing_table.vpn_routes.len(), 0);
        assert_eq!(routing_table.lan_routes.len(), 0);
        assert!(routing_table.server_route.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_cleanup_empty_routes() {
        let (_restorer, mut routing_table) = create_test_setup(RouteMode::Default);

        // Get initial route count from the system
        let initial_count = routing_table.route_manager.list().unwrap().len();

        // Cleanup should not change system routes since vpn_routes is empty
        routing_table.cleanup().await;

        // Check that vpn_routes remains empty
        assert_eq!(routing_table.vpn_routes.len(), 0);
        assert_eq!(routing_table.lan_routes.len(), 0);

        // Check that system routes are unchanged
        let final_count = routing_table.route_manager.list().unwrap().len();
        assert_eq!(initial_count, final_count);
        assert!(routing_table.server_route.is_none());
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[serial_test::serial(routing_table)]
    #[ignore = "May falsely fail during development due to local route settings"]
    fn test_privileged_cleanup_sync(route_mode: RouteMode) {
        let (_restorer, mut routing_table) = create_test_setup(route_mode);

        // Get initial route count from the system
        let initial_count = routing_table.route_manager.list().unwrap().len();

        // Create test routes using shared fixtures
        let (vpn_route, lan_route, server_route, _gateway_ip) =
            create_test_routes_with_gateway(&mut routing_table);

        // Add routes directly to the sync route manager and store them
        routing_table.route_manager.add(&vpn_route).unwrap();
        routing_table.vpn_routes.push(vpn_route.clone());

        routing_table.route_manager.add(&lan_route).unwrap();
        routing_table.lan_routes.push(lan_route.clone());

        routing_table.route_manager.add(&server_route).unwrap();
        routing_table.server_route = Some(server_route.clone());

        // Verify routes were added to the system
        let routes_after_add = routing_table.route_manager.list().unwrap();
        let routes_added = routes_after_add.len() - initial_count;
        assert_eq!(routes_added, 3);

        // Verify internal state
        assert_eq!(routing_table.vpn_routes.len(), 1);
        assert_eq!(routing_table.lan_routes.len(), 1);
        assert!(routing_table.server_route.is_some());

        // Test cleanup_sync
        routing_table.cleanup_sync();

        // Verify routes were removed from the system
        let routes_after_cleanup = routing_table.route_manager.list().unwrap();
        let final_count = routes_after_cleanup.len();
        assert_eq!(final_count, initial_count);

        // Verify internal state is unchanged (cleanup_sync doesn't modify internal vectors)
        assert_eq!(routing_table.vpn_routes.len(), 1);
        assert_eq!(routing_table.lan_routes.len(), 1);
        assert!(routing_table.server_route.is_some());
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    #[ignore = "May affect system routing"]
    async fn test_privileged_is_route_exists_error_real() {
        let (_restorer, mut routing_table) = create_test_setup(RouteMode::Default);

        // Create test routes using shared fixtures
        let (route, _, _, _) = create_test_routes_with_gateway(&mut routing_table);

        // Add the route first time - should succeed
        routing_table.add_route(&route).await.unwrap();

        // Try to add the same route again - should get "route exists" error
        let result2 = routing_table.route_manager_async.add(&route).await;
        match result2 {
            Err(e) => {
                assert!(routing_table.is_route_exists_error(&e));
            }
            Ok(_) => panic!(),
        }
    }

    #[test_case(RouteAddMethod::Standard)]
    #[test_case(RouteAddMethod::Server)]
    #[test_case(RouteAddMethod::Lan)]
    #[tokio::test]
    #[serial_test::serial(routing_table)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_add_single_route(add_method: RouteAddMethod) {
        let (_restorer, mut routing_table) = create_test_setup(RouteMode::Default);

        // Create test route using shared fixtures
        let (route1, _route2, _route3, _gateway_ip) =
            create_test_routes_with_gateway(&mut routing_table);

        // Test adding route using the specified method
        match add_method {
            RouteAddMethod::Standard => routing_table.add_route_vpn(route1.clone()).await.unwrap(),
            RouteAddMethod::Server => routing_table
                .add_route_server(route1.clone())
                .await
                .unwrap(),
            RouteAddMethod::Lan => routing_table.add_route_lan(route1.clone()).await.unwrap(),
        };
        let routes_after_add1 = routing_table.route_manager.list().unwrap();

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
    #[serial_test::serial(routing_table)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_initialize_routing_table(route_mode: RouteMode) {
        let (_restorer, mut routing_table) = create_test_setup(route_mode);

        // Create a TUN device for testing using shared fixtures
        let (_tun_device, tun_index) = create_test_tun(TUN_LOCAL_IP).await.unwrap();

        // Test initialize_routing_table using shared fixtures
        routing_table
            .initialize_routing_table(&EXTERNAL_IP, tun_index, &TUN_PEER_IP, &TUN_DNS_IP)
            .await
            .unwrap();

        // Get system routes after initialization
        let routes_after_init = routing_table.route_manager.list().unwrap();

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
            let (default_index, default_gateway) = routing_table
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
    #[serial_test::serial(routing_table)]
    #[ignore = "May falsely fail during development due to local route settings"]
    async fn test_privileged_find_server_route(route_mode: RouteMode) {
        let (_restorer, mut routing_table) = create_test_setup(route_mode);

        // Create a TUN device for testing using different IP to avoid conflicts
        let (_tun_device, tun_index) = create_test_tun(TUN_LOCAL_IP).await.unwrap();

        // Create test routes using tunnel route constants
        let route1 = Route::new(TUNNEL_ROUTES[0].0, TUNNEL_ROUTES[0].1)
            .with_gateway(TUN_PEER_IP)
            .with_if_index(tun_index);
        let route2 = Route::new(TUNNEL_ROUTES[1].0, TUNNEL_ROUTES[1].1)
            .with_gateway(TUN_PEER_IP)
            .with_if_index(tun_index);

        // Add routes (assuming add_route works based on previous test)
        routing_table.add_route_vpn(route1.clone()).await.unwrap();

        // Test find_server_route for test_ip1 using shared fixtures
        let found_route1 = routing_table.find_route(&ROUTE_TEST_IP1).unwrap();
        assert_eq!(found_route1.gateway(), route1.gateway());

        routing_table.add_route_vpn(route2.clone()).await.unwrap();

        // Test find_server_route for test_ip1 after adding route2
        let found_route1 = routing_table.find_route(&ROUTE_TEST_IP1).unwrap();
        assert_eq!(found_route1.gateway(), route1.gateway());

        let found_route2 = routing_table.find_route(&ROUTE_TEST_IP2).unwrap();
        assert_eq!(found_route2.gateway(), route2.gateway());
    }
}
