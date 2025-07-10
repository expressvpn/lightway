use anyhow::{Context, Result};
use route_manager::{AsyncRouteManager, Route, RouteManager};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use tracing::warn;

// LAN networks for RouteMode::Lan
const LAN_NETWORKS: [(IpAddr, u8, &str); 5] = [
    (
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        16,
        "RFC 1918 Class C private",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
        12,
        "RFC 1918 Class B private",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        8,
        "RFC 1918 Class A private",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        16,
        "RFC 3927 link-local",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        24,
        "RFC 5771 multicast",
    ),
];

// Tunnel routes for high priority default routing
const TUNNEL_ROUTES: [(IpAddr, u8, &str); 2] = [
    (
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        1,
        "First half default route (0.0.0.0/1)",
    ),
    (
        IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
        1,
        "Second half default route (128.0.0.0/1)",
    ),
];

#[derive(Debug, PartialEq, Copy, Clone, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
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
    fn find_default_interface_index_and_gateway(
        &mut self,
        server_ip: &IpAddr,
    ) -> Result<(u32, IpAddr), RoutingTableError> {
        let default_route = self.find_route(server_ip)?;
        let default_interface_index = default_route
            .if_index()
            .ok_or(RoutingTableError::InterfaceIndexNotFound)?;
        let default_interface_gateway = default_route
            .gateway()
            .ok_or(RoutingTableError::InterfaceGatewayNotFound)?;
        Ok((default_interface_index, default_interface_gateway))
    }

    /// Adds Route
    async fn add_route(&mut self, route: &Route) -> Result<(), RoutingTableError> {
        self.route_manager_async.add(route).await.map_err(|e| {
            // Check if the error is related to permissions
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                RoutingTableError::InsufficientPermissions
            } else {
                RoutingTableError::AddRouteError(e)
            }
        })
    }

    /// Adds Routes and stores it
    pub async fn add_vpn_route(&mut self, route: Route) -> Result<(), RoutingTableError> {
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
    pub async fn add_standard_lan_routes(
        &mut self,
        interface_index: u32,
        gateway: IpAddr,
    ) -> Result<(), RoutingTableError> {
        for (network, prefix, _description) in LAN_NETWORKS {
            let lan_route = Route::new(network, prefix)
                .with_gateway(gateway)
                .with_if_index(interface_index);

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
        for (network, prefix, _description) in TUNNEL_ROUTES {
            let tunnel_route = Route::new(network, prefix)
                .with_gateway(gateway)
                .with_if_index(interface_index);

            self.add_vpn_route(tunnel_route).await?;
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
    /// Will not cleanup the Vec
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

        if let Some(route) = &self.server_route {
            if let Err(e) = self.route_manager.delete(route) {
                warn!(
                    "Failed to delete server route during drop: {}, error: {}",
                    route, e
                );
            }
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

        let server_route = Route::new(*server_ip, 32)
            .with_gateway(default_interface_gateway)
            .with_if_index(default_interface_index);

        self.add_route_server(server_route)
            .await
            .context("Adding VPN Server IP Route")?;

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

        self.add_vpn_route(dns_route).await.with_context(|| {
            format!("Adding tunnel route for Tunnel DNS server on interface {tun_index}")
        })?;
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
    use tun::AbstractDevice;

    async fn create_test_tun(
        local_ip: IpAddr,
    ) -> Result<(tun::Device, u32), Box<dyn std::error::Error>> {
        let mut config = tun::Configuration::default();
        config
            .address(local_ip.to_string())
            .netmask("255.255.255.0")
            .up();

        let tun_device = tun::create(&config)?;

        // Add 50ms sleep to allow TUN device to be fully initialized
        // NOTE: This sometimes adds an additional route after the tests have stored the initial route
        //       which may lead to inaccurate tests. 50ms is eternity and enough to stabilise this.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Get interface index - unwrap if not available
        let if_index = tun_device.tun_index().unwrap() as u32;

        Ok((tun_device, if_index))
    }

    #[derive(Debug)]
    enum RouteAddMethod {
        Standard,
        Server,
        Lan,
    }

    async fn test_single_route_add_and_cleanup(
        add_method: RouteAddMethod,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut routing_table = RoutingTable::new(RouteMode::Default).unwrap();

        // Get initial route count from the system
        let initial_routes = routing_table.route_manager.list().unwrap();
        let initial_count = initial_routes.len();

        // Create test route - use a simple host route to a specific IP
        // Find the default gateway by looking up a route to an external IP
        let external_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let default_route = routing_table
            .find_route(&external_ip)
            .expect("Could not find default gateway for test");

        let gateway_ip = default_route
            .gateway()
            .expect("Default route has no gateway");

        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));
        let route1 = Route::new(target_ip, 32).with_gateway(gateway_ip);

        // Test adding route using the specified method
        let result1 = match add_method {
            RouteAddMethod::Standard => routing_table.add_vpn_route(route1.clone()).await,
            RouteAddMethod::Server => routing_table.add_route_server(route1.clone()).await,
            RouteAddMethod::Lan => routing_table.add_route_lan(route1.clone()).await,
        };
        match result1 {
            Ok(_) => {
                let routes_after_add1 = routing_table.route_manager.list().unwrap();
                assert_eq!(
                    routes_after_add1.len(),
                    initial_count + 1,
                    "System routes count should increase from {} to {}, but got {}",
                    initial_count,
                    initial_count + 1,
                    routes_after_add1.len()
                );
                match add_method {
                    RouteAddMethod::Standard => {
                        assert_eq!(
                            routing_table.vpn_routes.len(),
                            1,
                            "VPN routes should have 1 route, but has {}",
                            routing_table.vpn_routes.len()
                        );
                        assert_eq!(
                            routing_table.vpn_routes[0], route1,
                            "VPN routes should have: {:?} but has {:?}",
                            route1, routing_table.vpn_routes[0]
                        );
                        assert!(
                            routing_table.server_route.is_none(),
                            "Server route should be None, but is {:?}",
                            routing_table.server_route
                        );
                        assert_eq!(
                            routing_table.lan_routes.len(),
                            0,
                            "LAN routes should have 0 routes, but has {}",
                            routing_table.lan_routes.len()
                        );
                    }
                    RouteAddMethod::Server => {
                        assert_eq!(
                            routing_table.vpn_routes.len(),
                            0,
                            "VPN routes should have 0 route, but has {}",
                            routing_table.vpn_routes.len()
                        );
                        assert_eq!(
                            routing_table.server_route,
                            Some(route1.clone()),
                            "Server route should be set, but is {:?}",
                            routing_table.server_route
                        );
                        assert_eq!(
                            routing_table.lan_routes.len(),
                            0,
                            "LAN routes should have 0 routes, but has {}",
                            routing_table.lan_routes.len()
                        );
                    }
                    RouteAddMethod::Lan => {
                        assert_eq!(
                            routing_table.vpn_routes.len(),
                            0,
                            "VPN routes should have 0 routes, but has {}",
                            routing_table.vpn_routes.len()
                        );
                        assert!(
                            routing_table.server_route.is_none(),
                            "Server route should be None, but is {:?}",
                            routing_table.server_route
                        );
                        assert_eq!(
                            routing_table.lan_routes.len(),
                            1,
                            "LAN routes should have 1 route, but has {}",
                            routing_table.lan_routes.len()
                        );
                        assert_eq!(
                            routing_table.lan_routes[0], route1,
                            "LAN routes should have: {:?} but has {:?}",
                            route1, routing_table.lan_routes[0]
                        );
                    }
                }

                // Verify the route was actually added to the system
                let route_found = routes_after_add1.iter().any(|r| {
                    r.destination() == route1.destination() && r.gateway() == route1.gateway()
                });
                if !route_found {
                    // Attempt cleanup on exit
                    routing_table.cleanup().await;
                }
                assert!(
                    route_found,
                    "Route1 was not found in the system routing table. Target: {:?}, Gateway: {:?}",
                    route1.destination(),
                    route1.gateway()
                );
            }
            Err(e) => match e {
                RoutingTableError::AddRouteError(e) => {
                    assert_eq!(routing_table.vpn_routes.len(), 0);
                    assert_eq!(routing_table.lan_routes.len(), 0);
                    panic!("Failed to add routes!: {e}");
                }
                RoutingTableError::InsufficientPermissions => {
                    assert_eq!(routing_table.vpn_routes.len(), 0);
                    assert_eq!(routing_table.lan_routes.len(), 0);
                    panic!(
                        "WARNING: Insufficient permissions to modify routing table. Run tests with sudo/administrator privileges to test route modification. \n Consider running with sudo -E cargo test"
                    );
                }
                _ => panic!("Unexpected error type: {e:?}"),
            },
        }

        // Get route count before cleanup
        let routes_before_cleanup = routing_table.route_manager.list().unwrap();
        let before_cleanup_count = routes_before_cleanup.len();
        let vpn_routes_count = routing_table.vpn_routes.len();
        let route_server_count = routing_table.server_route.is_some() as usize;
        let lan_routes_count = routing_table.lan_routes.len();

        // Test cleanup
        routing_table.cleanup().await;

        // Verify vpn_routes is empty after cleanup
        assert_eq!(
            routing_table.vpn_routes.len(),
            0,
            "VPN routes should be empty after cleanup, but has {} routes",
            routing_table.vpn_routes.len()
        );
        assert!(
            routing_table.server_route.is_none(),
            "Server route should be None after cleanup, but is {:?}",
            routing_table.server_route
        );

        // Verify system routes are reduced by the number of routes we had in store
        let routes_after_cleanup = routing_table.route_manager.list().unwrap();
        let after_cleanup_count = routes_after_cleanup.len();
        assert_eq!(
            after_cleanup_count,
            before_cleanup_count - vpn_routes_count - route_server_count - lan_routes_count,
            "System routes should be reduced from {} to {} (difference: {}), but got {}",
            before_cleanup_count,
            before_cleanup_count - vpn_routes_count - route_server_count - lan_routes_count,
            vpn_routes_count,
            after_cleanup_count
        );

        Ok(())
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    fn test_new_routing_table(route_mode: RouteMode) {
        let result = RoutingTable::new(route_mode);
        assert!(result.is_ok());
        let routing_table = result.unwrap();
        assert_eq!(routing_table.routing_mode, route_mode);
        assert_eq!(routing_table.vpn_routes.len(), 0);
        assert_eq!(routing_table.lan_routes.len(), 0);
        assert!(routing_table.server_route.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_cleanup_empty_routes() {
        let mut routing_table = RoutingTable::new(RouteMode::Default).unwrap();

        // Get initial route count from the system
        // let initial_routes = routing_table.route_manager.list().unwrap_or_default();
        let initial_routes = routing_table.route_manager.list().unwrap();
        let initial_count = initial_routes.len();

        // Cleanup should not change system routes since vpn_routes is empty
        routing_table.cleanup().await;

        // Check that vpn_routes remains empty
        assert_eq!(routing_table.vpn_routes.len(), 0);
        assert_eq!(routing_table.lan_routes.len(), 0);

        // Check that system routes are unchanged
        let final_routes = routing_table.route_manager.list().unwrap();
        let final_count = final_routes.len();
        assert_eq!(initial_count, final_count);
        assert!(routing_table.server_route.is_none());
    }

    #[test_case(RouteAddMethod::Standard)]
    #[test_case(RouteAddMethod::Server)]
    #[test_case(RouteAddMethod::Lan)]
    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_add_single_route_and_cleanup(add_method: RouteAddMethod) {
        test_single_route_add_and_cleanup(add_method).await.unwrap();
    }

    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_initialize_routing_table_and_cleanup(
        route_mode: RouteMode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut routing_table = RoutingTable::new(route_mode).unwrap();

        // Create a TUN device for testing
        let tun_local_ip = IpAddr::V4(Ipv4Addr::new(10, 49, 0, 1));
        let (tun_device, tun_index) = match create_test_tun(tun_local_ip).await {
            Ok((device, index)) => (device, index),
            Err(e) => {
                panic!("Cannot create TUN device: {e}");
            }
        };
        let tun_peer_ip = IpAddr::V4(Ipv4Addr::new(10, 49, 0, 2));

        // Get initial system state AFTER TUN device creation
        let initial_routes = routing_table.route_manager.list().unwrap();
        let initial_count = initial_routes.len();

        // Set up parameters for initialization
        let server_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let tun_dns_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));

        // Test initialize_routing_table
        let result = routing_table
            .initialize_routing_table(&server_ip, tun_index, &tun_peer_ip, &tun_dns_ip)
            .await;

        match result {
            Ok(_) => {
                // Verify state after initialization
                let routes_after_init = routing_table.route_manager.list().unwrap();
                let routes_added = routes_after_init.len() - initial_count;

                match route_mode {
                    RouteMode::NoExec => {
                        // NoExec mode should not add any routes
                        // NOTE: This test occasionally fails without discernable reason
                        assert_eq!(
                            routes_added, 0,
                            "NoExec mode should not add any routes, but added {routes_added}"
                        );
                        assert_eq!(
                            routing_table.vpn_routes.len(),
                            0,
                            "VPN routes should be empty for NoExec mode, but has {}",
                            routing_table.vpn_routes.len()
                        );
                        assert!(
                            routing_table.server_route.is_none(),
                            "Server route should be None for NoExec mode"
                        );
                    }
                    RouteMode::Default => {
                        // Default mode should add at least (1 server + TUNNEL_ROUTES + 1 DNS) routes
                        assert!(
                            routes_added > 1 + TUNNEL_ROUTES.len(),
                            "Default mode should have added at least {} routes (1 server + {} tunnel routes + 1 DNS), but added {}",
                            1 + TUNNEL_ROUTES.len() + 1,
                            TUNNEL_ROUTES.len(),
                            routes_added
                        );

                        // Check vpn_routes has the expected routes (TUNNEL_ROUTES + 1 DNS)
                        assert_eq!(
                            routing_table.vpn_routes.len(),
                            TUNNEL_ROUTES.len() + 1,
                            "VPN routes should have {} routes after Default mode initialization, but has {}",
                            TUNNEL_ROUTES.len() + 1,
                            routing_table.vpn_routes.len()
                        );

                        // Check server_route is set
                        assert!(
                            routing_table.server_route.is_some(),
                            "Server route should be set after Default mode initialization"
                        );

                        let server_route = routing_table.server_route.as_ref().unwrap();
                        assert_eq!(
                            server_route.destination(),
                            server_ip,
                            "Server route destination should be {}, but is {:?}",
                            server_ip,
                            server_route.destination()
                        );
                        assert_eq!(
                            server_route.prefix(),
                            32,
                            "Server route prefix should be 32, but is {}",
                            server_route.prefix()
                        );

                        // Verify the tunnel routes in vpn_routes
                        for (network, prefix, _description) in TUNNEL_ROUTES {
                            let route_found = routing_table.vpn_routes.iter().any(|r| {
                                r.destination() == network
                                    && r.prefix() == prefix
                                    && r.gateway() == Some(tun_peer_ip)
                                    && r.if_index() == Some(tun_index)
                            });
                            assert!(
                                route_found,
                                "Expected tunnel route {network}/{prefix} via {tun_peer_ip} dev {tun_index} not found in vpn_routes"
                            );
                        }

                        // Verify the DNS route
                        let dns_route_found = routing_table.vpn_routes.iter().any(|r| {
                            r.destination() == tun_dns_ip
                                && r.prefix() == 32
                                && r.gateway() == Some(tun_peer_ip)
                                && r.if_index() == Some(tun_index)
                        });
                        assert!(
                            dns_route_found,
                            "Expected DNS route {tun_dns_ip}/32 via {tun_peer_ip} dev {tun_index} not found in vpn_routes"
                        );
                    }
                    RouteMode::Lan => {
                        // Lan mode should add at least (1 server + LAN_NETWORKS + TUNNEL_ROUTES + 1 DNS) routes
                        assert!(
                            routes_added > 1 + LAN_NETWORKS.len() + TUNNEL_ROUTES.len(),
                            "Lan mode should have added at least {} routes (1 server + {} LAN + {} tunnel routes + 1 DNS), but added {}",
                            1 + LAN_NETWORKS.len() + TUNNEL_ROUTES.len() + 1,
                            LAN_NETWORKS.len(),
                            TUNNEL_ROUTES.len(),
                            routes_added
                        );

                        // Check vpn_routes has the expected routes (TUNNEL_ROUTES + 1 DNS)
                        assert_eq!(
                            routing_table.vpn_routes.len(),
                            TUNNEL_ROUTES.len() + 1,
                            "VPN routes should have {} routes after Lan mode initialization, but has {}",
                            TUNNEL_ROUTES.len() + 1,
                            routing_table.vpn_routes.len()
                        );

                        // Check lan_routes has the expected routes (LAN_NETWORKS routes)
                        assert_eq!(
                            routing_table.lan_routes.len(),
                            LAN_NETWORKS.len(),
                            "LAN route store should have {} routes after Lan mode initialization, but has {}",
                            LAN_NETWORKS.len(),
                            routing_table.lan_routes.len()
                        );

                        // Check server_route is set
                        assert!(
                            routing_table.server_route.is_some(),
                            "Server route should be set after Lan mode initialization"
                        );

                        let server_route = routing_table.server_route.as_ref().unwrap();
                        assert_eq!(
                            server_route.destination(),
                            server_ip,
                            "Server route destination should be {}, but is {:?}",
                            server_ip,
                            server_route.destination()
                        );
                        assert_eq!(
                            server_route.prefix(),
                            32,
                            "Server route prefix should be 32, but is {}",
                            server_route.prefix()
                        );

                        // Find default gateway for LAN routes verification
                        let (_, default_gateway) = routing_table
                            .find_default_interface_index_and_gateway(&server_ip)
                            .unwrap();

                        // Verify the LAN routes in lan_routes
                        for (network, prefix, _description) in LAN_NETWORKS {
                            let lan_route_found = routing_table.lan_routes.iter().any(|r| {
                                r.destination() == network
                                    && r.prefix() == prefix
                                    && r.gateway() == Some(default_gateway)
                            });
                            assert!(
                                lan_route_found,
                                "Expected LAN route {network}/{prefix} via {default_gateway} not found in lan_routes"
                            );
                        }

                        // Verify the tunnel routes in vpn_routes (same as default mode)
                        for (network, prefix, _description) in TUNNEL_ROUTES {
                            let tunnel_route_found = routing_table.vpn_routes.iter().any(|r| {
                                r.destination() == network
                                    && r.prefix() == prefix
                                    && r.gateway() == Some(tun_peer_ip)
                                    && r.if_index() == Some(tun_index)
                            });
                            assert!(
                                tunnel_route_found,
                                "Expected tunnel route {network}/{prefix} via {tun_peer_ip} dev {tun_index} not found in vpn_routes"
                            );
                        }

                        // Verify the DNS route
                        let dns_route_found = routing_table.vpn_routes.iter().any(|r| {
                            r.destination() == tun_dns_ip
                                && r.prefix() == 32
                                && r.gateway() == Some(tun_peer_ip)
                                && r.if_index() == Some(tun_index)
                        });
                        assert!(
                            dns_route_found,
                            "Expected DNS route {tun_dns_ip}/32 via {tun_peer_ip} dev {tun_index} not found in vpn_routes"
                        );
                    }
                }
            }
            Err(e) => {
                routing_table.cleanup().await;
                drop(tun_device);
                panic!("Unexpected error during routing table initialization: {e:?}");
            }
        }

        // Get state before cleanup
        let routes_before_cleanup = routing_table.route_manager.list().unwrap();
        let before_cleanup_count = routes_before_cleanup.len();
        let vpn_routes_count = routing_table.vpn_routes.len();
        let lan_routes_count = routing_table.lan_routes.len();
        let server_route_count = if routing_table.server_route.is_some() {
            1
        } else {
            0
        };

        // Test cleanup
        routing_table.cleanup().await;

        // Verify cleanup worked
        assert_eq!(
            routing_table.vpn_routes.len(),
            0,
            "VPN routes should be empty after cleanup, but has {} routes",
            routing_table.vpn_routes.len()
        );
        assert_eq!(
            routing_table.lan_routes.len(),
            0,
            "LAN route store should be empty after cleanup, but has {} routes",
            routing_table.lan_routes.len()
        );
        assert!(
            routing_table.server_route.is_none(),
            "Server route should be None after cleanup, but is {:?}",
            routing_table.server_route
        );

        // Verify system routes are reduced
        let routes_after_cleanup = routing_table.route_manager.list().unwrap();
        let after_cleanup_count = routes_after_cleanup.len();
        let expected_final_count =
            before_cleanup_count - vpn_routes_count - lan_routes_count - server_route_count;

        assert_eq!(
            after_cleanup_count,
            expected_final_count,
            "System routes should be reduced from {} to {} (removed: {}), but got {}",
            before_cleanup_count,
            expected_final_count,
            vpn_routes_count + lan_routes_count + server_route_count,
            after_cleanup_count
        );

        // Cleanup TUN device
        drop(tun_device);

        Ok(())
    }

    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::NoExec)]
    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_find_server_route_with_added_routes(
        route_mode: RouteMode,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut routing_table = RoutingTable::new(route_mode).unwrap();

        // Create a TUN device for testing
        let tun_local_ip = IpAddr::V4(Ipv4Addr::new(10, 47, 0, 1));
        let (tun_device, tun_index) = match create_test_tun(tun_local_ip).await {
            Ok((device, index)) => (device, index),
            Err(e) => {
                panic!("Cannot create TUN device: {e}.");
            }
        };

        let tun_peer_ip = IpAddr::V4(Ipv4Addr::new(10, 47, 0, 5));

        // Create test routes and IP addresses for testing
        let route1 = Route::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
            .with_gateway(tun_peer_ip)
            .with_if_index(tun_index);
        let route2 = Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
            .with_gateway(tun_peer_ip)
            .with_if_index(tun_index);

        // Test IP addresses that should route through our added routes
        let test_ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)); // Should match to route1 (0.0.0.0/1)
        let test_ip2 = IpAddr::V4(Ipv4Addr::new(200, 1, 1, 1)); // Should match to route2 (128.0.0.0/1)

        // Add routes (assuming add_route works based on previous test)
        let result1 = routing_table.add_route(&route1).await;
        match result1 {
            Ok(_) => {
                routing_table.vpn_routes.push(route1.clone());
            }
            Err(e) => {
                drop(tun_device);
                match e {
                    RoutingTableError::AddRouteError(_) => {
                        panic!("Failed to add route error: {e:?}");
                    }
                    RoutingTableError::InsufficientPermissions => {
                        panic!("WARNING: Cannot add routes due to insufficient permissions");
                    }
                    _ => {
                        panic!("Unexpected error type: {e:?}");
                    }
                }
            }
        }

        // Test find_server_route for test_ip1
        let found_route1 = routing_table.find_route(&test_ip1);
        match found_route1 {
            Ok(found_route) => {
                assert_eq!(
                    found_route.gateway(),
                    route1.gateway(),
                    "find_server_route for test_ip1 did not return the expected gateway"
                );
            }
            Err(_) => {
                routing_table.cleanup().await;
                drop(tun_device);
                panic!("find_server_route for test_ip1 did not find the expected route");
            }
        }

        let result2 = routing_table.add_route(&route2).await;
        match result2 {
            Ok(_) => {
                routing_table.vpn_routes.push(route2.clone());
            }
            Err(e) => {
                routing_table.cleanup().await;
                drop(tun_device);
                match e {
                    RoutingTableError::AddRouteError(_) => {
                        panic!("Failed to add second route error: {e:?}");
                    }
                    RoutingTableError::InsufficientPermissions => {
                        panic!("WARNING: Cannot add second route due to insufficient permissions");
                    }
                    _ => {
                        panic!("Unexpected error type: {e:?}");
                    }
                }
            }
        }

        // Test find_server_route for test_ip1 after adding route2
        let found_route1 = routing_table.find_route(&test_ip1);
        match found_route1 {
            Ok(found_route) => {
                assert_eq!(
                    found_route.gateway(),
                    route1.gateway(),
                    "find_server_route for test_ip1 did not return the expected gateway after route2 was added"
                );
            }
            Err(_) => {
                routing_table.cleanup().await;
                drop(tun_device);
                panic!(
                    "find_server_route for test_ip1 did not find the expected route after route2 was added"
                );
            }
        }

        // Test find_server_route for test_ip2 (only if route2 was added)
        if routing_table.vpn_routes.len() > 1 {
            let found_route2 = routing_table.find_route(&test_ip2);
            match found_route2 {
                Ok(found_route) => {
                    assert_eq!(
                        found_route.gateway(),
                        route2.gateway(),
                        "find_server_route for test_ip2 did not return the expected gateway"
                    );
                }
                Err(_) => {
                    routing_table.cleanup().await;
                    drop(tun_device);
                    panic!("find_server_route for test_ip2 did not find the expected route");
                }
            }
        }

        // Cleanup routes first
        routing_table.cleanup().await;

        // TUN device will be automatically cleaned up when dropped
        drop(tun_device);

        Ok(())
    }

    #[test_case(RouteMode::Default)]
    #[test_case(RouteMode::Lan)]
    #[test_case(RouteMode::NoExec)]
    #[serial_test::serial(routing_table)]
    fn test_cleanup_sync(route_mode: RouteMode) {
        let mut routing_table = RoutingTable::new(route_mode).unwrap();

        // Get initial route count from the system
        let initial_routes = routing_table.route_manager.list().unwrap();
        let initial_count = initial_routes.len();

        // Create test routes - use simple host routes to specific IPs
        let external_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let default_route = routing_table
            .find_route(&external_ip)
            .expect("Could not find default gateway for test");

        let gateway_ip = default_route
            .gateway()
            .expect("Default route has no gateway");

        let target_ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));
        let target_ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 2));
        let target_ip3 = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 3));

        let vpn_route = Route::new(target_ip1, 32).with_gateway(gateway_ip);
        let lan_route = Route::new(target_ip2, 32).with_gateway(gateway_ip);
        let server_route = Route::new(target_ip3, 32).with_gateway(gateway_ip);

        // Add routes directly to the sync route manager and store them
        match routing_table.route_manager.add(&vpn_route) {
            Ok(_) => {
                routing_table.vpn_routes.push(vpn_route.clone());
            }
            Err(e) => {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    panic!(
                        "WARNING: Insufficient permissions to modify routing table. Run tests with sudo/administrator privileges to test route modification."
                    );
                } else {
                    panic!("Failed to add VPN route: {e}");
                }
            }
        }

        match routing_table.route_manager.add(&lan_route) {
            Ok(_) => {
                routing_table.lan_routes.push(lan_route.clone());
            }
            Err(e) => {
                // Clean up already added routes before panicking
                let _ = routing_table.route_manager.delete(&vpn_route);
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    panic!(
                        "WARNING: Insufficient permissions to modify routing table. Run tests with sudo/administrator privileges to test route modification."
                    );
                } else {
                    panic!("Failed to add LAN route: {e}");
                }
            }
        }

        match routing_table.route_manager.add(&server_route) {
            Ok(_) => {
                routing_table.server_route = Some(server_route.clone());
            }
            Err(e) => {
                // Clean up already added routes before panicking
                let _ = routing_table.route_manager.delete(&vpn_route);
                let _ = routing_table.route_manager.delete(&lan_route);
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    panic!(
                        "WARNING: Insufficient permissions to modify routing table. Run tests with sudo/administrator privileges to test route modification."
                    );
                } else {
                    panic!("Failed to add server route: {e}");
                }
            }
        }

        // Verify routes were added to the system
        let routes_after_add = routing_table.route_manager.list().unwrap();
        let routes_added = routes_after_add.len() - initial_count;
        assert_eq!(
            routes_added, 3,
            "Should have added 3 routes, but added {routes_added}"
        );

        // Verify internal state
        assert_eq!(routing_table.vpn_routes.len(), 1);
        assert_eq!(routing_table.lan_routes.len(), 1);
        assert!(routing_table.server_route.is_some());

        // Test cleanup_sync
        routing_table.cleanup_sync();

        // Verify routes were removed from the system
        let routes_after_cleanup = routing_table.route_manager.list().unwrap();
        let final_count = routes_after_cleanup.len();
        assert_eq!(
            final_count, initial_count,
            "System routes should be back to initial count {initial_count} after cleanup_sync, but got {final_count}"
        );

        // Verify internal state is unchanged (cleanup_sync doesn't modify internal vectors)
        assert_eq!(
            routing_table.vpn_routes.len(),
            1,
            "cleanup_sync should not modify vpn_routes length"
        );
        assert_eq!(
            routing_table.lan_routes.len(),
            1,
            "cleanup_sync should not modify lan_routes length"
        );
        assert!(
            routing_table.server_route.is_some(),
            "cleanup_sync should not modify server_route"
        );
    }
}
