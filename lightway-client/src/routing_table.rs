use anyhow::{Context, Result};
use route_manager::{AsyncRouteManager, Route, RouteManager};
use serde::{Serialize, Deserialize};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use tracing::warn;

#[derive(Debug, PartialEq, Copy, Clone, clap::ValueEnum, Serialize, Deserialize)]
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
    #[error("Interface name not found")]
    InterfaceNameNotFound,
    #[error("Interface gateway not found")]
    InterfaceGatewayNotFound,
    #[error("Insufficient permissions to modify routing table. Run with administrator/root privileges.")]
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
    route_store: Vec<Route>,
    server_route: Option<Route>,
}

impl RoutingTable {
    pub fn new(routing_mode: RouteMode) -> Result<Self, RoutingTableError> {
        let route_manager =
            RouteManager::new().map_err(|e| RoutingTableError::RoutingManagerError(e))?;
        let route_manager_async =
            AsyncRouteManager::new().map_err(|e| RoutingTableError::AsyncRoutingManagerError(e))?;
        Ok(Self {
            routing_mode,
            route_manager,
            route_manager_async,
            route_store: Vec::with_capacity(4),
            server_route: None,
        })
    }

    pub async fn cleanup(&mut self) {
        for r in self.route_store.drain(..) {
            self.route_manager_async
                .delete(&r)
                .await
                .unwrap_or_else(|e| {
                    warn!("Failed to delete route: {r}, error: {e}");
                })
        }
        if let Some(r) = &self.server_route {
            self.route_manager_async
                    .delete(&r)
                    .await
                    .unwrap_or_else(|e| {
                        warn!("Failed to delete server route: {r}, error: {e}");
                    })
        }
        self.server_route = None;
    }

    /// Identifies route used to reach a particular ip
    fn find_route(&mut self, server_ip: &IpAddr) -> Result<Route, RoutingTableError> {
        Ok(self
            .route_manager
            .find_route(server_ip)
            .map_err(|e| RoutingTableError::DefaultInterfaceNotFound(e))?
            .unwrap())
    }

    /// Identifies default interface by finding the route to be used to access server_ip
    fn find_default_interface_name_and_gateway(
        &mut self,
        server_ip: &IpAddr,
    ) -> Result<(String, IpAddr), RoutingTableError> {
        let default_route = self.find_route(server_ip)?;
        let default_interface_name = default_route
            .if_name()
            .ok_or(RoutingTableError::InterfaceNameNotFound)?
            .to_string();
        let default_interface_gateway = default_route
            .gateway()
            .ok_or(RoutingTableError::InterfaceGatewayNotFound)?;
        Ok((default_interface_name, default_interface_gateway))
    }

    /// Adds Route
    async fn add_route(&mut self, route: &Route) -> Result<(), RoutingTableError> {
        self.route_manager_async
            .add(route)
            .await
            .map_err(|e| {
                // Check if the error is related to permissions
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    RoutingTableError::InsufficientPermissions
                } else {
                    RoutingTableError::AddRouteError(e)
                }
            })
    }

    /// Adds Routes and stores it
    pub async fn add_route_store(&mut self, route: Route) -> Result<(), RoutingTableError> {
        self.add_route(&route).await?;
        self.route_store.push(route);
        Ok(())
    }

    /// Adds Server Route and stores it
    pub async fn add_route_server(&mut self, route: Route) -> Result<(), RoutingTableError> {
        if self.server_route.is_some() {
            return Err(RoutingTableError::ServerRouteAlreadyExists)
        }
        self.add_route(&route).await?;
        self.server_route = Some(route);
        Ok(())
    }

    async fn initialize_routing_table(
        &mut self,
        server_ip: &IpAddr,
        tun_name: &str,
        tun_local_ip: &IpAddr,
        tun_peer_ip: &IpAddr,
        tun_dns_ip: &IpAddr,
    ) -> Result<()> {
        if self.routing_mode == RouteMode::NoExec {
            return Ok(());
        }

        // Setting up VPN Server Routes
        let (default_interface_name, default_interface_gateway) =
            self.find_default_interface_name_and_gateway(server_ip)?;

        let server_route = Route::new(*server_ip, 32)
            .with_gateway(default_interface_gateway)
            .with_if_name(default_interface_name);

        self.add_route_server(server_route)
            .await
            .context("Adding VPN Server IP Route")?;

        if self.routing_mode == RouteMode::Lan {
            todo!()
        }

        // Setting up high priority routes
        let default_route_0 = Route::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
            .with_gateway(*tun_peer_ip)
            .with_if_name(tun_name.to_string());
        let default_route_1 = Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
            .with_gateway(*tun_peer_ip)
            .with_if_name(tun_name.to_string());
        let dns_route = Route::new(*tun_dns_ip, 32)
            .with_gateway(*tun_peer_ip)
            .with_if_name(tun_name.to_string());

        self.add_route_store(default_route_0)
            .await
            .context("Adding First Default Route")?;
        self.add_route_store(default_route_1)
            .await
            .context("Adding Second Default Route")?;
        self.add_route_store(dns_route)
            .await
            .context("Adding Tun DNS IP Route")?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio;

    fn create_test_tun(name: &str, ip: &str) -> Result<(tun::Device, IpAddr), Box<dyn std::error::Error>> {
        let mut config = tun::Configuration::default();
        config
            .tun_name(name)
            .address(ip)
            .netmask("255.255.255.0")
            .up();

        let tun_device = tun::create(&config)?;
        let ip_addr = ip.parse::<IpAddr>()?;
        Ok((tun_device, ip_addr))
    }

    #[derive(Debug)]
    enum RouteAddMethod {
        Store,
        Server,
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
        let default_route = routing_table.find_route(&external_ip)
            .expect("Could not find default gateway for test");
        
        let gateway_ip = default_route.gateway()
            .expect("Default route has no gateway");
        
        let target_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1));
        let route1 = Route::new(target_ip, 32)
            .with_gateway(gateway_ip);

        // Test adding route using the specified method
        let result1 = match add_method {
            RouteAddMethod::Store => routing_table.add_route_store(route1.clone()).await,
            RouteAddMethod::Server => routing_table.add_route_server(route1.clone()).await,
        };
        match result1 {
            Ok(_) => {
                let routes_after_add1 = routing_table.route_manager.list().unwrap();
                assert_eq!(routes_after_add1.len(), initial_count + 1, 
                          "System routes count should increase from {} to {}, but got {}", 
                          initial_count, initial_count + 1, routes_after_add1.len());
                match add_method {
                    RouteAddMethod::Store => {
                        assert_eq!(routing_table.route_store.len(), 1, 
                                "Route store should have 1 route, but has {}", routing_table.route_store.len());
                        assert_eq!(routing_table.route_store[0], route1, "Route store should have: {:?} but has {:?}", route1, routing_table.route_store[0]);
                        assert!(routing_table.server_route.is_none(), 
                           "Server route should be None, but is {:?}", routing_table.server_route);
                    },
                    RouteAddMethod::Server => {
                        assert_eq!(routing_table.route_store.len(), 0, 
                                "Route store should have 0 route, but has {}", routing_table.route_store.len());
                        assert_eq!(routing_table.server_route, Some(route1.clone()), 
                            "Server route should be set, but is {:?}", routing_table.server_route);
                    },
                }

                // Verify the route was actually added to the system
                let route_found = routes_after_add1.iter().any(|r| {
                    r.destination() == route1.destination() &&
                    r.gateway() == route1.gateway()
                });
                if !route_found {
                    // Attempt cleanup on exit
                    routing_table.cleanup().await;
                }
                assert!(route_found, "Route1 was not found in the system routing table. Target: {:?}, Gateway: {:?}", 
                       route1.destination(), route1.gateway());
            }
            Err(e) => match e {
                RoutingTableError::AddRouteError(e) => {
                    assert_eq!(routing_table.route_store.len(), 0);
                    panic!("Failed to add routes!: {e}");
                }
                RoutingTableError::InsufficientPermissions => {
                    assert_eq!(routing_table.route_store.len(), 0);
                    panic!("WARNING: Insufficient permissions to modify routing table. Run tests with sudo/administrator privileges to test route modification. \n Consider running with sudo -E cargo test");
                }
                _ => panic!("Unexpected error type: {:?}", e),
            },
        }

        // Get route count before cleanup
        let routes_before_cleanup = routing_table.route_manager.list().unwrap();
        let before_cleanup_count = routes_before_cleanup.len();
        let route_store_count = routing_table.route_store.len();
        let route_server_count = routing_table.server_route.is_some() as usize;

        // Test cleanup
        routing_table.cleanup().await;

        // Verify route_store is empty after cleanup
        assert_eq!(routing_table.route_store.len(), 0, 
                  "Route store should be empty after cleanup, but has {} routes", routing_table.route_store.len());
        assert!(routing_table.server_route.is_none(), 
               "Server route should be None after cleanup, but is {:?}", routing_table.server_route);

        // Verify system routes are reduced by the number of routes we had in store
        let routes_after_cleanup = routing_table.route_manager.list().unwrap();
        let after_cleanup_count = routes_after_cleanup.len();
        assert_eq!(
            after_cleanup_count,
            before_cleanup_count - route_store_count - route_server_count,
            "System routes should be reduced from {} to {} (difference: {}), but got {}",
            before_cleanup_count, before_cleanup_count - route_store_count - route_server_count, route_store_count, after_cleanup_count
        );

        Ok(())
    }

    #[test]
    fn test_new_routing_table_default_mode() {
        let result = RoutingTable::new(RouteMode::Default);
        assert!(result.is_ok());
        let routing_table = result.unwrap();
        assert_eq!(routing_table.routing_mode, RouteMode::Default);
        assert_eq!(routing_table.route_store.len(), 0);
        assert!(routing_table.server_route.is_none());
    }

    #[test]
    fn test_new_routing_table_lan_mode() {
        let result = RoutingTable::new(RouteMode::Lan);
        assert!(result.is_ok());
        let routing_table = result.unwrap();
        assert_eq!(routing_table.routing_mode, RouteMode::Lan);
        assert_eq!(routing_table.route_store.len(), 0);
        assert!(routing_table.server_route.is_none());
    }

    #[test]
    fn test_new_routing_table_noexec_mode() {
        let result = RoutingTable::new(RouteMode::NoExec);
        assert!(result.is_ok());
        let routing_table = result.unwrap();
        assert_eq!(routing_table.routing_mode, RouteMode::NoExec);
        assert_eq!(routing_table.route_store.len(), 0);
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

        // Cleanup should not change system routes since route_store is empty
        routing_table.cleanup().await;

        // Check that route_store remains empty
        assert_eq!(routing_table.route_store.len(), 0);

        // Check that system routes are unchanged
        let final_routes = routing_table.route_manager.list().unwrap();
        let final_count = final_routes.len();
        assert_eq!(initial_count, final_count);
        assert!(routing_table.server_route.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_add_single_route_store_and_cleanup() {
        test_single_route_add_and_cleanup(
            RouteAddMethod::Store,
        ).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_add_single_route_server_and_cleanup() {
        test_single_route_add_and_cleanup(
            RouteAddMethod::Server,
        ).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_initialize_routing_table_and_cleanup() {
        let mut routing_table = RoutingTable::new(RouteMode::Default).unwrap();

        // Get initial system state
        let initial_routes = routing_table.route_manager.list().unwrap();
        let initial_count = initial_routes.len();

        // Create a TUN device for testing
        let tun_name = "init_test_tun";
        let (tun_device, tun_local_ip) = match create_test_tun(tun_name, "10.49.0.1") {
            Ok((device, ip)) => (device, ip),
            Err(e) => {
                println!("WARNING: Cannot create TUN device: {}. Skipping test.", e);
                return;
            }
        };

        // Set up parameters for initialization
        let server_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let tun_peer_ip = IpAddr::V4(Ipv4Addr::new(10, 49, 0, 2));
        let tun_dns_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4));

        // Test initialize_routing_table
        let result = routing_table.initialize_routing_table(
            &server_ip,
            tun_name,
            &tun_local_ip,
            &tun_peer_ip,
            &tun_dns_ip,
        ).await;

        match result {
            Ok(_) => {
                // Verify state after initialization
                let routes_after_init = routing_table.route_manager.list().unwrap();
                let routes_added = routes_after_init.len() - initial_count;
                
                assert!(routes_added >= 4, 
                       "Should have added at least 4 routes (1 server + 3 tunnel routes), but added {}", routes_added);

                // Check route_store has the expected routes (3 routes: 2 default + 1 DNS)
                assert_eq!(routing_table.route_store.len(), 3, 
                          "Route store should have 3 routes after initialization, but has {}", routing_table.route_store.len());

                // Check server_route is set
                assert!(routing_table.server_route.is_some(), 
                       "Server route should be set after initialization");

                let server_route = routing_table.server_route.as_ref().unwrap();
                assert_eq!(server_route.destination(), server_ip, 
                          "Server route destination should be {}, but is {:?}", server_ip, server_route.destination());
                assert_eq!(server_route.prefix(), 32, 
                          "Server route prefix should be 32, but is {}", server_route.prefix());

                // Verify the routes in route_store
                let expected_routes = [
                    (IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1),     // First default route
                    (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),   // Second default route
                    (tun_dns_ip, 32),                                // DNS route
                ];

                for (expected_dest, expected_prefix) in expected_routes.iter() {
                    let route_found = routing_table.route_store.iter().any(|r| {
                        r.destination() == *expected_dest && 
                        r.prefix() == *expected_prefix &&
                        r.gateway() == Some(tun_peer_ip) &&
                        r.if_name() == Some(&tun_name.to_string())
                    });
                    assert!(route_found, 
                           "Expected route {}/{} via {} dev {} not found in route_store", 
                           expected_dest, expected_prefix, tun_peer_ip, tun_name);
                }

                // Verify routes are actually in the system
                for (expected_dest, expected_prefix) in expected_routes.iter() {
                    let system_route_found = routes_after_init.iter().any(|r| {
                        r.destination() == *expected_dest && 
                        r.prefix() == *expected_prefix &&
                        r.gateway() == Some(tun_peer_ip)
                    });
                    assert!(system_route_found, 
                           "Expected route {}/{} via {} not found in system routing table", 
                           expected_dest, expected_prefix, tun_peer_ip);
                }
            }
            Err(e) => {
                routing_table.cleanup().await;
                drop(tun_device);
                panic!("Unexpected error during routing table initialization: {:?}", e);
            }
        }

        // Get state before cleanup
        let routes_before_cleanup = routing_table.route_manager.list().unwrap();
        let before_cleanup_count = routes_before_cleanup.len();
        let route_store_count = routing_table.route_store.len();
        let server_route_count = if routing_table.server_route.is_some() { 1 } else { 0 };

        // Test cleanup
        routing_table.cleanup().await;

        // Verify cleanup worked
        assert_eq!(routing_table.route_store.len(), 0, 
                  "Route store should be empty after cleanup, but has {} routes", routing_table.route_store.len());
        assert!(routing_table.server_route.is_none(), 
               "Server route should be None after cleanup, but is {:?}", routing_table.server_route);

        // Verify system routes are reduced
        let routes_after_cleanup = routing_table.route_manager.list().unwrap();
        let after_cleanup_count = routes_after_cleanup.len();
        let expected_final_count = before_cleanup_count - route_store_count - server_route_count;
        
        assert_eq!(after_cleanup_count, expected_final_count,
                  "System routes should be reduced from {} to {} (removed: {}), but got {}",
                  before_cleanup_count, expected_final_count, route_store_count + server_route_count, after_cleanup_count);

        // Cleanup TUN device
        drop(tun_device);
    }

    #[tokio::test]
    #[serial_test::serial(routing_table)]
    async fn test_find_server_route_with_added_routes() {
        let mut routing_table = RoutingTable::new(RouteMode::Default).unwrap();

        // Create a TUN device for testing
        let tun_name = "test_tun";
        let (tun_device, _) = match create_test_tun(tun_name, "10.47.0.1") {
            Ok((device, ip)) => (device, ip),
            Err(e) => {
                panic!("Cannot create TUN device: {}.", e);
            }
        };

        let tun_peer_ip = IpAddr::V4(Ipv4Addr::new(10, 47, 0, 5));

        // Create test routes and IP addresses for testing
        let route1 = Route::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1)
            .with_gateway(tun_peer_ip)
            .with_if_name(tun_name.to_string());
        let route2 = Route::new(IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1)
            .with_gateway(tun_peer_ip)
            .with_if_name(tun_name.to_string());

        // Test IP addresses that should route through our added routes
        let test_ip1 = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)); // Should match to route1 (0.0.0.0/1)
        let test_ip2 = IpAddr::V4(Ipv4Addr::new(200, 1, 1, 1)); // Should match to route2 (128.0.0.0/1)

        // Add routes (assuming add_route works based on previous test)
        let result1 = routing_table.add_route(&route1).await;
        match result1 {
            Ok(_) => {
                routing_table.route_store.push(route1.clone());
            }
            Err(e) => {
                drop(tun_device);
                match e {
                    RoutingTableError::AddRouteError(_) => {
                        panic!("Failed to add route error: {:?}", e);
                    }
                    RoutingTableError::InsufficientPermissions => {
                        panic!("WARNING: Cannot add routes due to insufficient permissions. Skipping find_server_route test.");
                    }
                    _ => {
                        panic!("Unexpected error type: {:?}", e);
                    }
                }
            }
        }
        
        // Test find_server_route for test_ip1
        let found_route1 = routing_table.find_route(&test_ip1);
        match found_route1 {
            Ok(found_route) => {
                assert_eq!(found_route.gateway(), route1.gateway(),
                          "find_server_route for test_ip1 did not return the expected gateway");
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
                routing_table.route_store.push(route2.clone());
            }
            Err(e) => {
                routing_table.cleanup().await;
                drop(tun_device);
                match e {
                    RoutingTableError::AddRouteError(_) => {
                        panic!("Failed to add second route error: {:?}", e);
                    }
                    RoutingTableError::InsufficientPermissions => {
                        panic!("WARNING: Cannot add second route due to insufficient permissions. Continuing with one route.");
                    }
                    _ => {
                        panic!("Unexpected error type: {:?}", e);
                    }
                }
            }
        }
        
        // Test find_server_route for test_ip1 after adding route2
        let found_route1 = routing_table.find_route(&test_ip1);
        match found_route1 {
            Ok(found_route) => {
                assert_eq!(found_route.gateway(), route1.gateway(),
                          "find_server_route for test_ip1 did not return the expected gateway after route2 was added");
            }
            Err(_) => {
                routing_table.cleanup().await;
                drop(tun_device);
                panic!("find_server_route for test_ip1 did not find the expected route after route2 was added");
            }
        }
        
        // Test find_server_route for test_ip2 (only if route2 was added)
        if routing_table.route_store.len() > 1 {
            let found_route2 = routing_table.find_route(&test_ip2);
            match found_route2 {
                Ok(found_route) => {
                    assert_eq!(found_route.gateway(), route2.gateway(),
                              "find_server_route for test_ip2 did not return the expected gateway");
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
    }

}
