use anyhow::{Context, Result};
use route_manager::{AsyncRouteManager, Route, RouteManager};
use std::net::{IpAddr, Ipv4Addr};
use thiserror::Error;
use tracing::warn;

#[derive(PartialEq)]
pub enum RoutingMode {
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
    #[error("Failed to Delete Route {0}")]
    DeleteRouteError(std::io::Error),
    #[error("RoutingManager error {0}")]
    RoutingManagerError(std::io::Error),
    #[error("Tun interface not found")]
    TunInterfaceNotFound,
    #[error("Interface name not found")]
    InterfaceNameNotFound,
    #[error("Interface gateway not found")]
    InterfaceGatewayNotFound,
}

pub struct RoutingTable {
    routing_mode: RoutingMode,
    route_manager: RouteManager,
    route_manager_async: AsyncRouteManager,
    route_store: Vec<Route>,
    server_route: Option<Route>,
}

impl RoutingTable {
    pub fn new(routing_mode: RoutingMode) -> Result<Self, RoutingTableError> {
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
    }

    /// Identifies server route by finding the route to be used to access server_ip
    fn find_server_route(&mut self, server_ip: &IpAddr) -> Result<Route, RoutingTableError> {
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
        let default_route = self.find_server_route(server_ip)?;
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
        Ok(self
            .route_manager_async
            .add(route)
            .await
            .map_err(|e| RoutingTableError::AddRouteError(e))?)
    }

    async fn initialize_routing_table(
        &mut self,
        server_ip: &IpAddr,
        tun_name: &str,
        tun_local_ip: &IpAddr,
        tun_peer_ip: &IpAddr,
        tun_dns_ip: &IpAddr,
    ) -> Result<()> {
        if self.routing_mode == RoutingMode::NoExec {
            return Ok(());
        }

        // Setting up VPN Server Routes
        let (default_interface_name, default_interface_gateway) =
            self.find_default_interface_name_and_gateway(server_ip)?;

        let server_route = Route::new(*server_ip, 32)
            .with_gateway(default_interface_gateway)
            .with_if_name(default_interface_name);

        self.add_route(&server_route)
            .await
            .context("Adding VPN Server IP Route")?;
        self.server_route = Some(server_route);

        if self.routing_mode == RoutingMode::Lan {
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

        self.add_route(&default_route_0)
            .await
            .context("Adding First Default Route")?;
        self.add_route(&default_route_1)
            .await
            .context("Adding Second Default Route")?;
        self.add_route(&dns_route)
            .await
            .context("Adding Tun DNS IP Route")?;
        self.route_store.push(default_route_0);
        self.route_store.push(default_route_1);
        self.route_store.push(dns_route);
        Ok(())
    }
}
#[cfg(test)]
mod test {
    fn test_cleanup() {
        // Create, then delete, then compare begin and end
    }
}
