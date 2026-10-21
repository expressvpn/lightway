use crate::wire::AuthSuccessWithConfigV4;
use std::net::{AddrParseError, Ipv4Addr};
use std::sync::Arc;

/// Network config for inside interface, sent to client after authentication
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct InsideIpConfig {
    /// IP address assigned by server to client
    pub client_ip: Ipv4Addr,
    /// Server IP address
    pub server_ip: Ipv4Addr,
    /// DNS server for client to use
    pub dns_ip: Ipv4Addr,
    /// Inside Tun MTU
    pub mtu: Option<u16>,
}

impl TryFrom<AuthSuccessWithConfigV4> for InsideIpConfig {
    type Error = AddrParseError;

    fn try_from(value: AuthSuccessWithConfigV4) -> Result<Self, Self::Error> {
        Ok(Self {
            client_ip: value.local_ip.parse()?,
            server_ip: value.peer_ip.parse()?,
            dns_ip: value.dns_ip.parse()?,
            mtu: value.mtu.parse().ok(),
        })
    }
}

/// Server Ip pool. Servers should have a pool of IPs to support
/// multiple clients.
pub trait ServerIpPool<AppState: Send = ()> {
    /// Allocate IP from free pool
    ///
    /// If the pool is exhausted, this method can return None.
    /// And Lightway core will disconnect the new client
    fn alloc(&self, state: &mut AppState) -> Option<InsideIpConfig>;

    /// Free IP back to pool
    fn free(&self, state: &mut AppState);
}

/// Convenience type to use as function arguments
pub type ServerIpPoolArg<AppState> = Arc<dyn ServerIpPool<AppState> + Sync + Send>;

/// Trait for client to handle [`InsideIpConfig`] from server
///
/// After successful authentication, `lightway_server` will assign one
/// unique IP to the client and sent this IP along with server and dns IP.
/// `lightway_core` then uses this trait to notify client about this inside ip config
pub trait ClientIpConfig<AppState: Send = ()> {
    /// Inside Ip config assigned by server
    fn ip_config(&self, state: &mut AppState, ip_config: InsideIpConfig);
}

/// Convenience type to use as function arguments
pub type ClientIpConfigArg<AppState> = Arc<dyn ClientIpConfig<AppState> + Sync + Send>;
