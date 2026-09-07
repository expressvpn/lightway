mod ip_pool;

use ipnet::Ipv4Net;
use lightway_core::{InsideIpConfig, ServerIpPool};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use tracing::info;

use crate::{
    connection::{Connection, ConnectionState},
    metrics,
};

use ip_pool::IpPool;

/// IpManager - Manages IP pool to assign to clients
/// Similar to DHCP server
///
/// Generic over T to make it testable
pub(crate) struct IpManager<T = Arc<Connection>> {
    inner: RwLock<IpManagerInner<T>>,
}

/// Inner struct to use for managing IP pool
struct IpManagerInner<T> {
    /// Client IP to lightway::Connection hashmap
    ip_to_conn_map: HashMap<Ipv4Addr, T>,
    /// Mapping of pool's for specific IPs
    ip_map: HashMap<IpAddr, IpPool>,
    /// IP pool
    ip_pool: IpPool,
    /// Static inside ip config which should be sent to clients in case of IP translation
    static_ip_config: InsideIpConfig,
    /// Use static IP or actual assigned IP address
    use_dynamic_client_ip: bool,
}

impl ServerIpPool<ConnectionState> for IpManager {
    fn alloc(&self, state: &mut ConnectionState) -> Option<InsideIpConfig> {
        // Recover weak handle to connection which we always set
        let conn = state.conn.get().unwrap();
        // Try to recover a strong handle, the connection may have gone away.
        let conn = conn.upgrade()?;

        // If this connection has already been allocated an IP then
        // return the corresponding config -- otherwise allocate a new
        // IP.
        match state.internal_ip {
            Some(ip) => Some(self.inside_ip_config(ip)),
            None => {
                let (allocation, config) = self.alloc(conn, state.local_addr.ip())?;

                state.internal_ip = Some(allocation);

                Some(config)
            }
        }
    }

    fn free(&self, state: &mut ConnectionState) {
        if let Some(ip) = state.internal_ip.take() {
            self.free(ip, state.local_addr.ip());
        }
    }
}

impl<T> IpManager<T> {
    pub(crate) fn new(
        ip_pool: Ipv4Net,
        ip_map: HashMap<IpAddr, Ipv4Net>,
        reserved_ips: impl IntoIterator<Item = Ipv4Addr>,
        static_ip_config: InsideIpConfig,
        use_dynamic_client_ip: bool,
        randomize_ippool: bool,
    ) -> Self {
        let mut ip_pool = IpPool::new(ip_pool, reserved_ips);
        if randomize_ippool {
            ip_pool.shuffle_ips();
        } else {
            tracing::warn!("IpPool not randomized");
        }

        let ip_map = ip_map
            .into_iter()
            .map(|(ip, subnet)| (ip, ip_pool.split_subnet(subnet)))
            .collect();

        IpManager {
            inner: RwLock::new(IpManagerInner {
                ip_to_conn_map: HashMap::new(),
                ip_map,
                ip_pool,
                static_ip_config,
                use_dynamic_client_ip,
            }),
        }
    }

    pub(crate) fn allocated_ips_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.ip_to_conn_map.len()
    }

    fn inside_ip_config(&self, ip: Ipv4Addr) -> InsideIpConfig {
        let inner = self.inner.read().unwrap();
        inner.config_for_ip(ip)
    }

    fn alloc(&self, conn: T, local_ip: IpAddr) -> Option<(Ipv4Addr, InsideIpConfig)> {
        let mut inner = self.inner.write().unwrap();

        let IpManagerInner {
            ip_map, ip_pool, ..
        } = &mut *inner;

        let ip_pool = ip_map.get_mut(&local_ip).unwrap_or(ip_pool);

        let Some(ip) = ip_pool.allocate_ip() else {
            metrics::connection_rejected_no_free_ip();
            return None;
        };

        info!(ip = ?ip, "Alloc");

        inner.ip_to_conn_map.insert(ip, conn);

        let config = inner.config_for_ip(ip);

        Some((ip, config))
    }

    fn free(&self, ip: Ipv4Addr, local_ip: IpAddr) {
        let mut inner = self.inner.write().unwrap();

        let IpManagerInner {
            ip_map, ip_pool, ..
        } = &mut *inner;

        let ip_pool = ip_map.get_mut(&local_ip).unwrap_or(ip_pool);

        info!(ip = ?ip, "Free");

        ip_pool.free_ip(ip);
        inner.ip_to_conn_map.remove(&ip);
    }
}

impl<T: Clone> IpManager<T> {
    pub(crate) fn find_connection(&self, ip: Ipv4Addr) -> Option<T> {
        let inner = self.inner.read().unwrap();
        inner.ip_to_conn_map.get(&ip).cloned()
    }
}

impl<T> IpManagerInner<T> {
    fn config_for_ip(&self, client_ip: Ipv4Addr) -> InsideIpConfig {
        let client_ip = if self.use_dynamic_client_ip {
            client_ip
        } else {
            self.static_ip_config.client_ip
        };
        InsideIpConfig {
            client_ip,
            ..self.static_ip_config
        }
    }
}

#[cfg(test)]
mod tests {
    use ipnet::Ipv4Net;
    use std::sync::Arc;

    use super::*;

    #[derive(PartialEq, Debug, Clone)]
    struct DummyConnection;

    fn get_static_ip_config() -> InsideIpConfig {
        InsideIpConfig {
            client_ip: "10.125.0.5".parse().unwrap(),
            server_ip: "10.125.0.6".parse().unwrap(),
            dns_ip: "10.125.0.1".parse().unwrap(),
        }
    }

    #[derive(PartialEq, Debug, Clone)]
    struct TestConnection(Arc<usize>);

    impl TestConnection {
        fn new(n: usize) -> Self {
            Self(Arc::new(n))
        }
    }

    fn get_ip_manager(use_dynamic_client_ip: bool) -> IpManager<TestConnection> {
        let ip_pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip: Ipv4Addr = "10.125.0.1".parse().unwrap();
        let dns_ip: Ipv4Addr = "10.125.0.2".parse().unwrap();
        IpManager::new(
            ip_pool,
            [(
                "192.168.85.208".parse().unwrap(),
                "10.125.2.0/28".parse().unwrap(),
            )]
            .into(),
            [local_ip, dns_ip],
            get_static_ip_config(),
            use_dynamic_client_ip,
            true,
        )
    }

    fn get_ip_manager_with_test_connection() -> IpManager<TestConnection> {
        get_ip_manager(false)
    }

    fn get_ip_manager_using_dynamic_client_ip() -> IpManager<TestConnection> {
        get_ip_manager(true)
    }

    #[test]
    fn alloc_ip_from_global() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);
        let subnet: Ipv4Net = "10.125.2.0/28".parse().unwrap();

        let (local_ip1, ip_config) = ip_manager
            .alloc(conn1, "192.168.23.54".parse().unwrap())
            .unwrap();
        assert!(!subnet.contains(&local_ip1));
        assert_eq!(
            ip_config,
            get_static_ip_config(),
            "IP config should match static config"
        );

        let (local_ip2, ip_config) = ip_manager
            .alloc(conn2, "192.168.125.13".parse().unwrap())
            .unwrap();
        assert!(!subnet.contains(&local_ip2));
        assert_eq!(
            ip_config,
            get_static_ip_config(),
            "IP config should match static config"
        );

        let inner = ip_manager.inner.read().unwrap();

        assert!(inner.ip_to_conn_map.contains_key(&local_ip1));
        assert!(inner.ip_to_conn_map.contains_key(&local_ip2));
        assert_eq!(inner.ip_to_conn_map.len(), 2);
    }

    #[test]
    fn alloc_ip_using_dynamic_client_ip() {
        let ip_manager = get_ip_manager_using_dynamic_client_ip();
        let conn1 = TestConnection::new(1);
        let subnet: Ipv4Net = "10.125.2.0/28".parse().unwrap();

        let (local_ip1, ip_config) = ip_manager
            .alloc(conn1, "192.168.23.54".parse().unwrap())
            .unwrap();
        assert!(!subnet.contains(&local_ip1));
        assert_eq!(
            local_ip1, ip_config.client_ip,
            "Client IP config should be the actual assigned dynamic ip"
        );
    }

    #[test]
    fn alloc_ip_from_subrange() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);
        let subnet: Ipv4Net = "10.125.2.0/28".parse().unwrap();

        let (local_ip1, ip_config) = ip_manager
            .alloc(conn1, "192.168.85.208".parse().unwrap())
            .unwrap();
        assert!(subnet.contains(&local_ip1));
        assert_eq!(
            ip_config,
            get_static_ip_config(),
            "IP config should match static config"
        );

        let (local_ip2, ip_config) = ip_manager
            .alloc(conn2, "192.168.85.208".parse().unwrap())
            .unwrap();
        assert!(subnet.contains(&local_ip2));
        assert_eq!(
            ip_config,
            get_static_ip_config(),
            "IP config should match static config"
        );

        let inner = ip_manager.inner.read().unwrap();

        assert!(inner.ip_to_conn_map.contains_key(&local_ip1));
        assert!(inner.ip_to_conn_map.contains_key(&local_ip2));
        assert_eq!(inner.ip_to_conn_map.len(), 2);
    }

    #[test]
    fn free_ip_from_global() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);
        let ip1 = "192.168.24.64".parse().unwrap();
        let ip2 = "192.168.11.45".parse().unwrap();

        let (alloc1, _) = ip_manager.alloc(conn1.clone(), ip1).unwrap();
        let (alloc2, _) = ip_manager.alloc(conn2.clone(), ip2).unwrap();

        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 2);
        }

        ip_manager.free(alloc1, ip1);
        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 1);
        }

        ip_manager.free(alloc2, ip2);
        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 0);
        }
    }

    #[test]
    fn free_ip_from_subrange() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);
        let ip = "192.168.85.208".parse().unwrap();

        let (alloc1, _) = ip_manager.alloc(conn1.clone(), ip).unwrap();
        let (alloc2, _) = ip_manager.alloc(conn2.clone(), ip).unwrap();

        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 2);
        }

        ip_manager.free(alloc1, ip);
        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 1);
        }

        ip_manager.free(alloc2, ip);
        {
            let inner = ip_manager.inner.read().unwrap();
            assert_eq!(inner.ip_to_conn_map.len(), 0);
        }
    }

    #[test]
    fn find_ip() {
        let ip_manager = get_ip_manager_with_test_connection();
        let conn1 = TestConnection::new(1);
        let conn2 = TestConnection::new(2);
        let ip1 = "192.168.190.7".parse().unwrap();
        let ip2 = "192.168.187.186".parse().unwrap();

        let (ip1, _) = ip_manager.alloc(conn1.clone(), ip1).unwrap();
        let (ip2, _) = ip_manager.alloc(conn2.clone(), ip2).unwrap();

        // Getting ip1 and verify
        let conn = ip_manager.find_connection(ip1).unwrap();
        assert_eq!(*conn.0, 1);
        assert!(Arc::ptr_eq(&conn.0, &conn1.0));
        assert!(!Arc::ptr_eq(&conn.0, &conn2.0));

        // Getting ip2 and verify
        let conn = ip_manager.find_connection(ip2).unwrap();
        assert_eq!(*conn.0, 2);
        assert!(Arc::ptr_eq(&conn.0, &conn2.0));
        assert!(!Arc::ptr_eq(&conn.0, &conn1.0));
    }

    #[test]
    fn reserved_ips_never_allocated() {
        let ip_pool: Ipv4Net = "10.125.0.0/24".parse().unwrap();
        let local_ip: Ipv4Addr = "10.125.0.1".parse().unwrap();
        let dns_ip: Ipv4Addr = "10.125.0.2".parse().unwrap();
        let reserved_ip1: Ipv4Addr = "10.125.0.34".parse().unwrap();
        let reserved_ip2: Ipv4Addr = "10.125.0.220".parse().unwrap();
        let conn_local_ip: IpAddr = "192.168.81.115".parse().unwrap();

        let ip_manager = IpManager::new(
            ip_pool,
            Default::default(),
            [local_ip, dns_ip, reserved_ip1, reserved_ip2],
            get_static_ip_config(),
            false,
            true,
        );
        // Allocate every possible IP and check we never get a reserved one
        let mut count = 0;
        while let Some((ip, _)) = ip_manager.alloc(DummyConnection, conn_local_ip) {
            count += 1;
            assert_ne!(ip, local_ip);
            assert_ne!(ip, dns_ip);
            assert_ne!(ip, reserved_ip1);
            assert_ne!(ip, reserved_ip2);
        }

        let total_hosts = ip_pool.hosts().count();
        assert_eq!(count, total_hosts - 4); // 4 == local + dns + 2x reserved
    }
}
