use ipnet::Ipv4Net;
use std::{
    collections::{HashSet, VecDeque},
    net::Ipv4Addr,
};
use tracing::warn;

/// Manages the alloction of a pool of IPs
pub struct IpPool {
    /// Reserved IPs, must never be allocated to a client.
    reserved_ips: HashSet<Ipv4Addr>,
    /// Allocated IPs,
    allocated_ips: HashSet<Ipv4Addr>,
    /// Queue to store IPs which are currently unused (a queue for LRU uses)
    available_ips: VecDeque<Ipv4Addr>,
}

impl IpPool {
    pub fn new(ip_pool: Ipv4Net, reserved_ips: impl IntoIterator<Item = Ipv4Addr>) -> Self {
        let reserved_ips = HashSet::from_iter(
            reserved_ips
                .into_iter()
                .chain(std::iter::once(ip_pool.network()))
                .chain(std::iter::once(ip_pool.broadcast())),
        );

        let available_ips: VecDeque<_> = ip_pool
            .hosts()
            .filter(|ip| !reserved_ips.contains(ip))
            .collect();

        Self {
            reserved_ips,
            allocated_ips: Default::default(),
            available_ips,
        }
    }

    // Shuffle available IPs and make it harder to guess IPs
    pub fn shuffle_ips(&mut self) {
        use rand::prelude::*;
        self.available_ips
            .make_contiguous()
            .shuffle(&mut rand::rng());
    }

    pub fn allocate_ip(&mut self) -> Option<Ipv4Addr> {
        let ip = self.available_ips.pop_front()?;
        self.allocated_ips.insert(ip);
        Some(ip)
    }

    pub fn free_ip(&mut self, ip: Ipv4Addr) {
        if !self.allocated_ips.remove(&ip) {
            warn!(ip = ?ip, "Attempt to free unallocated IP address");
            return;
        }

        self.available_ips.push_back(ip);
    }

    pub fn split_subnet(&mut self, subnet: Ipv4Net) -> Self {
        let available_ips: VecDeque<_> = self
            .available_ips
            .iter()
            .copied()
            .filter(|ip| subnet.contains(ip))
            .collect();
        self.available_ips.retain(|ip| !available_ips.contains(ip));

        // copy any relevant reserved IPs
        let reserved_ips = self
            .reserved_ips
            .iter()
            .copied()
            .filter(|ip| subnet.contains(ip))
            .collect();
        Self {
            reserved_ips,
            allocated_ips: Default::default(),
            available_ips,
        }
    }
}

// Tests START -> panic, unwrap, expect allowed
#[cfg(test)]
mod tests {
    use super::*;

    use more_asserts::*;
    use rand::prelude::*;
    use test_case::test_case;

    fn get_ip_pool() -> IpPool {
        let ip_pool: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip: Ipv4Addr = "10.125.0.1".parse().unwrap();
        let dns_ip: Ipv4Addr = "10.125.0.2".parse().unwrap();
        IpPool::new(ip_pool, [local_ip, dns_ip])
    }

    #[test_case("10.125.0.1", "10.125.0.1", 1; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.2", 2; "Different Local and DNS IP")]
    fn used_ips_check(local_ip: &str, dns_ip: &str, expected_len: usize) {
        let ip_range: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip = local_ip.parse().unwrap();
        let dns_ip = dns_ip.parse().unwrap();
        let pool = IpPool::new(ip_range, [local_ip, dns_ip]);

        assert_eq!(
            pool.available_ips.len(),
            ip_range.hosts().count() - expected_len
        );
        assert!(pool.reserved_ips.contains(&local_ip));
        assert!(pool.reserved_ips.contains(&dns_ip));
    }

    #[test_case("10.125.0.1", "10.125.0.1"; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.3"; "Different Local and DNS IP")]
    fn alloc_ip(local_ip: &str, dns_ip: &str) {
        let ip_range: Ipv4Net = "10.125.0.0/16".parse().unwrap();
        let local_ip = local_ip.parse().unwrap();
        let dns_ip = dns_ip.parse().unwrap();
        let mut pool = IpPool::new(ip_range, [local_ip, dns_ip]);

        // Allocate IP
        let new_ip = pool.allocate_ip().unwrap();
        assert!(ip_range.contains(&new_ip));
        assert_ne!(new_ip, local_ip);
        assert_ne!(new_ip, dns_ip);
    }

    #[test_case("10.125.0.1", "10.125.0.1", 253; "Same Local and DNS IP")]
    #[test_case("10.125.0.1", "10.125.0.3", 252; "Different Local and DNS IP")]
    #[test_case("10.125.0.1", "8.8.8.8", 253; "Different Local and DNS IP. DNS ip in different subnet")]
    fn alloc_ip_exhaust(local_ip: &str, dns_ip: &str, available_ips: usize) {
        let ip_range: Ipv4Net = "10.125.0.0/24".parse().unwrap();
        let local_ip: Ipv4Addr = local_ip.parse().unwrap();
        let dns_ip: Ipv4Addr = dns_ip.parse().unwrap();
        let mut pool = IpPool::new(ip_range, [local_ip, dns_ip]);

        for _ in 1..=available_ips {
            let _ = pool.allocate_ip().unwrap();
        }

        assert_eq!(pool.allocate_ip(), None);
    }

    #[test_case(2, 2; "Free all allocated")]
    #[test_case(3, 2; "Free fewer than allocated")]
    fn free_ip(alloc_times: usize, free_times: usize) {
        let mut pool = get_ip_pool();
        let pool_size = 65536 - 2; // A /16 less network and broadcast addresses
        let reserved_ip_count: usize = 2;

        let mut alloced_ips = Vec::new();
        // Allocate IP
        for _ in 1..=alloc_times {
            let new_ip = pool.allocate_ip().unwrap();
            alloced_ips.push(new_ip);
        }

        assert_eq!(
            pool.available_ips.len(),
            pool_size - alloc_times - reserved_ip_count
        );

        // Free IP
        for _ in 1..=free_times {
            let remove_ip = alloced_ips.pop().unwrap();
            pool.free_ip(remove_ip);
        }

        assert_eq!(
            pool.available_ips.len(),
            pool_size - reserved_ip_count - alloc_times + free_times
        );
    }

    #[test_case("10.125.0.1"; "Free local ip")]
    #[test_case("10.125.0.2"; "Free dns ip")]
    #[test_case("10.125.0.9"; "Free unallocated ip")]
    #[test_case("192.168.1.1"; "Free unrelated ip")]
    fn free_reserved_or_unallocated_ip(ip: &str) {
        let mut pool = get_ip_pool();
        let pool_size = 65536 - 2 - 2; // A /16 less network and broadcast addresses and two reserved addresses

        assert_eq!(pool.available_ips.len(), pool_size);
        pool.free_ip(ip.parse().unwrap());
        assert_eq!(pool.available_ips.len(), pool_size);
    }

    #[test]
    fn split_subnet_initial_range_omits_network_and_reserved_addresses() {
        let mut pool = get_ip_pool();
        let subpool = pool.split_subnet("10.125.0.0/29".parse().unwrap());

        assert_eq!(subpool.available_ips.len(), 5);
        let available_ips: HashSet<_> = subpool.available_ips.into_iter().collect();
        assert_eq!(
            available_ips,
            [
                // .0 is the network address, .1 and .2 are reserved.
                "10.125.0.3".parse().unwrap(),
                "10.125.0.4".parse().unwrap(),
                "10.125.0.5".parse().unwrap(),
                "10.125.0.6".parse().unwrap(),
                "10.125.0.7".parse().unwrap(),
            ]
            .into()
        );
        assert_eq!(
            subpool.reserved_ips,
            [
                "10.125.0.0".parse().unwrap(),
                "10.125.0.1".parse().unwrap(),
                "10.125.0.2".parse().unwrap(),
            ]
            .into()
        );
    }

    #[test]
    fn split_subnet_mid_range_includes_full_subrange() {
        let mut pool = get_ip_pool();
        let subpool = pool.split_subnet("10.125.138.96/29".parse().unwrap());

        assert_eq!(subpool.available_ips.len(), 8);
        let available_ips: HashSet<_> = subpool.available_ips.into_iter().collect();
        assert_eq!(
            available_ips,
            [
                "10.125.138.96".parse().unwrap(),
                "10.125.138.97".parse().unwrap(),
                "10.125.138.98".parse().unwrap(),
                "10.125.138.99".parse().unwrap(),
                "10.125.138.100".parse().unwrap(),
                "10.125.138.101".parse().unwrap(),
                "10.125.138.102".parse().unwrap(),
                "10.125.138.103".parse().unwrap(),
            ]
            .into()
        );
        assert!(subpool.reserved_ips.is_empty());
    }

    #[test]
    fn split_subnet_final_range_omits_broadcast_address() {
        let mut pool = get_ip_pool();
        let subpool = pool.split_subnet("10.125.255.248/29".parse().unwrap());

        assert_eq!(subpool.available_ips.len(), 7);
        let available_ips: HashSet<_> = subpool.available_ips.into_iter().collect();
        assert_eq!(
            available_ips,
            [
                "10.125.255.248".parse().unwrap(),
                "10.125.255.249".parse().unwrap(),
                "10.125.255.250".parse().unwrap(),
                "10.125.255.251".parse().unwrap(),
                "10.125.255.252".parse().unwrap(),
                "10.125.255.253".parse().unwrap(),
                "10.125.255.254".parse().unwrap(),
                // .255 is the broadcast address
            ]
            .into()
        );
        assert_eq!(
            subpool.reserved_ips,
            ["10.125.255.255".parse().unwrap(),].into()
        );
    }

    #[test_case("10.125.0.0/29", 5, "10.125.0.0")]
    #[test_case("10.125.0.0/29", 5, "10.125.0.1")]
    #[test_case("10.125.0.0/29", 5, "10.125.0.2")]
    #[test_case("10.125.0.0/29", 5, "10.125.0.16")] // outside range
    #[test_case("10.125.29.192/29", 8, "10.125.0.2")] // outside range
    #[test_case("10.125.255.248/29", 7, "10.125.255.247")] // outside range
    #[test_case("10.125.255.248/29", 7, "10.125.255.255")]
    fn split_subnet_free_reserved_ips(subnet: &str, pool_size: usize, ip: &str) {
        let mut pool = get_ip_pool();
        let subpool = pool.split_subnet(subnet.parse().unwrap());

        assert_eq!(subpool.available_ips.len(), pool_size);
        pool.free_ip(ip.parse().unwrap());
        assert_eq!(subpool.available_ips.len(), pool_size);
    }

    #[test_case("10.125.0.0/29", 5)]
    #[test_case("10.125.98.192/29", 8)]
    #[test_case("10.125.255.248/29", 7)]
    fn split_subnet_alloc_all_then_free_all(subnet: &str, pool_size: usize) {
        let mut pool = get_ip_pool();
        let mut subpool = pool.split_subnet(subnet.parse().unwrap());

        assert_eq!(subpool.available_ips.len(), pool_size);

        let ips: Vec<_> = (1..=pool_size)
            .map(|_| subpool.allocate_ip().unwrap())
            .collect();

        assert!(subpool.allocate_ip().is_none());
        assert_eq!(subpool.available_ips.len(), 0);

        ips.into_iter().for_each(|ip| subpool.free_ip(ip));

        assert_eq!(subpool.available_ips.len(), pool_size);
    }

    #[test]
    fn lru_behaviour() {
        let mut pool = get_ip_pool();
        let pool_size = pool.available_ips.len();

        // Allocate and then free an IP
        let ip = pool.allocate_ip().unwrap();
        pool.free_ip(ip);

        // We should now be able to allocate N-1 other IPs and not get
        // that initial IP back again.
        let mut other_ips: Vec<_> = (0..pool_size - 1)
            .map(|_| {
                let other_ip = pool.allocate_ip().unwrap();
                assert_ne!(ip, other_ip);
                other_ip
            })
            .collect();

        assert_eq!(other_ips.len(), pool_size - 1);

        // Only the initial IP is left
        assert_eq!(pool.available_ips.len(), 1);
        let same_ip = pool.allocate_ip().unwrap();
        assert_eq!(ip, same_ip);

        // Nothing left
        assert!(pool.allocate_ip().is_none());

        // Now free all the other IPs in a random order
        other_ips.shuffle(&mut rand::rng());
        for other_ip in other_ips.iter() {
            pool.free_ip(*other_ip)
        }
        // and we should get them back in that order
        for other_ip in other_ips.into_iter() {
            let ip = pool.allocate_ip().unwrap();
            assert_eq!(ip, other_ip);
        }
    }

    #[test]
    fn test_no_shuffle() {
        // 10.125.0.1 is used for local ip
        // 10.125.0.2 is used for dns ip
        let exp_ip1: Ipv4Addr = "10.125.0.3".parse().unwrap();
        let exp_ip2: Ipv4Addr = "10.125.0.4".parse().unwrap();
        let mut pool = get_ip_pool();

        let new_ip = pool.allocate_ip().unwrap();
        assert_eq!(new_ip, exp_ip1);
        let new_ip = pool.allocate_ip().unwrap();
        assert_eq!(new_ip, exp_ip2);
    }

    #[test]
    fn test_shuffle() {
        let mut pool = get_ip_pool();
        pool.shuffle_ips();

        // An imperfect test of randomness. This is sufficient to
        // catch an obvious mistake such as allocating in order.
        //
        // The average delta between two consecutive allocations from
        // a non-sequential list should be a non-small number.
        //
        // If the list were sorted then the average would be 1.
        //
        // Given the 2^16 entry IP pool here the average delta in
        // practice is 21-22,000 (about 1/3 of the pool size). The
        // chances of this coming out as less than 512 in practice are
        // miniscule.
        let mut previous = pool.allocate_ip().unwrap().to_bits();
        let (count, total_differences) = std::iter::from_fn(|| {
            let ip = pool.allocate_ip()?.to_bits();

            let delta = ip.abs_diff(previous);
            previous = ip;
            Some(delta as f64)
        })
        .fold((0, 0.0f64), |(mut count, mut total_differences), v| {
            count += 1;
            total_differences += v;
            (count, total_differences)
        });
        assert_gt!(total_differences / count as f64, 512.0);
    }
}

// Tests END -> panic, unwrap, expect allowed
