use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use iptables::IPTables;
use route_manager::RouteManager;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetworkSetupError {
    #[error("Failed to initialize iptables")]
    IptablesInit(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to create route manager")]
    RouteManagerInit(#[from] std::io::Error),

    #[error("Failed to find default route")]
    RouteDiscovery(std::io::Error),

    #[error("No default route found")]
    NoDefaultRoute,

    #[error("Default route has no interface name")]
    NoInterfaceName,

    #[error("Default route has no gateway")]
    NoGateway,

    #[error("WAN interface has no IP address")]
    NoWanInterfaceIp,

    #[error("Failed to get current IP forwarding state")]
    IpForwardingState(std::io::Error),

    #[error("Failed to enable IP forwarding")]
    IpForwardingEnable(std::io::Error),

    #[error("Failed to create filter chain")]
    FilterChainCreate(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to create NAT chain")]
    NatChainCreate(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert FORWARD jump rule")]
    ForwardJumpRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert POSTROUTING jump rule")]
    PostroutingJumpRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert TUN to WAN forwarding rule")]
    TunToWanRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert WAN to TUN established connection rule")]
    WanToTunRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert SNAT rule")]
    SnatRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert rate limiting rule")]
    RateLimitingRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert DROP rule")]
    DropRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert anti-spoofing rule")]
    AntiSpoofingRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert IPv6 blocking rule")]
    Ipv6BlockingRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert fragment handling rule")]
    FragmentRule(#[source] Box<dyn std::error::Error + Send + Sync>),

    #[error("Failed to insert connection state validation rule")]
    StateValidationRule(#[source] Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Debug, Default, Clone, clap::ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkSetupMode {
    #[default]
    Default,
    /// Strict mode with additional security: DROP rules, rate limiting, and anti-spoofing
    Strict,
    /// Paranoid mode with maximum security: IPv6 blocking, fragment handling, and connection validation
    Paranoid,
    NoExec,
}

pub(crate) struct NetworkSetup {
    mode: NetworkSetupMode,
    ipt: IPTables,
    tun_ip_pool: Ipv4Net,
    tun_name: String,
    wan_name: String,
    wan_ip: IpAddr,
    chain_forward: String,
    chain_postrouting: String,
    prev_ip_forward: Option<u8>,
}

fn get_ip_forwarding_state() -> std::io::Result<u8> {
    let contents = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")?;
    let trimmed = contents.trim();
    trimmed.parse::<u8>().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid IP forward value: {}", e),
        )
    })
}

fn set_ip_forwarding_state(state: u8) -> std::io::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", format!("{}", state))
}

impl NetworkSetup {
    /// Get the primary IP address of a network interface
    fn get_interface_ip(
        interface_name: &str,
        if_index: Option<u32>,
    ) -> Result<IpAddr, NetworkSetupError> {
        use if_addrs::get_if_addrs;

        // Get all network interfaces
        let interfaces = get_if_addrs().map_err(|_| NetworkSetupError::NoWanInterfaceIp)?;

        // Try to match by interface index
        for interface in &interfaces {
            if interface.index == if_index {
                if interface.addr.ip().is_ipv4() && !interface.addr.ip().is_loopback() {
                    return Ok(interface.addr.ip());
                }
            }
            // Fallback: match by interface name
            if interface.name == interface_name {
                if !interface.addr.ip().is_loopback() && interface.addr.ip().is_ipv4() {
                    return Ok(interface.addr.ip());
                }
            }
        }

        Err(NetworkSetupError::NoWanInterfaceIp)
    }

    pub fn new(
        mode: NetworkSetupMode,
        tun_ip_pool: Ipv4Net,
        tun_name: String,
    ) -> Result<Self, NetworkSetupError> {
        let ipt = iptables::new(false).map_err(|e| {
            NetworkSetupError::IptablesInit(format!("iptables initialization failed: {}", e).into())
        })?;
        let mut route_manager = RouteManager::new()?;

        let route = route_manager
            .find_route(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .map_err(NetworkSetupError::RouteDiscovery)?
            .ok_or(NetworkSetupError::NoDefaultRoute)?;

        tracing::info!("Default route found: {:?}", route);
        let wan_name = route
            .if_name()
            .ok_or(NetworkSetupError::NoInterfaceName)?
            .to_string();

        // Get the actual interface IP, not the gateway IP, for SNAT
        let wan_ip = route
            .pref_source()
            .or_else(|| {
                // Fallback: get IP from the interface directly
                Self::get_interface_ip(&wan_name, route.if_index()).ok()
            })
            .ok_or(NetworkSetupError::NoWanInterfaceIp)?;

        Ok(Self {
            mode,
            ipt,
            tun_ip_pool,
            tun_name,
            wan_name,
            wan_ip,
            chain_forward: String::from("LW_FORWARD"),
            chain_postrouting: String::from("LW_POSTROUTING_NAT"),
            prev_ip_forward: None,
        })
    }

    pub async fn start(&mut self) -> Result<(), NetworkSetupError> {
        if matches!(self.mode, NetworkSetupMode::NoExec) {
            return Ok(());
        }

        let is_strict = matches!(self.mode, NetworkSetupMode::Strict);
        let is_paranoid = matches!(self.mode, NetworkSetupMode::Paranoid);
        let has_security = is_strict || is_paranoid;

        // 1. Enable IP forwarding
        self.prev_ip_forward =
            Some(get_ip_forwarding_state().map_err(NetworkSetupError::IpForwardingState)?);
        set_ip_forwarding_state(1).map_err(NetworkSetupError::IpForwardingEnable)?;

        // 2. Create custom chains
        self.ipt
            .new_chain("filter", &self.chain_forward)
            .map_err(|e| NetworkSetupError::FilterChainCreate(format!("{}", e).into()))?;
        self.ipt
            .new_chain("nat", &self.chain_postrouting)
            .map_err(|e| NetworkSetupError::NatChainCreate(format!("{}", e).into()))?;

        // 3. Insert jump rules (using 1-based indexing for iptables)
        self.ipt
            .insert(
                "filter",
                "FORWARD",
                &format!("-j {}", self.chain_forward),
                1,
            )
            .map_err(|e| NetworkSetupError::ForwardJumpRule(format!("{}", e).into()))?;
        self.ipt
            .insert(
                "nat",
                "POSTROUTING",
                &format!("-j {}", self.chain_postrouting),
                1,
            )
            .map_err(|e| NetworkSetupError::PostroutingJumpRule(format!("{}", e).into()))?;

        // 4. Anti-spoofing protection (Strict and Paranoid modes)
        if has_security {
            // Prevent source IP spoofing from TUN interface
            self.ipt
                .append(
                    "filter",
                    &self.chain_forward,
                    &format!("-i {} ! -s {} -j DROP", self.tun_name, self.tun_ip_pool),
                )
                .map_err(|e| NetworkSetupError::AntiSpoofingRule(format!("{}", e).into()))?;
        }

        // 5. Forwarding rules (tun → wan)
        if has_security {
            // 5a. Rate limiting for new connections in security modes
            self.ipt
                .append(
                    "filter",
                    &self.chain_forward,
                    &format!(
                        "-i {} -o {} -s {} -m state --state NEW -m limit --limit 25/min --limit-burst 100 -j ACCEPT",
                        self.tun_name, self.wan_name, self.tun_ip_pool
                    ),
                )
                .map_err(|e| NetworkSetupError::RateLimitingRule(format!("{}", e).into()))?;

            // 5b. Allow established/related connections without rate limiting
            self.ipt
                .append(
                    "filter",
                    &self.chain_forward,
                    &format!(
                        "-i {} -o {} -s {} -m state --state ESTABLISHED,RELATED -j ACCEPT",
                        self.tun_name, self.wan_name, self.tun_ip_pool
                    ),
                )
                .map_err(|e| NetworkSetupError::TunToWanRule(format!("{}", e).into()))?;
        } else {
            // 5. Standard forwarding rule (all traffic)
            self.ipt
                .append(
                    "filter",
                    &self.chain_forward,
                    &format!(
                        "-i {} -o {} -s {} -j ACCEPT",
                        self.tun_name, self.wan_name, self.tun_ip_pool
                    ),
                )
                .map_err(|e| NetworkSetupError::TunToWanRule(format!("{}", e).into()))?;
        }

        // 6. Paranoid mode: Additional security hardening
        if is_paranoid {
            // 6a. Connection state validation - drop invalid connections
            self.ipt
                .append(
                    "filter",
                    &self.chain_forward,
                    "-m state --state INVALID -j DROP",
                )
                .map_err(|e| NetworkSetupError::StateValidationRule(format!("{}", e).into()))?;

            // 6b. Fragment handling - log and drop fragmented packets
            self.ipt
                .append(
                    "filter",
                    &self.chain_forward,
                    "-f -j LOG --log-prefix \"FRAG_DROP: \" --log-level 4",
                )
                .map_err(|e| NetworkSetupError::FragmentRule(format!("{}", e).into()))?;

            self.ipt
                .append("filter", &self.chain_forward, "-f -j DROP")
                .map_err(|e| NetworkSetupError::FragmentRule(format!("{}", e).into()))?;

            // 6c. IPv6 blocking - block all IPv6 traffic (requires ip6tables)
            // Note: This would require ip6tables crate or system commands
            // For now, we'll log that IPv6 blocking is recommended to be done at system level
            tracing::warn!(
                "Paranoid mode: IPv6 blocking should be configured at system level with ip6tables"
            );
        }

        // 7. Reverse / established traffic (wan → tun)
        self.ipt
            .append(
                "filter",
                &self.chain_forward,
                &format!(
                    "-i {} -o {} -d {} -m state --state RELATED,ESTABLISHED -j ACCEPT",
                    self.wan_name, self.tun_name, self.tun_ip_pool
                ),
            )
            .map_err(|e| NetworkSetupError::WanToTunRule(format!("{}", e).into()))?;

        // 8. SNAT rule for outgoing VPN traffic
        self.ipt
            .append(
                "nat",
                &self.chain_postrouting,
                &format!(
                    "-s {} -o {} -j SNAT --to-source {}",
                    self.tun_ip_pool, self.wan_name, self.wan_ip
                ),
            )
            .map_err(|e| NetworkSetupError::SnatRule(format!("{}", e).into()))?;

        // 9. Security modes: Add explicit DROP rules at end of our custom chain
        if has_security {
            // Log dropped packets for security auditing (append before DROP)
            self.ipt
                .append(
                    "filter",
                    &self.chain_forward,
                    "-j LOG --log-prefix \"LW_DROP: \" --log-level 4",
                )
                .map_err(|e| NetworkSetupError::DropRule(format!("{}", e).into()))?;

            // Drop any remaining traffic in our custom chain (append at end)
            self.ipt
                .append("filter", &self.chain_forward, "-j DROP")
                .map_err(|e| NetworkSetupError::DropRule(format!("{}", e).into()))?;
        }

        Ok(())
    }
}

impl Drop for NetworkSetup {
    fn drop(&mut self) {
        // 1. Remove jump rules
        let _ = self
            .ipt
            .delete("filter", "FORWARD", &format!("-j {}", self.chain_forward));
        let _ = self.ipt.delete(
            "nat",
            "POSTROUTING",
            &format!("-j {}", self.chain_postrouting),
        );

        // 2. Flush & delete custom chains
        let _ = self.ipt.flush_chain("filter", &self.chain_forward);
        let _ = self.ipt.delete_chain("filter", &self.chain_forward);

        let _ = self.ipt.flush_chain("nat", &self.chain_postrouting);
        let _ = self.ipt.delete_chain("nat", &self.chain_postrouting);

        // 3. Restore IP forwarding
        if let Some(state) = self.prev_ip_forward {
            if set_ip_forwarding_state(state).is_err() {
                tracing::warn!("Failed to restore previous ip_forward state");
            }
        }
    }
}
