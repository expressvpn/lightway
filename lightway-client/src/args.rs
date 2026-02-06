use super::dns_manager::DnsConfigMode;
use super::route_manager::RouteMode;
use anyhow::{Result, anyhow};
use bytesize::ByteSize;
use clap::Parser;
use lightway_app_utils::args::{Cipher, ConnectionType, Duration, LogLevel, NonZeroDuration};
use lightway_core::{AuthMethod, MAX_OUTSIDE_MTU};
use std::{net::Ipv4Addr, path::PathBuf};
use twelf::config;

#[config]
#[derive(Parser, Debug)]
#[command(about = "A lightway client")]
pub struct Config {
    /// Config File to load
    #[clap(short, long)]
    pub config_file: PathBuf,

    /// Servers to attempt to connect to. Configuration is only supported in
    /// config file, not command line or environment variable
    #[clap(skip)]
    #[serde(default)]
    pub servers: Vec<ConnectionConfig>,

    /// Server to connect to in <hostname>:<port> format
    /// Only used if `servers` is empty
    #[clap(short, long, default_value_t)]
    pub server: String,

    /// Connection mode
    /// Only used if `servers` is empty
    #[clap(short, long, value_enum, default_value_t = ConnectionType::Tcp)]
    pub mode: ConnectionType,

    /// Server domain name
    /// Only used if `servers` is empty
    #[clap(long, default_value = None)]
    pub server_dn: Option<String>,

    /// Cipher to use for encryption
    /// Only used if `servers` is empty
    #[clap(long, value_enum, default_value_t = Cipher::Aes256)]
    pub cipher: Cipher,

    /// Auth token
    /// If both token and user/pass are provided, token auth will
    /// be used. user/pass will be ignored in this case
    #[clap(long, hide = true)]
    pub token: Option<String>,

    /// Username for auth
    #[clap(short, long, hide = true)]
    pub user: Option<String>,

    /// Password for auth
    #[clap(short, long, hide = true)]
    pub password: Option<String>,

    /// CA certificate
    /// This can either be a path to the file, or a string starting with
    /// "-----BEGIN CERTIFICATE-----"
    #[clap(long, default_value = "./ca_cert.crt")]
    pub ca_cert: String,

    /// Outside (wire) MTU
    #[clap(long, default_value_t = MAX_OUTSIDE_MTU)]
    pub outside_mtu: usize,

    /// Tun device name to use
    #[clap(short, long, default_value = None)]
    pub tun_name: Option<String>,

    /// Local IP to use in Tun device
    #[clap(long, default_value = "100.64.0.6")]
    pub tun_local_ip: Ipv4Addr,

    /// Peer IP to use in Tun device
    #[clap(long, default_value = "100.64.0.5")]
    pub tun_peer_ip: Ipv4Addr,

    /// DNS IP to use in Tun device
    #[clap(long, default_value = "100.64.0.1")]
    pub tun_dns_ip: Ipv4Addr,

    /// Enable Post Quantum Crypto
    #[cfg(feature = "postquantum")]
    #[clap(long, default_value_t)]
    pub enable_pqc: bool,

    /// Interval between keepalives
    #[clap(long, default_value = "10s")]
    pub keepalive_interval: NonZeroDuration,

    /// Keepalive timeout
    #[clap(long, default_value = "60s")]
    pub keepalive_timeout: NonZeroDuration,

    /// Enable continuous Keepalive
    #[clap(long, default_value_t = true)]
    pub keepalive_continuous: bool,

    /// Time it takes to trigger a tracer packet
    /// when we haven't received an outside packet
    #[clap(long, default_value = "10s")]
    pub tracer_packet_timeout: NonZeroDuration,

    /// How long to wait before selecting the best connection. If the preferred
    /// connection connects before the timeout, it will be used immediately.
    #[clap(long, default_value = "0s")]
    pub preferred_connection_wait_interval: Duration,

    /// Socket send buffer size
    #[clap(long)]
    pub sndbuf: Option<ByteSize>,
    /// Socket receive buffer size
    #[clap(long)]
    pub rcvbuf: Option<ByteSize>,

    /// Setup of route table
    /// Modes:
    ///     default: Sets up routes as specified in server, tun_local_ip, tun_peer_ip, tun_dns_ip
    ///     noexec : Does not setup any routes
    ///     lan    : Sets up default + additional lan routes
    #[clap(long, value_enum, default_value_t)]
    #[cfg(desktop)]
    pub route_mode: RouteMode,

    /// DNS configuration mode
    /// Modes:
    ///     default: Sets up DNS Configuration based on target platform
    ///     noexec : Skips DNS Configuration setup
    #[clap(long, value_enum, default_value_t)]
    #[cfg(desktop)]
    pub dns_config_mode: DnsConfigMode,

    /// Log level to use
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Enable Expresslane for [`ConnectionType::Udp`] connections
    #[clap(long, default_value_t)]
    pub enable_expresslane: bool,

    /// Enable PMTU discovery for [`ConnectionType::Udp`] connections
    #[clap(long)]
    pub enable_pmtud: bool,

    /// Base MTU to use for PMTU discovery
    #[clap(long)]
    pub pmtud_base_mtu: Option<u16>,

    /// Enable IO-uring interface for Tunnel
    #[clap(long, default_value_t)]
    pub enable_tun_iouring: bool,

    /// IO-uring submission queue count. Only applicable when
    /// `enable_tun_iouring` is `true`
    // Any value more than 1024 negatively impact the throughput
    #[clap(long, default_value_t = 1024)]
    pub iouring_entry_count: usize,

    /// IO-uring sqpoll idle time. If non-zero use a kernel thread to
    /// perform submission queue polling. After the given idle time
    /// the thread will go to sleep.
    #[clap(long, default_value = "100ms")]
    pub iouring_sqpoll_idle_time: Duration,

    /// Enable inside packet encoding once lightway connects
    /// Only used if a codec is set
    #[clap(short, long, default_value_t)]
    pub enable_inside_pkt_encoding_at_connect: bool,

    /// File path to save wireshark keylog
    #[cfg(feature = "debug")]
    #[clap(long, default_value = None)]
    pub keylog: Option<PathBuf>,

    /// Enable WolfSSL debug logging
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,

    /// Enable DPAPI encryption/decryption for config file
    /// Only for Windows platform
    #[cfg(windows)]
    #[clap(long)]
    pub enable_dpapi: bool,
}

impl Config {
    pub fn take_auth(&mut self) -> Result<AuthMethod> {
        match (self.token.take(), self.user.take(), self.password.take()) {
            (Some(token), _, _) => Ok(AuthMethod::Token { token }),
            (_, Some(user), Some(password)) => Ok(AuthMethod::UserPass { user, password }),
            _ => Err(anyhow!(
                "Either a token or username and password is required"
            )),
        }
    }
}

#[config]
#[derive(Parser, Debug)]
pub struct ConnectionConfig {
    /// Server to connect to in <hostname>:<port> format
    pub server: String,

    /// Connection mode
    #[serde(default)]
    pub mode: ConnectionType,

    /// Server domain name
    #[serde(default)]
    pub server_dn: Option<String>,

    /// Cipher to use for encryption
    #[serde(default)]
    pub cipher: Cipher,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use clap::CommandFactory;
    use test_case::test_case;
    use twelf::Layer;

    #[test_case("../tests/client/client_config.yaml", true, 0)]
    #[test_case(
        "../tests/client/parallel_connect/client_config.tcp_then_udp.yaml",
        false,
        2
    )]
    #[test_case("../tests/client/parallel_connect/client_config.tcp.yaml", false, 10)]
    #[test_case(
        "../tests/client/parallel_connect/client_config.udp_then_tcp.yaml",
        false,
        2
    )]
    #[test_case("../tests/client/parallel_connect/client_config.udp.yaml", false, 10)]
    fn test_parse_config(config_file: &str, has_top_level_server: bool, servers_len: usize) {
        let matches =
            Config::command().get_matches_from(["lightway-client", "--config-file", config_file]);
        let config_file = PathBuf::from_str(config_file).unwrap();
        let config =
            Config::with_layers(&[Layer::Yaml(config_file), Layer::Clap(matches)]).unwrap();

        assert_eq!(config.server.is_empty(), !has_top_level_server);
        assert_eq!(config.servers.len(), servers_len);
    }
}
