use std::{
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    path::PathBuf,
};

use bytesize::ByteSize;
use clap::Parser;
use ipnet::Ipv4Net;
use twelf::config;

use lightway_app_utils::args::{ConnectionType, Duration, IpMap, LogFormat, LogLevel};

#[config]
#[derive(Parser, Debug)]
#[command(
    about = "Lightway server - high-performance, secure, reliable VPN protocol in Rust",
    version,
    author = "ExpressVPN <lightway-developers@expressvpn.com>",
    after_help = concat!(
        "EXAMPLES:\n",
        "    lightway-server -c server.yaml\n",
        "    lightway-server -c server.yaml --ip-pool 192.168.100.0/24\n",
        "    lightway-server -c server.yaml --mode udp --proxy-protocol\n",
        "\n",
        "See lightway-server(1) manpage for detailed configuration and usage information."
    )
)]
pub struct Config {
    /// Configuration file path (YAML format)
    /// Supports both absolute and relative paths
    #[clap(short, long, value_name = "FILE")]
    pub config_file: PathBuf,

    /// Transport protocol for client connections
    /// TCP provides reliability, UDP provides better performance
    #[clap(short, long, value_enum, default_value_t=ConnectionType::Tcp, value_name = "PROTOCOL")]
    pub mode: ConnectionType,

    /// Path to user database file (Apache htpasswd format)
    /// Supports bcrypt, SHA-256, and SHA-512 password hashes only
    #[clap(long, value_name = "FILE")]
    pub user_db: Option<PathBuf>,

    /// RSA public key file for JWT token validation (PEM format)
    /// Used to verify RS256-signed JWT tokens from clients
    #[clap(long, value_name = "FILE")]
    pub token_rsa_pub_key_pem: Option<PathBuf>,

    /// Path to server TLS certificate file
    /// Must be valid X.509 certificate in PEM format
    #[clap(long, default_value = "./server.crt", value_name = "FILE")]
    pub server_cert: PathBuf,

    /// Path to server TLS private key file
    /// Must correspond to the server certificate
    #[clap(long, default_value = "./server.key", value_name = "FILE")]
    pub server_key: PathBuf,

    /// TUN device name for tunnel interface
    /// Must be unique if running multiple server instances
    #[clap(long, default_value = "lightway", value_name = "NAME")]
    pub tun_name: String,

    /// IP address pool for client assignment (CIDR notation)
    /// All connected clients receive IPs from this range
    #[clap(long, default_value = "10.125.0.0/16", value_name = "SUBNET")]
    pub ip_pool: Ipv4Net,

    /// Custom IP mapping for specific client source addresses
    /// Maps incoming IP to a specific subnet within the main IP pool
    #[clap(long, value_name = "MAP")]
    pub ip_map: Option<IpMap>,

    /// IP address for the server's TUN device
    /// Reserved from the IP pool if within that range
    #[clap(long, value_name = "IP")]
    pub tun_ip: Option<Ipv4Addr>,

    /// Server IP address sent to clients in network configuration
    /// Represents the server endpoint within the tunnel
    #[clap(long, default_value = "10.125.0.6", value_name = "IP")]
    pub lightway_server_ip: Ipv4Addr,

    /// Default client IP address for network configuration
    /// Template for client tunnel interface configuration
    #[clap(long, default_value = "10.125.0.5", value_name = "IP")]
    pub lightway_client_ip: Ipv4Addr,

    /// DNS server IP address sent to clients
    /// Used by clients for domain name resolution through VPN
    #[clap(long, default_value = "10.125.0.1", value_name = "IP")]
    pub lightway_dns_ip: Ipv4Addr,

    /// Enable Post-Quantum Cryptography (experimental)
    /// Provides protection against future quantum computing attacks
    #[clap(long)]
    pub enable_pqc: bool,

    /// Enable io_uring for high-performance tunnel I/O (Linux only)
    /// Provides better performance but requires recent Linux kernel
    #[clap(long)]
    pub enable_tun_iouring: bool,

    /// io_uring submission queue size (max 1024 for optimal performance)
    /// Only used when --enable-tun-iouring is enabled
    #[clap(long, default_value_t = 1024, value_name = "COUNT")]
    pub iouring_entry_count: usize,

    /// io_uring kernel polling idle time (0 = disabled)
    /// Uses kernel thread for polling; reduces CPU usage but may increase latency
    #[clap(long, default_value = "100ms", value_name = "DURATION")]
    pub iouring_sqpoll_idle_time: Duration,

    /// Log output format for different use cases
    /// 'json' is recommended for structured logging and monitoring
    #[clap(long, value_enum, default_value_t = LogFormat::Full, value_name = "FORMAT")]
    pub log_format: LogFormat,

    /// Logging verbosity level
    /// Use 'debug' or 'trace' for troubleshooting server issues
    #[clap(long, value_enum, default_value_t = LogLevel::Info, value_name = "LEVEL")]
    pub log_level: LogLevel,

    /// Interval for automatic TLS/DTLS key rotation
    /// More frequent updates improve security but may impact performance
    #[clap(long, default_value = "15m", value_name = "DURATION")]
    pub key_update_interval: Duration,

    /// Server bind address and port (host:port)
    /// Use 0.0.0.0 to listen on all interfaces
    #[clap(long, default_value = "0.0.0.0:27690", value_name = "ADDRESS")]
    pub bind_address: SocketAddr,

    /// Number of bind retry attempts if address is in use
    /// Waits 1 second between attempts; useful for service restarts
    #[clap(long, default_value_t = NonZeroUsize::MIN, value_name = "COUNT")]
    pub bind_attempts: NonZeroUsize,

    /// Enable PROXY protocol v1/v2 support (TCP mode only)
    /// Required when running behind load balancers like HAProxy
    #[clap(long)]
    pub proxy_protocol: bool,

    /// UDP socket buffer size for performance tuning
    /// Larger buffers improve performance on high-throughput connections
    #[clap(long, default_value_t = ByteSize::mib(15), value_name = "SIZE")]
    pub udp_buffer_size: ByteSize,

    /// Enable detailed TLS/SSL debug logging (debug builds only)
    /// Provides verbose cryptographic handshake information
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,
}

impl Config {
    /// Create a clap command with extensive help text for manpage generation
    #[allow(dead_code)]
    pub fn command_for_manpage() -> clap::Command {
        use clap::CommandFactory;
        let long_about = [
            "Lightway is a modern VPN server that implements the Lightway protocol. It provides",
            "a high-performance, secure VPN service using modern cryptographic algorithms and",
            "optimized network protocols.",
            "",
            "The server accepts connections from Lightway clients and provides secure tunneling",
            "services. It supports multiple authentication methods, dynamic IP assignment, and",
            "advanced features like PROXY protocol support and io_uring optimization on Linux.",
            "",
            "Configuration can be provided via YAML files, environment variables (LW_SERVER_*),",
            "or command-line arguments. Command-line arguments have the highest priority.",
            "",
            "Authentication: Supports both username/password (htpasswd format) and JWT token",
            "authentication. Only bcrypt, SHA-256, and SHA-512 password hashes are supported.",
        ]
        .join("\n");

        let after_help = [
            "CONFIGURATION FILE:",
            "The server requires a configuration file in YAML format. Environment variables can",
            "override configuration file settings using the LW_SERVER_ prefix. Command-line",
            "arguments have the highest priority.",
            "",
            "Example configuration:",
            "    mode: tcp",
            "    bind_address: \"0.0.0.0:27690\"",
            "    server_cert: \"/etc/lightway/server.crt\"",
            "    server_key: \"/etc/lightway/server.key\"",
            "    user_db: \"/etc/lightway/users.db\"",
            "    ip_pool: \"10.125.0.0/16\"",
            "    log_level: info",
            "    key_update_interval: \"15m\"",
            "",
            "AUTHENTICATION:",
            "The server supports multiple authentication methods:",
            "  • Username/Password: Uses Apache htpasswd compatible format. Only bcrypt,",
            "    SHA-256, and SHA-512 hashes are supported (not Apache MD5).",
            "  • JWT Token: Uses RSA public key to validate JWT tokens with RS256 algorithm.",
            "    Tokens must include a valid \"exp\" claim.",
            "",
            "Both methods can be enabled simultaneously. Each client connection uses one",
            "method chosen by the client.",
            "",
            "USER DATABASE FORMAT:",
            "The user database file follows Apache htpasswd format:",
            "    username:hash(password)",
            "",
            "Generate entries using:",
            "    htpasswd -B -c users.db username",
            "",
            "Only bcrypt (-B), SHA-256 (-5), and SHA-512 (-2) are supported.",
            "",
            "IP ASSIGNMENT:",
            "The server dynamically assigns IP addresses from the configured pool:",
            "  • --ip-pool defines the available address range",
            "  • --tun-ip reserves an address for the TUN device",
            "  • --ip-map allows custom mappings for specific source IPs",
            "  • Addresses are automatically assigned and released",
            "",
            "SECURITY CONSIDERATIONS:",
            "  • Ensure proper file permissions on certificate files (600 recommended)",
            "  • Use strong passwords and modern hashing algorithms for user database",
            "  • Regularly rotate JWT signing keys",
            "  • Monitor key update intervals for optimal security",
            "  • Use appropriate IP pool ranges to avoid conflicts",
            "",
            "EXIT STATUS:",
            "    0    Successful operation",
            "    1    General error (configuration, network, certificate)",
            "    2    Permission error (insufficient privileges for tunnel operations)",
            "",
            "EXAMPLES:",
            "    lightway-server --config-file /etc/lightway/server.yaml",
            "    lightway-server -c server.yaml --ip-pool 192.168.100.0/24 --log-level debug",
            "    lightway-server -c server.yaml --mode udp",
            "    lightway-server -c server.yaml --proxy-protocol",
            "",
            "FILES:",
            "    /etc/lightway/server.yaml    System-wide server configuration",
            "    /etc/lightway/server.crt     Server certificate",
            "    /etc/lightway/server.key     Server private key",
            "    /etc/lightway/users.db       User database (htpasswd format)",
            "    /etc/lightway/token.pub      JWT validation public key",
            "",
            "ENVIRONMENT:",
            "    LW_SERVER_BIND_ADDRESS     Server bind address",
            "    LW_SERVER_LOG_LEVEL        Logging level",
            "    LW_SERVER_USER_DB          Path to user database file",
            "    LW_SERVER_IP_POOL          Client IP pool subnet",
            "",
            "SIGNALS:",
            "    SIGTERM, SIGINT    Graceful shutdown",
            "    SIGHUP             Reload configuration (if supported)",
            "",
            "SEE ALSO:",
            "    lightway-client(1), lightway-core(7), htpasswd(1), ip(8), iptables(8)",
            "",
            "REPORT BUGS:",
            "    https://github.com/expressvpn/lightway/issues",
        ]
        .join("\n");

        Self::command()
            .long_about(long_about)
            .after_help(after_help)
    }
}
