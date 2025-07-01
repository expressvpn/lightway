use anyhow::{Result, anyhow};
use bytesize::ByteSize;
use clap::Parser;
use lightway_app_utils::args::{Cipher, ConnectionType, Duration, LogLevel};
use lightway_core::{AuthMethod, MAX_OUTSIDE_MTU};
use std::{net::Ipv4Addr, path::PathBuf};
use twelf::config;

#[config]
#[derive(Parser, Debug)]
#[command(
    about = "Lightway client - high-performance, secure, reliable VPN protocol in Rust",
    version,
    author = "ExpressVPN <lightway-developers@expressvpn.com>",
    after_help = concat!(
        "EXAMPLES:\n",
        "    lightway-client -c client.yaml\n",
        "    lightway-client -c client.yaml --server vpn.example.com:27690\n",
        "    lightway-client -c client.yaml --mode udp --enable-pmtud\n",
        "\n",
        "See lightway-client(1) manpage for detailed configuration and usage information."
    )
)]
pub struct Config {
    /// Configuration file path (YAML format)
    /// Supports both absolute and relative paths
    #[clap(short, long, value_name = "FILE")]
    pub config_file: PathBuf,

    /// Transport protocol to use for VPN connection
    /// TCP provides reliability, UDP provides better performance
    #[clap(short, long, value_enum, default_value_t = ConnectionType::Tcp, value_name = "PROTOCOL")]
    pub mode: ConnectionType,

    /// JWT authentication token (takes precedence over username/password)
    /// Use configuration file or environment variable instead of CLI argument
    #[clap(long, value_name = "TOKEN", hide = true)]
    pub token: Option<String>,

    /// Username for authentication
    /// Use configuration file or environment variable instead of CLI argument
    #[clap(short, long, value_name = "USER")]
    pub user: Option<String>,

    /// Password for authentication
    /// WARNING: Visible to other users when passed via CLI. Use config file or LW_CLIENT_PASSWORD env var
    #[clap(short, long, value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Path to CA certificate file for server validation
    /// Ensures secure connection to authentic Lightway server
    #[clap(long, default_value = "./ca_cert.crt", value_name = "FILE")]
    pub ca_cert: PathBuf,

    /// Maximum Transmission Unit for network packets
    /// Adjust based on your network infrastructure to avoid fragmentation
    #[clap(long, default_value_t = MAX_OUTSIDE_MTU, value_name = "SIZE")]
    pub outside_mtu: usize,

    /// MTU for tunnel interface (requires CAP_NET_ADMIN capability)
    /// Override default MTU of tunnel device for performance tuning
    #[clap(long, value_name = "SIZE")]
    pub inside_mtu: Option<u16>,

    /// TUN device name (leave empty for auto-assignment)
    /// On macOS, must follow format 'utun[0-9]+' or leave empty
    #[clap(short, long, value_name = "NAME")]
    pub tun_name: Option<String>,

    /// Local IP address for tunnel interface
    /// Must be within the same subnet as peer IP
    #[clap(long, default_value = "100.64.0.6", value_name = "IP")]
    pub tun_local_ip: Ipv4Addr,

    /// Peer IP address for tunnel interface
    /// Represents the server endpoint within the tunnel
    #[clap(long, default_value = "100.64.0.5", value_name = "IP")]
    pub tun_peer_ip: Ipv4Addr,

    /// DNS server IP address for tunnel traffic
    /// Used for resolving domain names through the VPN
    #[clap(long, default_value = "100.64.0.1", value_name = "IP")]
    pub tun_dns_ip: Ipv4Addr,

    /// Encryption cipher algorithm
    /// AES-256 provides strong security, ChaCha20 may perform better on some CPUs
    #[clap(long, value_enum, default_value_t = Cipher::Aes256, value_name = "CIPHER")]
    pub cipher: Cipher,

    /// Enable Post-Quantum Cryptography (experimental)
    /// Provides protection against future quantum computing attacks
    #[cfg(feature = "postquantum")]
    #[clap(long)]
    pub enable_pqc: bool,

    /// Interval between keepalive packets (0s = disabled)
    /// Helps maintain connection through NAT devices and firewalls
    #[clap(long, default_value = "0s", value_name = "DURATION")]
    pub keepalive_interval: Duration,

    /// Timeout for keepalive responses (0s = disabled)
    /// Connection considered dead if no response within this time
    #[clap(long, default_value = "0s", value_name = "DURATION")]
    pub keepalive_timeout: Duration,

    /// Socket send buffer size for performance tuning
    /// Larger buffers may improve throughput on high-bandwidth connections
    #[clap(long, value_name = "SIZE")]
    pub sndbuf: Option<ByteSize>,
    /// Socket receive buffer size for performance tuning
    /// Larger buffers may improve throughput on high-bandwidth connections
    #[clap(long, value_name = "SIZE")]
    pub rcvbuf: Option<ByteSize>,

    /// Logging verbosity level
    /// Use 'debug' or 'trace' for troubleshooting connection issues
    #[clap(long, value_enum, default_value_t = LogLevel::Info, value_name = "LEVEL")]
    pub log_level: LogLevel,

    /// Enable Path MTU Discovery for UDP connections
    /// Automatically determines optimal packet size for the network path
    #[clap(long)]
    pub enable_pmtud: bool,

    /// Starting MTU size for Path MTU Discovery process
    /// Only used when --enable-pmtud is set
    #[clap(long, value_name = "SIZE")]
    pub pmtud_base_mtu: Option<u16>,

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

    /// Server domain name for certificate validation
    /// Used to verify server certificate matches expected hostname
    #[clap(long, value_name = "DOMAIN")]
    pub server_dn: Option<String>,

    /// Server address to connect to (host:port)
    /// Can be IP address or domain name with port number
    #[clap(short, long, value_name = "ADDRESS")]
    pub server: String,

    /// Enable packet encoding/obfuscation after connection
    /// Provides additional traffic obfuscation when codec is configured
    #[clap(short, long)]
    pub enable_inside_pkt_encoding_at_connect: bool,

    /// Path to save TLS keylog for Wireshark decryption (debug builds only)
    /// Enables traffic analysis and debugging of encrypted connections
    #[cfg(feature = "debug")]
    #[clap(long, value_name = "FILE")]
    pub keylog: Option<PathBuf>,

    /// Enable detailed TLS/SSL debug logging (debug builds only)
    /// Provides verbose cryptographic handshake information
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,
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

    /// Create a clap command with extensive help text for manpage generation
    #[allow(dead_code)]
    pub fn command_for_manpage() -> clap::Command {
        use clap::CommandFactory;
        let long_about = [
            "Lightway is a modern VPN client that implements the Lightway protocol. It provides",
            "a fast, secure, and reliable VPN connection using modern cryptographic algorithms",
            "and optimized network protocols.",
            "",
            "The client connects to a Lightway server and establishes a secure tunnel for",
            "routing network traffic. It supports both TCP and UDP transport protocols and",
            "includes advanced features like Path MTU Discovery, keepalive mechanisms, and",
            "io_uring optimization on Linux.",
            "",
            "Configuration can be provided via YAML files, environment variables (LW_CLIENT_*),",
            "or command-line arguments. Command-line arguments have the highest priority.",
            "",
            "Security Note: Avoid passing passwords via command-line arguments as they may be",
            "visible to other users. Use configuration files or environment variables instead.",
        ]
        .join("\n");

        let after_help = [
            "CONFIGURATION FILE:",
            "The client requires a configuration file in YAML format. Environment variables can",
            "override configuration file settings using the LW_CLIENT_ prefix. Command-line",
            "arguments have the highest priority.",
            "",
            "Example configuration:",
            "    mode: tcp",
            "    server: \"vpn.example.com:27690\"",
            "    user: \"myuser\"",
            "    password: \"mypassword\"",
            "    ca_cert: \"/etc/lightway/ca.crt\"",
            "    log_level: info",
            "",
            "AUTHENTICATION:",
            "The client supports two authentication methods:",
            "  • Username/Password: Traditional username and password authentication",
            "  • JWT Token: JSON Web Token authentication using RS256 algorithm",
            "",
            "If both token and username/password are provided, token authentication takes precedence.",
            "",
            "SECURITY CONSIDERATIONS:",
            "  • Never pass passwords via command-line arguments as they may be visible to other users",
            "  • Use configuration files or environment variables for sensitive data",
            "  • Ensure proper file permissions on configuration files (600 recommended)",
            "  • Validate server certificates using the --ca-cert option",
            "",
            "EXIT STATUS:",
            "    0    Successful operation",
            "    1    General error (configuration, network, authentication)",
            "    2    Permission error (insufficient privileges for tunnel operations)",
            "",
            "EXAMPLES:",
            "    lightway-client --config-file /etc/lightway/client.yaml",
            "    lightway-client -c client.yaml --server vpn.example.com:27690 --log-level debug",
            "    lightway-client -c client.yaml --mode udp --enable-pmtud",
            "",
            "FILES:",
            "    /etc/lightway/client.yaml    System-wide client configuration",
            "    ~/.config/lightway/client.yaml    User-specific client configuration",
            "    ./ca_cert.crt    Default CA certificate location",
            "",
            "ENVIRONMENT:",
            "    LW_CLIENT_SERVER       Server address",
            "    LW_CLIENT_USER         Username for authentication",
            "    LW_CLIENT_PASSWORD     Password for authentication",
            "    LW_CLIENT_LOG_LEVEL    Logging level",
            "",
            "SEE ALSO:",
            "    lightway-server(1), lightway-core(7), ip(8), iptables(8)",
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
