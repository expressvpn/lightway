use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use bytesize::ByteSize;
use clap::Parser;
use ipnet::Ipv4Net;
use twelf::config;

use lightway_app_utils::args::{ConnectionType, Duration, IpMap, LogFormat, LogLevel};

#[config]
#[derive(Parser, Debug)]
#[clap(about = "A lightway server")]
pub struct Config {
    /// Config File to load
    #[clap(short, long)]
    pub config_file: PathBuf,

    /// Connection mode
    #[clap(short, long, value_enum, default_value_t=ConnectionType::Tcp)]
    pub mode: ConnectionType,

    /// user database, in Apache htpasswd format
    #[clap(long)]
    pub user_db: Option<PathBuf>,

    #[clap(long)]
    pub token_rsa_pub_key_pem: Option<PathBuf>,

    /// Server certificate
    #[clap(long, default_value = "./server.crt")]
    pub server_cert: PathBuf,

    /// Server key
    #[clap(long, default_value = "./server.key")]
    pub server_key: PathBuf,

    /// Tun device name to use
    #[clap(long, default_value = None)]
    pub tun_name: Option<String>,

    /// IP pool to assign clients
    #[clap(long, default_value = "10.125.0.0/16")]
    pub ip_pool: Ipv4Net,

    /// Additional IP address map. Maps from incoming IP address to
    /// a subnet of "ip_pool" to use for that address.
    #[clap(long)]
    pub ip_map: Option<IpMap>,

    /// The IP assigned to the Tun device. If this is within `ip_pool`
    /// then it will be reserved.
    #[clap(long)]
    pub tun_ip: Option<Ipv4Addr>,

    /// Server IP to send in network_config message
    #[clap(long, default_value = "10.125.0.6")]
    pub lightway_server_ip: Ipv4Addr,

    /// Client IP to send in network_config message
    #[clap(long, default_value = "10.125.0.5")]
    pub lightway_client_ip: Ipv4Addr,

    /// DNS IP to send in network_config message
    #[clap(long, default_value = "10.125.0.1")]
    pub lightway_dns_ip: Ipv4Addr,

    /// Enable Expresslane for [`ConnectionType::Udp`] connections
    #[clap(long, default_value_t)]
    pub enable_expresslane: bool,

    /// Enable Post Quantum Crypto
    #[clap(long, default_value_t)]
    pub enable_pqc: bool,

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

    /// Log format
    #[clap(long, value_enum, default_value_t = LogFormat::Full)]
    pub log_format: LogFormat,

    /// Log level to use
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// The key update interval for DTLS/TLS 1.3 connections
    #[clap(long, default_value = "15m")]
    pub key_update_interval: Duration,

    /// Address to listen to
    #[clap(long, default_value = "0.0.0.0:27690")]
    pub bind_address: SocketAddr,

    /// Enable PROXY protocol support (TCP only)
    #[clap(long)]
    pub proxy_protocol: bool,

    /// Set UDP buffer size. Default value is 15 MiB.
    #[clap(long, default_value_t = ByteSize::mib(15))]
    pub udp_buffer_size: ByteSize,

    /// Enable WolfSSL debug logging
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,

    /// Disable IP pool randomization
    /// Should be used for debugging only
    #[cfg(feature = "debug")]
    #[clap(long, default_value_t = true)]
    pub randomize_ippool: bool,
}
