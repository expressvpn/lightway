use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use bytesize::ByteSize;
use clap::Parser;
use ipnet::Ipv4Net;
use serde::Deserialize;
use std::time::Duration as StdDuration;
use struct_patch::Patch;

use lightway_app_utils::args::{
    ConnectionType, Duration, IpMap, LogFormat, LogLevel, NonZeroDuration,
};

#[derive(Parser, Debug, Deserialize, Patch)]
#[patch(attribute(derive(Deserialize)))]
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
    pub key_update_interval: NonZeroDuration,

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

impl Default for Config {
    fn default() -> Config {
        Config {
            config_file: PathBuf::default(),
            mode: ConnectionType::Tcp,
            user_db: None,
            token_rsa_pub_key_pem: None,
            server_cert: PathBuf::from("./server.crt"),
            server_key: PathBuf::from("./server.key"),
            tun_name: None,
            ip_pool: Ipv4Net::new(Ipv4Addr::new(10, 125, 0, 0), 16)
                .expect("default value should corret"),
            ip_map: None,
            tun_ip: None,
            lightway_server_ip: Ipv4Addr::new(10, 125, 0, 6),
            lightway_client_ip: Ipv4Addr::new(10, 125, 0, 5),
            lightway_dns_ip: Ipv4Addr::new(10, 125, 0, 1),
            enable_expresslane: false,
            enable_pqc: false,
            enable_tun_iouring: false,
            iouring_entry_count: 1024,
            iouring_sqpoll_idle_time: Duration::from_std_duration(StdDuration::from_millis(100)),
            log_format: LogFormat::Full,
            log_level: LogLevel::Info,
            // TODO: use from_mins, if MSRV > 1.91
            key_update_interval: NonZeroDuration::from_std_duration(StdDuration::from_secs(
                15 * 60,
            )),
            bind_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 27690),
            proxy_protocol: false,
            udp_buffer_size: ByteSize::mib(15),
            #[cfg(feature = "debug")]
            tls_debug: false,
            #[cfg(feature = "debug")]
            randomize_ippool: true,
        }
    }
}
