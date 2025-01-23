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
    #[clap(long, default_value = "lightway")]
    pub tun_name: String,

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

    /// Enable Post Quantum Crypto
    #[clap(long, default_value_t)]
    pub enable_pqc: bool,

    /// Total IO-uring submission queue count.
    ///
    /// Must be larger than the total of:
    ///
    /// UDP:
    ///
    ///   iouring_tun_rx_count + iouring_udp_rx_count +
    ///   iouring_tx_count + 1 (cancellation request)
    ///
    /// TCP:
    ///
    ///   iouring_tun_rx_count + iouring_tx_count + 1 (cancellation
    ///   request) + 2 * maximum number of connections.
    ///
    ///   Each connection actually uses up to 3 slots, a persistent
    ///   recv request and on demand slots for TX and cancellation
    ///   (teardown).
    ///
    /// There is no downside to setting this much larger.
    #[clap(long, default_value_t = 1024)]
    pub iouring_entry_count: usize,

    /// IO-uring sqpoll idle time. If non-zero use a kernel thread to
    /// perform submission queue polling. After the given idle time
    /// the thread will go to sleep.
    #[clap(long, default_value = "100ms")]
    pub iouring_sqpoll_idle_time: Duration,

    /// Number of concurrent TUN device read requests to issue to
    /// IO-uring. Setting this too large may negatively impact
    /// performance.
    #[clap(long, default_value_t = 64)]
    pub iouring_tun_rx_count: u32,

    /// Configure TUN device in blocking mode. This can allow
    /// equivalent performance with fewer `ìouring-tun-rx-count`
    /// entries but can significantly harm performance on some kernels
    /// where the kernel does not indicate that the tun device handles
    /// `FMODE_NOWAIT`.
    ///
    /// If blocking mode is enabled then `iouring_tun_rx_count` may be
    /// set much lower.
    ///
    /// This was fixed by <https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=438b406055cd21105aad77db7938ee4720b09bee>
    /// which was part of v6.4-rc1.
    #[clap(long, default_value_t = false)]
    pub iouring_tun_blocking: bool,

    /// Number of concurrent UDP socket recvmsg requests to issue to
    /// IO-uring.
    #[clap(long, default_value_t = 32)]
    pub iouring_udp_rx_count: u32,

    /// Maximum number of concurrent UDP + TUN sendmsg/write requests
    /// to issue to IO-uring.
    #[clap(long, default_value_t = 512)]
    pub iouring_tx_count: u32,

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

    /// Set UDP buffer size. Default value is 256 KiB.
    #[clap(long, default_value_t = ByteSize::kib(256))]
    pub tcp_buffer_size: ByteSize,

    /// Enable WolfSSL debug logging
    #[cfg(feature = "debug")]
    #[clap(long)]
    pub tls_debug: bool,
}
