use anyhow::{anyhow, Result};
use bytesize::ByteSize;
use clap::Parser;
use lightway_app_utils::args::{Cipher, ConnectionType, Duration, LogLevel};
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

    /// Connection mode
    #[clap(short, long, value_enum, default_value_t = ConnectionType::Tcp)]
    pub mode: ConnectionType,

    /// Auth token
    /// If both token and user/pass are provided, token auth will
    /// be used. user/pass will be ignored in this case
    #[clap(long)]
    pub token: Option<String>,

    /// Username for auth
    #[clap(short, long, hide = true)]
    pub user: Option<String>,

    /// Password for auth
    #[clap(short, long, hide = true)]
    pub password: Option<String>,

    /// CA certificate
    #[clap(long, default_value = "./ca_cert.crt")]
    pub ca_cert: PathBuf,

    /// Outside (wire) MTU
    #[clap(long, default_value_t = MAX_OUTSIDE_MTU)]
    pub outside_mtu: usize,

    /// Inside (tunnel) MTU (requires `CAP_NET_ADMIN`)
    #[clap(long)]
    pub inside_mtu: Option<u16>,

    /// Tun device name to use
    #[clap(short, long, default_value = "lightway")]
    pub tun_name: String,

    /// Local IP to use in Tun device
    #[clap(long, default_value = "100.64.0.6")]
    pub tun_local_ip: Ipv4Addr,

    /// Peer IP to use in Tun device
    #[clap(long, default_value = "100.64.0.5")]
    pub tun_peer_ip: Ipv4Addr,

    /// DNS IP to use in Tun device
    #[clap(long, default_value = "100.64.0.1")]
    pub tun_dns_ip: Ipv4Addr,

    /// Cipher to use for encryption
    #[clap(long, value_enum, default_value_t = Cipher::Aes256)]
    pub cipher: Cipher,

    /// Enable Post Quantum Crypto
    #[cfg(feature = "postquantum")]
    #[clap(long, default_value_t)]
    pub enable_pqc: bool,

    /// Interval between keepalives
    #[clap(long, default_value = "0s")]
    pub keepalive_interval: Duration,

    /// Keepalive timeout
    #[clap(long, default_value = "0s")]
    pub keepalive_timeout: Duration,

    /// Socket send buffer size
    #[clap(long)]
    pub sndbuf: Option<ByteSize>,
    /// Socket receive buffer size
    #[clap(long)]
    pub rcvbuf: Option<ByteSize>,

    /// Log level to use
    #[clap(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Enable PMTU discovery for [`ConnectionType::Udp`] connections
    #[clap(long)]
    pub enable_pmtud: bool,

    /// Enable IO-uring interface for Tunnel
    #[clap(long, default_value_t)]
    pub enable_tun_iouring: bool,

    /// IO-uring submission queue count. Only applicable when
    /// `enable_tun_iouring` is `true`
    // Any value more than 1024 negatively impact the throughput
    #[clap(long, default_value_t = 1024)]
    pub iouring_entry_count: usize,

    /// Server domain name
    #[clap(long, default_value = None)]
    pub server_dn: Option<String>,

    /// Server to connect to
    #[clap(short, long, default_value_t)]
    pub server: String,

    /// File path to save wireshark keylog
    #[cfg(feature = "debug")]
    #[clap(long, default_value = None)]
    pub keylog: Option<PathBuf>,

    /// Enable WolfSSL debug logging
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
}
