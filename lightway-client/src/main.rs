use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::CommandFactory;
use twelf::reexports::log::error;
use twelf::Layer;

use lightway_app_utils::{args::ConnectionType, is_file_path_valid};
use lightway_client::*;

mod args;
use args::Config;

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Config::command().get_matches();

    // Fetch the config filepath from CLI and load it as config
    let Some(config_file) = matches.get_one::<PathBuf>("config_file") else {
        return Err(anyhow!("Config file not present"));
    };

    if !is_file_path_valid(config_file) {
        let error_string = format!("Config file {:?} not present", &config_file);
        error!("{}", &error_string);
        return Err(anyhow!(error_string));
    }

    let config = Config::with_layers(&[
        Layer::Yaml(config_file.to_owned()),
        Layer::Env(Some(String::from("LW_CLIENT_"))),
        Layer::Clap(matches),
    ])?;

    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .init();

    let auth = AuthMethod::UserPass {
        user: config.user,
        password: config.password,
    };

    let mode = match config.mode {
        ConnectionType::Tcp => ClientConnectionType::Stream(None),
        ConnectionType::Udp => ClientConnectionType::Datagram(None),
    };

    let root_ca_cert = RootCertificate::PemFileOrDirectory(&config.ca_cert);

    let config = ClientConfig {
        mode,
        auth,
        root_ca_cert,
        outside_mtu: config.outside_mtu,
        inside_mtu: config.inside_mtu,
        #[cfg(feature = "linux-tun")]
        tun_name: config.tun_name,
        #[cfg(not(feature = "linux-tun"))]
        tun_fd: -1, // A placeholder until tun_fd retrival is implemented
        tun_local_ip: config.tun_local_ip,
        tun_peer_ip: config.tun_peer_ip,
        tun_dns_ip: config.tun_dns_ip,
        cipher: config.cipher,
        #[cfg(feature = "postquantum")]
        enable_pqc: config.enable_pqc,
        keepalive_interval: config.keepalive_interval.into(),
        keepalive_timeout: config.keepalive_timeout.into(),
        sndbuf: config.sndbuf,
        rcvbuf: config.rcvbuf,
        enable_pmtud: config.enable_pmtud,
        enable_tun_iouring: config.enable_tun_iouring,
        iouring_entry_count: config.iouring_entry_count,
        server_dn: config.server_dn,
        server: config.server,
        inside_plugins: Default::default(),
        outside_plugins: Default::default(),
        #[cfg(feature = "debug")]
        keylog: config.keylog,
    };

    client(config).await
}
