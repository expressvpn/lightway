use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, anyhow};
use clap::CommandFactory;
use lightway_core::{Event, EventCallback};
use twelf::Layer;

use lightway_app_utils::{
    TunConfig, Validate, args::ConnectionType, validate_configuration_file_path,
};
use lightway_client::{io::inside::InsideIO, *};

mod args;
use args::Config;

struct EventHandler;

impl EventCallback for EventHandler {
    fn event(&self, event: lightway_core::Event) {
        if let Event::StateChanged(state) = event {
            tracing::debug!("State changed to {:?}", state);
        }
    }
}

#[tokio::main(worker_threads = 1)]
async fn main() -> Result<()> {
    let matches = Config::command().get_matches();

    // Fetch the config filepath from CLI and load it as config
    let Some(config_file) = matches.get_one::<PathBuf>("config_file") else {
        return Err(anyhow!("Config file not present"));
    };

    validate_configuration_file_path(config_file, Validate::OwnerOnly)
        .with_context(|| format!("Invalid configuration file {}", config_file.display()))?;

    let mut config = Config::with_layers(&[
        Layer::Yaml(config_file.to_owned()),
        Layer::Env(Some(String::from("LW_CLIENT_"))),
        Layer::Clap(matches),
    ])?;

    tracing_subscriber::fmt()
        .with_max_level(config.log_level)
        .init();

    let auth = config.take_auth()?;

    let mode = match config.mode {
        ConnectionType::Tcp => ClientConnectionMode::Stream(None),
        ConnectionType::Udp => ClientConnectionMode::Datagram(None),
    };

    let root_ca_cert = RootCertificate::PemFileOrDirectory(&config.ca_cert);

    let mut tun_config = TunConfig::default();

    if let Some(tun_name) = config.tun_name {
        tun_config.tun_name(tun_name);
    }
    if let Some(inside_mtu) = &config.inside_mtu {
        tun_config.mtu(*inside_mtu);
    }

    let (ctrlc_tx, ctrlc_rx) = tokio::sync::oneshot::channel();
    let mut ctrlc_tx = Some(ctrlc_tx);
    ctrlc::set_handler(move || {
        if let Some(Err(err)) = ctrlc_tx.take().map(|tx| tx.send(())) {
            tracing::warn!("Failed to send Ctrl-C signal: {err:?}");
        }
    })?;

    let inside_io: Option<Arc<dyn InsideIO<()>>> = None;

    let config = ClientConfig {
        mode,
        auth,
        root_ca_cert,
        outside_mtu: config.outside_mtu,
        inside_io,
        tun_config,
        tun_local_ip: config.tun_local_ip,
        tun_peer_ip: config.tun_peer_ip,
        tun_dns_ip: config.tun_dns_ip,
        cipher: config.cipher,
        #[cfg(feature = "postquantum")]
        enable_pqc: config.enable_pqc,
        keepalive_interval: config.keepalive_interval.into(),
        keepalive_timeout: config.keepalive_timeout.into(),
        continuous_keepalive: true,
        sndbuf: config.sndbuf,
        rcvbuf: config.rcvbuf,
        enable_pmtud: config.enable_pmtud,
        pmtud_base_mtu: config.pmtud_base_mtu,
        #[cfg(feature = "io-uring")]
        enable_tun_iouring: config.enable_tun_iouring,
        #[cfg(feature = "io-uring")]
        iouring_entry_count: config.iouring_entry_count,
        #[cfg(feature = "io-uring")]
        iouring_sqpoll_idle_time: config.iouring_sqpoll_idle_time.into(),
        server_dn: config.server_dn,
        server: config.server,
        inside_plugins: Default::default(),
        outside_plugins: Default::default(),
        inside_pkt_codec: None,
        inside_pkt_codec_config: None,
        stop_signal: ctrlc_rx,
        network_change_signal: None,
        event_handler: Some(EventHandler),
        #[cfg(feature = "debug")]
        tls_debug: config.tls_debug,
        #[cfg(feature = "debug")]
        keylog: config.keylog,
    };

    client(config).await.map(|_| ())
}
