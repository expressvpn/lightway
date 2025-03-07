use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use clap::CommandFactory;
use lightway_core::{Event, EventCallback};
use tokio_stream::StreamExt;
use twelf::Layer;

use lightway_app_utils::{
    TunConfig, Validate, args::ConnectionType, validate_configuration_file_path,
};
use lightway_client::*;

mod args;
use args::Config;

use signal_hook::consts::signal::{SIGUSR1, SIGUSR2};
use signal_hook_tokio::Signals;
use tokio::time::Duration;

struct EventHandler;

impl EventCallback for EventHandler {
    fn event(&self, event: lightway_core::Event) {
        if let Event::StateChanged(state) = event {
            tracing::debug!("State changed to {:?}", state);
        }
    }
}

async fn handle_toggle_encoding_signals(
    mut signals: Signals,
    toggle_signal_tx: tokio::sync::mpsc::Sender<bool>,
) {
    while let Some(signal) = signals.next().await {
        match signal {
            SIGUSR1 => {
                tracing::info!("Enable encoding signal SIGUSR1 received.");
                if let Err(e) = toggle_signal_tx.send(true).await {
                    tracing::error!("Failed to transmit enable encoding signal. {e}");
                }
            }
            SIGUSR2 => {
                tracing::info!("Disable encoding signal SIGUSR2 received.");
                if let Err(e) = toggle_signal_tx.send(false).await {
                    tracing::error!("Failed to transmit disable encoding signal. {e}");
                }
            }
            _ => unreachable!("handle toggle encoding signals task encoutered an uknown signal"),
        }
    }
}

#[tokio::main]
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
        ConnectionType::Tcp => ClientConnectionType::Stream(None),
        ConnectionType::Udp => ClientConnectionType::Datagram(None),
    };

    let root_ca_cert = RootCertificate::PemFileOrDirectory(&config.ca_cert);

    let mut tun_config = TunConfig::default();
    tun_config.tun_name(config.tun_name);
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

    let ingress_pkt_accumulator = Box::new(lightway_app_utils::RaptorEncoderFactory::new(
        1350,
        3,
        1350 * 20,
        0.2,
    ));
    let egress_pkt_accumulator = Box::new(lightway_app_utils::RaptorDecoderFactory::new(
        Duration::from_secs_f32(2.0),
    ));

    let toggle_encode_signals = Signals::new([SIGUSR1, SIGUSR2])?;
    let (toggle_encode_tx, toggle_encode_rx) = tokio::sync::mpsc::channel(1);
    tokio::spawn(handle_toggle_encoding_signals(
        toggle_encode_signals,
        toggle_encode_tx,
    ));

    let config = ClientConfig {
        mode,
        auth,
        root_ca_cert,
        outside_mtu: config.outside_mtu,
        inside_mtu: config.inside_mtu,
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
        ingress_pkt_accumulator,
        egress_pkt_accumulator,
        pkt_accumulator_flush_interval: Duration::from_secs_f64(0.000001),
        pkt_accumulator_clean_up_interval: Duration::from_secs_f64(0.5),
        toggle_encoding_signal: toggle_encode_rx,
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
