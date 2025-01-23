mod args;
mod auth;

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::CommandFactory;

use metrics_util::debugging::DebuggingRecorder;
use tokio_stream::StreamExt;
use tracing::{error, trace};
use twelf::Layer;

use args::Config;
use lightway_app_utils::{validate_configuration_file_path, TunConfig, Validate};
use lightway_server::*;

async fn metrics_debug() {
    if !tracing::enabled!(tracing::Level::TRACE) {
        return;
    }
    trace!("Logging metrics as trace messages");

    let stats_recorder = DebuggingRecorder::new();

    let snapshotter = stats_recorder.snapshotter();

    if let Err(e) = stats_recorder.install() {
        error!("Error installing stats_recorder: {:?}", e);
        return;
    }

    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut ticker = tokio_stream::wrappers::IntervalStream::new(ticker);

    while ticker.next().await.is_some() {
        let snapshot = snapshotter.snapshot();

        for (key, _maybe_units, _maybe_description, value) in snapshot.into_vec() {
            let (_, key) = key.into_parts();
            let (name, labels) = key.into_parts();
            match value {
                metrics_util::debugging::DebugValue::Counter(value) => {
                    trace!("metric: {} {labels:?} = Counter({value:?})", name.as_str())
                }
                metrics_util::debugging::DebugValue::Gauge(value) => {
                    trace!("metric: {} {labels:?} = Guage({value:?})", name.as_str())
                }
                metrics_util::debugging::DebugValue::Histogram(values) => {
                    // TODO: https://docs.rs/average/latest/average/macro.concatenate.html for min/max and avg?

                    use average::{concatenate, Estimate, Max, Mean, Min};

                    concatenate!(Stats, [Min, min], [Mean, mean], [Max, max]);
                    let len = values.len();
                    let s: Stats = values.into_iter().map(|f| f.into_inner()).collect();

                    trace!(
                        "metric: {} {labels:?} = Histogram({} samples min/avg/max {:.2}/{:.2}/{:.2})",
                        name.as_str(),
                        len,
                        s.min(),
                        s.mean(),
                        s.max(),
                    )
                }
            };
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

    validate_configuration_file_path(config_file, Validate::AllowWorldRead)
        .with_context(|| format!("Invalid configuration file {}", config_file.display()))?;

    let config = Config::with_layers(&[
        Layer::Yaml(config_file.to_owned()),
        Layer::Env(Some(String::from("LW_SERVER_"))),
        Layer::Clap(matches),
    ])?;

    validate_configuration_file_path(&config.server_key, Validate::OwnerOnly)
        .with_context(|| format!("Invalid server key file {}", config.server_key.display()))?;
    validate_configuration_file_path(&config.server_cert, Validate::AllowWorldRead)
        .with_context(|| format!("Invalid server cert file {}", config.server_cert.display()))?;

    if let Some(user_db) = &config.user_db {
        validate_configuration_file_path(user_db, Validate::OwnerOnly)
            .with_context(|| format!("Invalid user db file {}", user_db.display()))?;
    }

    #[cfg(feature = "debug")]
    if config.tls_debug {
        enable_tls_debug();
    }

    let fmt = tracing_subscriber::fmt().with_max_level(config.log_level);

    config.log_format.init(fmt);

    tokio::spawn(metrics_debug());

    let auth = auth::Auth::new(
        config.user_db.as_ref().map(AsRef::as_ref),
        config.token_rsa_pub_key_pem.as_ref().map(AsRef::as_ref),
    )?;

    let mut tun_config = TunConfig::default();
    tun_config.tun_name(config.tun_name);

    let config = ServerConfig {
        connection_type: config.mode.into(),
        auth,
        server_cert: config.server_cert,
        server_key: config.server_key,
        tun_config,
        ip_pool: config.ip_pool,
        ip_map: config.ip_map.unwrap_or_default().try_into()?,
        tun_ip: config.tun_ip,
        lightway_server_ip: config.lightway_server_ip,
        lightway_client_ip: config.lightway_client_ip,
        lightway_dns_ip: config.lightway_dns_ip,
        enable_pqc: config.enable_pqc,
        iouring_entry_count: config.iouring_entry_count,
        iouring_sqpoll_idle_time: config.iouring_sqpoll_idle_time.into(),
        iouring_tun_rx_count: config.iouring_tun_rx_count,
        iouring_tun_blocking: config.iouring_tun_blocking,
        iouring_udp_rx_count: config.iouring_udp_rx_count,
        iouring_tx_count: config.iouring_tx_count,
        key_update_interval: config.key_update_interval.into(),
        inside_plugins: Default::default(),
        outside_plugins: Default::default(),
        bind_address: config.bind_address,
        proxy_protocol: config.proxy_protocol,
        udp_buffer_size: config.udp_buffer_size,
        tcp_buffer_size: config.tcp_buffer_size,
    };

    server(config).await
}
