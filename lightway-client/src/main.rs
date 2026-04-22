use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use struct_patch::Patch;

use anyhow::{Context, Result, anyhow};
use futures::future::join_all;
use lightway_core::{Event, EventCallback};
use tokio::fs::read_to_string;

use lightway_app_utils::{
    TunConfig, Validate,
    args::{ConnectionType, LogFormat},
    validate_configuration_file_path,
};
use lightway_client::{io::inside::InsideIO, *};
mod args;
use args::{Config, ConfigPatch};

use crate::args::ConnectionConfig;

struct EventHandler;

impl EventCallback for EventHandler {
    fn event(&mut self, event: lightway_core::Event) {
        match event {
            Event::StateChanged(state) => {
                tracing::debug!("State changed to {:?}", state);
            }
            Event::EncodingStateChanged { enabled } => {
                tracing::debug!("Encoding state changed to {:?}", enabled);
            }
            _ => {}
        }
    }
}

async fn make_client_connection_config(
    config: ConnectionConfig,
) -> Result<ClientConnectionConfig<EventHandler>> {
    tracing::info!("Resolving server address: {}", &config.server);

    let server_addr: SocketAddr = tokio::net::lookup_host(config.server)
        .await?
        .next()
        .ok_or_else(|| anyhow!("No addresses resolved"))?;

    let mode = match config.mode {
        ConnectionType::Tcp => ClientConnectionMode::Stream(None),
        ConnectionType::Udp => ClientConnectionMode::Datagram(None),
    };

    Ok(ClientConnectionConfig {
        mode,
        cipher: config.cipher,
        server_dn: config.server_dn,
        server: server_addr,
        inside_plugins: Default::default(),
        outside_plugins: Default::default(),
        inside_pkt_codec: None,
        event_handler: Some(EventHandler),
    })
}

#[cfg(windows)]
async fn load_patch(options: &ConfigPatch, config_file: &PathBuf) -> Result<ConfigPatch> {
    use crate::platform::windows::crypto::decrypt_dpapi_config_file;
    use windows_dpapi::Scope::User;

    // Fetch whether DPAPI is enabled from CLI args
    let enable_dpapi = options.enable_dpapi;

    let content = if enable_dpapi {
        tracing::info!("DPAPI decryption enabled for config file");
        decrypt_dpapi_config_file(config_file, User)
            .context("Failed to decrypt DPAPI-protected config file")?
    } else {
        tracing::debug!("Loading config file directly (no DPAPI)");
        read_to_string(config_file).await?
    };
    Ok(serde_saphyr::from_str::<ConfigPatch>(&content)?)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut options = ConfigPatch::parse();

    // Fetch the config filepath from CLI and load it as config
    let Some(config_file) = options.config_file.take() else {
        return Err(anyhow!("Config file not present"));
    };

    validate_configuration_file_path(&config_file, Validate::OwnerOnly)
        .with_context(|| format!("Invalid configuration file {}", config_file.display()))?;

    let mut config = Config::default();

    // Load config patch with DPAPI support
    #[cfg(windows)]
    config.apply(load_patch(&options, &config_file).await?);
    #[cfg(not(windows))]
    config.apply(serde_saphyr::from_str::<ConfigPatch>(
        &read_to_string(config_file).await?,
    )?);
    config.apply(serde_env::from_env_with_prefix("LW_CLIENT")?);
    config.apply(options);

    let level: tracing::level_filters::LevelFilter = config.log_level.into();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(level.into())
        // https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.Builder.html#method.with_regex
        // recommends to disable REGEX when using envfilter from untrusted sources
        .with_regex(false)
        .with_env_var("LW_CLIENT_RUST_LOG")
        .from_env_lossy();
    let fmt = tracing_subscriber::fmt().with_env_filter(filter);

    LogFormat::Full.init_with_env_filter(fmt);

    let auth = config.take_auth()?;

    let root_ca_path = PathBuf::from(&config.ca_cert);
    let root_ca_cert = if config
        .ca_cert
        .as_str()
        .starts_with("-----BEGIN CERTIFICATE-----")
    {
        RootCertificate::PemBuffer(config.ca_cert.as_bytes())
    } else {
        RootCertificate::PemFileOrDirectory(&root_ca_path)
    };

    let mut tun_config = TunConfig::default();

    if let Some(tun_name) = config.tun_name.take() {
        tun_config.tun_name(tun_name);
    }

    #[cfg(windows)]
    {
        if let Some(ref wintun_file) = config.wintun_file {
            tun_config.wintun_file(wintun_file);
        }
        tun_config.ring_capacity(config.wintun_ring_capacity.as_u64().try_into()?)?;
    }

    #[cfg(windows)]
    if let Some(ref device_guid) = config.device_guid {
        let parsed = uuid::Uuid::parse_str(device_guid)
            .with_context(|| format!("invalid device GUID: {device_guid}"))?;
        tracing::info!(device_guid = %parsed, "Setting device GUID");
        tun_config.device_guid(parsed.as_u128());
    }

    // TODO: Fix in future PR
    tun_config
        .mtu(1350)
        .address(config.tun_local_ip.into())
        .destination(config.tun_peer_ip)
        .up();

    let (ctrlc_tx, mut ctrlc_rx) = tokio::sync::oneshot::channel();
    let mut ctrlc_tx = Some(ctrlc_tx);
    ctrlc::set_handler(move || {
        if let Some(Err(err)) = ctrlc_tx.take().map(|tx| tx.send(())) {
            tracing::warn!("Failed to send Ctrl-C signal: {err:?}");
        }
    })?;

    let inside_io: Option<Arc<dyn InsideIO<()>>> = None;

    let servers = if config.servers.is_empty() {
        vec![ConnectionConfig {
            server: config.server,
            mode: config.mode,
            server_dn: config.server_dn,
            cipher: config.cipher,
        }]
    } else {
        config.servers
    };

    let servers = join_all(servers.into_iter().map(make_client_connection_config));
    let servers = tokio::select! {
        results = servers => {
            results.into_iter()
                .flat_map(|result| result.map_err(|e| tracing::error!("{e}")))
                .collect::<Vec<_>>()
        }
        _ = &mut ctrlc_rx => {
            tracing::info!("Ctrl-C received, exiting...");
            // `lookup_host` uses `spawn_blocking`, and the executor will still wait for the tasks
            // to finish before exiting. Instead of waiting for the resolution to fail, we exit
            // manually.
            std::process::exit(0);
        }
    };

    let config = ClientConfig {
        auth,
        root_ca_cert,
        outside_mtu: config.outside_mtu,
        inside_io,
        tun_config,
        tun_local_ip: config.tun_local_ip,
        tun_peer_ip: config.tun_peer_ip,
        tun_dns_ip: config.tun_dns_ip,
        #[cfg(feature = "postquantum")]
        keyshare: config.keyshare,
        enable_expresslane: config.enable_expresslane,
        expresslane_cb: None,
        expresslane_metrics: None,
        keepalive_interval: config.keepalive_interval.into(),
        keepalive_timeout: config.keepalive_timeout.into(),
        continuous_keepalive: config.keepalive_continuous,
        tracer_packet_timeout: config.tracer_packet_timeout.into(),
        preferred_connection_wait_interval: config.preferred_connection_wait_interval.into(),
        sndbuf: config.sndbuf,
        rcvbuf: config.rcvbuf,
        #[cfg(batch_receive)]
        enable_batch_receive: config.enable_batch_receive,
        #[cfg(desktop)]
        route_mode: config.route_mode,
        #[cfg(desktop)]
        dns_config_mode: config.dns_config_mode,
        enable_pmtud: config.enable_pmtud,
        pmtud_base_mtu: config.pmtud_base_mtu,
        #[cfg(feature = "io-uring")]
        enable_tun_iouring: config.enable_tun_iouring,
        #[cfg(feature = "io-uring")]
        iouring_entry_count: config.iouring_entry_count,
        #[cfg(feature = "io-uring")]
        iouring_sqpoll_idle_time: config.iouring_sqpoll_idle_time.into(),
        inside_pkt_codec_config: None,
        network_change_signal: None,
        best_connection_selected_signal: None,
        #[cfg(feature = "debug")]
        tls_debug: config.tls_debug,
        #[cfg(feature = "debug")]
        keylog: config.keylog,
    };

    client(config, ctrlc_rx, servers).await.map(|_| ())
}
