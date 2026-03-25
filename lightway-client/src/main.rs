use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use struct_patch::Patch;

use anyhow::{Context, Result, anyhow};
use futures::future::join_all;
use lightway_core::{Event, EventCallback};
use tokio::fs::read_to_string;

use lightway_app_utils::{
    TunConfig, Validate,
    args::{ConfigFormat, ConnectionType, LogFormat},
    validate_configuration_file_path,
};
use lightway_client::{io::inside::InsideIO, *};

mod config;
use config::{Config, ConfigPatch, ConnectionConfig};

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

fn generate_config(format: ConfigFormat, config_file: &PathBuf) -> Result<()> {
    println!("Create {format:?} config to {}", config_file.display());

    match format {
        ConfigFormat::Yaml => {
            let default_configs = Config::default();
            let mut file = std::fs::File::create(config_file)?;
            serde_saphyr::to_io_writer(&mut file, &default_configs)?;
        }
        ConfigFormat::JsonSchema => {
            let settings = schemars::generate::SchemaSettings::draft07().with(|s| {
                s.inline_subschemas = true;
            });
            let schema = settings.into_generator().into_root_schema_for::<Config>();
            std::fs::write(
                config_file,
                serde_json::to_string_pretty(&schema)
                    .expect("Some JsonSchema field did not implement properly"),
            )
            .expect("Fail to write config file for json schema");
        }
    }

    Ok(())
}
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let mut options = ConfigPatch::parse();

    // Fetch the config filepath from CLI and load it as config
    let Some(config_file) = options.config_file.take() else {
        return Err(anyhow!("Config file not present"));
    };

    if let Some(config_format) = options.generate.take() {
        return generate_config(config_format, &config_file);
    }

    validate_configuration_file_path(&config_file, Validate::OwnerOnly)
        .with_context(|| format!("Invalid configuration file {}", config_file.display()))?;

    let mut config = Config::default();
    // NOTE:
    // RootCertificate of wolfssl is not a self handled Struct
    // we need keep the PathBuf live outside
    let mut _root_ca_cert_path: Option<PathBuf> = None;

    // Load config patch with DPAPI support
    #[cfg(windows)]
    config.apply(load_patch(&options, &config_file).await?);
    #[cfg(not(windows))]
    config.apply(serde_saphyr::from_str::<ConfigPatch>(
        &read_to_string(config_file).await?,
    )?);
    config.apply(
        envious::Config::default()
            .with_prefix("LW_CLIENT_")
            .build_from_env()?,
    );
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

    let mut tun_config = TunConfig::default();

    if let Some(tun_name) = config.tun_name.take() {
        tun_config.tun_name(tun_name);
    }

    #[cfg(windows)]
    if let Some(ref wintun_file) = config.wintun_file {
        tun_config.wintun_file(wintun_file);
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

    if config.servers.is_empty() {
        config.servers = vec![ConnectionConfig {
            server: config.server.clone(),
            mode: config.mode,
            server_dn: config.server_dn.clone(),
            cipher: config.cipher,
            ..Default::default()
        }];
    }

    let conn_confs = join_all(
        std::mem::take::<Vec<ConnectionConfig>>(&mut config.servers)
            .into_iter()
            .map(make_client_connection_config),
    );
    let conn_confs = tokio::select! {
        results = conn_confs => {
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
        auth: config.take_auth()?,
        root_ca_cert: config
            .load_ca()
            .unwrap_or(config.load_ca_file(&mut _root_ca_cert_path)),
        outside_mtu: config.outside_mtu,
        inside_io,
        tun_config,
        tun_local_ip: config.tun_local_ip,
        tun_peer_ip: config.tun_peer_ip,
        tun_dns_ip: config.tun_dns_ip,
        #[cfg(feature = "postquantum")]
        enable_pqc: config.enable_pqc,
        enable_expresslane: config.enable_expresslane,
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
        keylog: config.keylog.clone(),
    };

    client(config, ctrlc_rx, conn_confs).await.map(|_| ())
}
