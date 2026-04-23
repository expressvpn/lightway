use clap::Parser;
use std::{path::PathBuf, sync::Arc};
use struct_patch::Patch;

use anyhow::{Context, Result, anyhow};
use futures::future::join_all;
use tokio::fs::read_to_string;

use lightway_app_utils::{
    Validate,
    args::{ConfigFormat, LogFormat},
    validate_configuration_file_path,
};
use lightway_client::{io::inside::InsideIO, *};

mod config;
use config::{Config, ConfigPatch};

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

    let (ctrlc_tx, mut ctrlc_rx) = tokio::sync::oneshot::channel();
    let mut ctrlc_tx = Some(ctrlc_tx);
    ctrlc::set_handler(move || {
        if let Some(Err(err)) = ctrlc_tx.take().map(|tx| tx.send(())) {
            tracing::warn!("Failed to send Ctrl-C signal: {err:?}");
        }
    })?;

    let inside_io: Option<Arc<dyn InsideIO<()>>> = None;
    let servers = config.take_servers()?;

    let conn_confs = join_all(
        servers
            .into_iter()
            .map(|c| c.into_client_connection_config()),
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

    client(config.into_client_config(inside_io), ctrlc_rx, conn_confs)
        .await
        .map(|_| ())
}
