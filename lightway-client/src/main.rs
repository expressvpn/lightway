use clap::Parser;
use std::path::PathBuf;
use struct_patch::Patch;

use anyhow::{Context, Result, anyhow};
use futures::future::join_all;
use lightway_core::{Event, EventCallback};
use tokio::fs::read_to_string;
use tokio::sync::mpsc;

use lightway_app_utils::{
    Validate,
    args::{ConfigFormat, LogFormat},
    validate_configuration_file_path,
};
use lightway_client::*;

use lightway_client::config::{Config, ConfigPatch};

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
            std::fs::write(config_file, serde_json::to_string_pretty(&schema)?)?;
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
    // RootCertificate of TLS library is not a self handled Struct
    // we need keep the PathBuf live outside
    let mut _root_ca_cert_path: Option<PathBuf> = None;

    // Load config patch with DPAPI support
    #[cfg(windows)]
    config.apply(load_patch(&options, &config_file).await?);
    #[cfg(not(windows))]
    config.apply(serde_saphyr::from_str::<ConfigPatch>(
        &read_to_string(&config_file).await?,
    )?);
    let env_patch: ConfigPatch = serde_env::from_env_with_prefix("LW_CLIENT")?;
    config.apply(env_patch.clone());
    let cli_patch = options.clone();
    config.apply(options);
    config.validate()?;

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

    #[cfg(unix)]
    {
        tokio::spawn(async move {
            let mut sigint =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                    .expect("Failed to register SIGINT handler");
            let mut sigterm =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("Failed to register SIGTERM handler");
            tokio::select! {
                _ = sigint.recv() => {}
                _ = sigterm.recv() => {}
            }
            let _ = ctrlc_tx.send(());
        });
    }

    #[cfg(windows)]
    {
        let ctrlc_tx = std::sync::Mutex::new(Some(ctrlc_tx));
        ctrlc::set_handler(move || {
            if let Some(tx) = ctrlc_tx.lock().unwrap().take() {
                let _ = tx.send(());
            }
        })?;
    }

    let config_reload_signal =
        spawn_reload_event_handler(&config, config_file.clone(), env_patch, cli_patch);

    let servers = config.take_servers()?;

    let client_config = lightway_client::ClientConfig::<()>::try_from_reload_sig_and_config(
        config_reload_signal,
        config,
    )?;

    let conn_confs = join_all(servers.into_iter().map(|c| {
        ClientConnectionConfig::try_from_event_handler_and_connection_config(Some(EventHandler), c)
    }));
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

    client(client_config, ctrlc_rx, conn_confs)
        .await
        .map(|_| ())
}

#[cfg(any(unix, windows))]
async fn reload_config(
    path: &PathBuf,
    env_patch: &ConfigPatch,
    cli_patch: &ConfigPatch,
) -> Option<Config> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| tracing::error!("Failed to read config: {e}"))
        .ok()?;
    let file_patch = serde_saphyr::from_str::<ConfigPatch>(&content)
        .map_err(|e| tracing::error!("Failed to parse config on reload: {e}"))
        .ok()?;

    let mut config = Config::default();
    config.apply(file_patch);
    config.apply(env_patch.clone());
    config.apply(cli_patch.clone());
    Some(config)
}

#[cfg(any(unix, windows))]
fn warn_non_reloadable_changes(old: &Config, new: &Config) {
    /// Mask reloadable fields so only non-reloadable differences remain.
    /// Clone old, overwrite listed fields with new's values, then compare to new.
    /// Any remaining difference means a non-reloadable field changed.
    macro_rules! mask_reloadable {
        ($old:expr, $new:expr, $($field:ident),+ $(,)?) => {{
            let mut masked = $old.clone();
            $(masked.$field = $new.$field.clone();)+
            masked
        }};
    }

    if old == new {
        return;
    }

    // List ONLY the fields that CAN be reloaded at runtime.
    // Everything else is automatically caught by the PartialEq check.
    let masked = mask_reloadable!(old, new, log_level, enable_inside_pkt_encoding);

    if masked != *new {
        tracing::warn!("Non-reloadable config fields changed (requires restart to take effect)");
    }
}

#[cfg(unix)]
fn spawn_reload_event_handler(
    config: &Config,
    config_file: PathBuf,
    env_patch: ConfigPatch,
    cli_patch: ConfigPatch,
) -> Option<mpsc::Receiver<ReloadableClientConfig>> {
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        .expect("Failed to register SIGHUP handler");

    let initial = config.clone();

    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        let mut prev = ReloadableClientConfig::from(&initial);
        let mut prev_config = initial;

        while sighup.recv().await.is_some() {
            tracing::info!("SIGHUP received, reloading config");

            let Some(new_config) = reload_config(&config_file, &env_patch, &cli_patch).await else {
                continue;
            };

            warn_non_reloadable_changes(&prev_config, &new_config);

            let current = ReloadableClientConfig::from(&new_config);
            prev_config = new_config;

            if current == prev {
                tracing::info!("Config unchanged, skipping reload");
                continue;
            }

            let delta = current.delta(&prev);
            prev = current;

            if tx.send(delta).await.is_err() {
                break;
            }
        }
    });
    Some(rx)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn spawn_reload_event_handler(
    config: &Config,
    config_file: PathBuf,
    env_patch: ConfigPatch,
    cli_patch: ConfigPatch,
) -> Option<mpsc::Receiver<ReloadableClientConfig>> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, WAIT_OBJECT_0},
        System::Threading::{CreateEventW, INFINITE, WaitForSingleObject},
    };

    const EVENT_NAME: &str = "Global\\LightwayConfigReload";

    let wide_name: Vec<u16> = EVENT_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: CreateEventW with valid null-terminated wide string.
    let handle = unsafe { CreateEventW(std::ptr::null(), 0, 0, wide_name.as_ptr()) };
    if handle.is_null() {
        tracing::error!("Failed to create reload event");
        return None;
    }

    let initial = config.clone();
    let (tx, rx) = mpsc::channel(1);

    #[derive(Clone, Copy)]
    struct SendHandle(windows_sys::Win32::Foundation::HANDLE);

    impl SendHandle {
        fn raw(self) -> windows_sys::Win32::Foundation::HANDLE {
            self.0
        }
    }

    // SAFETY: The handle is only used from one thread at a time (the blocking thread).
    unsafe impl Send for SendHandle {}

    let send_handle = SendHandle(handle);

    tokio::spawn(async move {
        let mut prev = ReloadableClientConfig::from(&initial);
        let mut prev_config = initial;

        loop {
            let h = send_handle;
            let wait_result = tokio::task::spawn_blocking(move || {
                // SAFETY: handle was created above, is valid
                unsafe { WaitForSingleObject(h.raw(), INFINITE) }
            })
            .await;

            match wait_result {
                Ok(WAIT_OBJECT_0) => {}
                Ok(code) => {
                    tracing::error!("WaitForSingleObject returned unexpected code: {code}");
                    break;
                }
                Err(e) => {
                    tracing::error!("spawn_blocking panicked: {e}");
                    break;
                }
            }

            tracing::info!("Reload event signaled, reloading config");

            let Some(new_config) = reload_config(&config_file, &env_patch, &cli_patch).await else {
                continue;
            };

            warn_non_reloadable_changes(&prev_config, &new_config);

            let current = ReloadableClientConfig::from(&new_config);
            prev_config = new_config;

            if current == prev {
                tracing::info!("Config unchanged, skipping reload");
                continue;
            }

            let delta = current.delta(&prev);
            prev = current;

            if tx.send(delta).await.is_err() {
                break;
            }
        }

        // SAFETY: handle was created above, owned by us
        unsafe { CloseHandle(send_handle.raw()) };
    });

    Some(rx)
}

#[cfg(not(any(unix, windows)))]
fn spawn_reload_event_handler(
    _config: &Config,
    _config_file: PathBuf,
    _env_patch: ConfigPatch,
    _cli_patch: ConfigPatch,
) -> Option<mpsc::Receiver<ReloadableClientConfig>> {
    None
}
