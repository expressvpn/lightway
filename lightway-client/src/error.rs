//! Error mod for lightway clients

// TODO:
// Cli client errors should not be arbitrary anyhow erorrs,
// it will be nice to maintain by following the strong typed errors

// NOTE:
// The error enum name can not be Error, because it is used by uniffi::Error
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "mobile", derive(uniffi::Error), uniffi(flat_error))]
pub enum LightwayError {
    #[error("Connection Error: `{0}`")]
    ConnectionError(#[from] anyhow::Error),
    #[error("Received empty endpoints")]
    EmptyEndpointsError,
    #[error("User is not authorized / authentication failed")]
    Unauthorized,
    #[error("Config Error: `{0}`")]
    ConfigError(#[from] crate::config::Error),
    #[error("Config Format Error: `{0}`")]
    ConfigFormatError(#[from] serde_saphyr::Error),

    #[cfg(feature = "mobile")]
    #[error("Logging bridge initialization error: `{0}`")]
    LoggingBridgeError(#[from] crate::mobile::tracing_utils::LoggingBridgeError),
    #[cfg(feature = "mobile")]
    #[error("State Error: `{0}`")]
    StateError(#[from] crate::state::Error),
}
