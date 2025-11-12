use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{
    EnvFilter,
    filter::LevelFilter,
    fmt::{SubscriberBuilder, format},
};

#[derive(Copy, Clone, ValueEnum, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
/// Tracing log format type compatible with clap and twelf
pub enum LogFormat {
    /// human-readable, single-line logs for each event that occurs
    Full,
    /// human-readable, single-line logs for each event that occurs, optimized for short line lengths
    Compact,
    /// excessively pretty, multi-line logs, optimized for human readability
    Pretty,
    /// newline-delimited JSON logs
    Json,
}

impl LogFormat {
    /// Finalise a [`SubscriberBuilder`] according to the `LogFormat`
    pub fn init(self, builder: SubscriberBuilder) {
        match self {
            LogFormat::Full => builder.init(),
            LogFormat::Compact => builder.compact().init(),
            LogFormat::Pretty => builder.pretty().init(),
            LogFormat::Json => builder.json().init(),
        }
    }

    /// Finalise a [`SubscriberBuilder`] with [`EnvFilter`] according to the `LogFormat`
    pub fn init_with_env_filter(
        self,
        builder: SubscriberBuilder<
            format::DefaultFields,
            format::Format,
            EnvFilter,
            fn() -> std::io::Stdout,
        >,
    ) {
        match self {
            LogFormat::Full => builder.init(),
            LogFormat::Compact => builder.compact().init(),
            LogFormat::Pretty => builder.pretty().init(),
            LogFormat::Json => builder.json().init(),
        }
    }
}

#[derive(Copy, Clone, ValueEnum, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
/// Tracing log level type compatible with clap and twelf
pub enum LogLevel {
    /// Trace
    Trace,
    /// Debug
    Debug,
    /// Info
    Info,
    /// Warn
    Warn,
    /// Error
    Error,
    /// Off
    Off,
}

impl From<LogLevel> for LevelFilter {
    fn from(item: LogLevel) -> LevelFilter {
        match item {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Off => LevelFilter::OFF,
        }
    }
}
